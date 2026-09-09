package cli

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/report"

	// The lockfile formats register their parsers from init, so the binary knows
	// a format only if something imports its package. These are that import: diff
	// and scan ask internal/lockfile which parser reads a file, and without them
	// the answer would always be none.
	_ "github.com/vahapogut/trustdiff/internal/lockfile/cargo"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/npm"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/pnpm"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/uv"
)

// pruned are the directory names a scan never descends into. They hold installed
// copies of packages rather than the project's own files, and the lockfiles
// inside them belong to a dependency, not to the project under audit. Vendored
// and built output is skipped for the same reason, and .git because none of it is
// a working file.
var pruned = map[string]bool{
	".git":         true,
	".venv":        true,
	"dist":         true,
	"node_modules": true,
	"target":       true,
	"vendor":       true,
}

// maxDroppedListed is how many dropped entries one note spells out before it says
// only how many are left, so a file that drops a hundred entries costs one line
// like every other file.
const maxDroppedListed = 3

// settings are what a lockfile command settles before it touches the network: the
// policy, the clock, the level that decides the exit code and the report writer.
// Everything here can reject the command line, so a bad flag fails at once
// instead of after a full run. check does the same inline; diff and scan share
// this because they also have work to do between the flags and the run.
type settings struct {
	pol        *policy.Policy
	policyPath string
	// cooldown is the young-version threshold in the spelling the report prints.
	cooldown string
	now      time.Time
	failOn   model.Level
	writer   report.Writer
}

// settle validates and loads everything a run needs before the loader is built.
func (a *App) settle() (*settings, error) {
	pol, policyPath, err := a.loadPolicyOrDefault()
	if err != nil {
		return nil, err
	}
	pol, cooldown := a.applyCooldownOverride(pol)

	now, err := runClock(os.Getenv(nowEnv))
	if err != nil {
		return nil, err
	}
	failOn, err := report.ParseFailOn(a.Opts.FailOn)
	if err != nil {
		return nil, Usagef("%v", err)
	}
	writer, err := report.New(a.Opts.Format, report.Options{Color: a.Opts.Color, Width: a.Opts.Width})
	if err != nil {
		return nil, Usagef("%v", err)
	}
	return &settings{pol: pol, policyPath: policyPath, cooldown: cooldown, now: now, failOn: failOn, writer: writer}, nil
}

// evaluate runs the checks over the inputs, writes the report and returns the
// exit code as an error, the way check does: 1 for findings at or above
// --fail-on, 3 when a data source was unavailable and the policy says fail.
// A run with no inputs still writes a report, so a document format always gets a
// document.
func (a *App) evaluate(ctx context.Context, st *settings, inputs []checks.Input) error {
	loader, err := loaderFactory(a)
	if err != nil {
		return Usagef("%v", err)
	}
	runner := &checks.Runner{
		Loader:  loader,
		Policy:  st.pol,
		Jobs:    a.Opts.Jobs,
		Timeout: checkTimeout,
		Now:     st.now,
		Log:     a.Opts.Log,
	}
	outcomes := runner.Evaluate(ctx, inputs)

	rep := report.Build(checks.Subjects(outcomes), report.CurrentTool(), report.Policy{
		Path:     st.policyPath,
		Cooldown: st.cooldown,
		FailOn:   a.Opts.FailOn,
	}, st.failOn)
	// Exit code 1 says there is something to act on now, 3 that the answer is
	// incomplete. When both apply the findings win.
	if rep.Summary.ExitCode == ExitOK && dataUnavailableFails(st.pol, outcomes) {
		rep.SetExitCode(ExitUnavailable)
	}

	if err := st.writer.Write(a.Stdout, rep); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if rep.Summary.ExitCode != ExitOK {
		return Exit(rep.Summary.ExitCode, nil)
	}
	return nil
}

// writeNotes prints the lines that belong beside the report rather than in it:
// which lockfiles were compared, what a change removed, what a parser could not
// read, how much work a scan is about to do. The human format is the one a person
// reads, so there they go to stdout above the cards, followed by a blank line.
// The document formats keep stdout to the document alone and the notes go to the
// log instead, where -v shows them.
func (a *App) writeNotes(lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	if a.Opts.Format != "human" {
		for _, line := range lines {
			a.Opts.Log.Info(line)
		}
		return nil
	}
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	if _, err := io.WriteString(a.Stdout, b.String()); err != nil {
		return fmt.Errorf("write the notes: %w", err)
	}
	return nil
}

// inputFor turns one lockfile entry into a subject to evaluate. path is the
// lockfile as the report should name it, slash separated. The entry is copied,
// so the input owns the entry the checks read.
func inputFor(path string, eco model.Ecosystem, e *lockfile.Entry) checks.Input {
	entry := *e
	if entry.Ref.Ecosystem == "" {
		entry.Ref.Ecosystem = eco
	}
	return checks.Input{
		Ref:      entry.Ref,
		Location: &model.Location{Path: path, Line: entry.Line},
		Direct:   entry.Direct,
		Lock:     &entry,
	}
}

// entryInputs turns the entries of one lockfile into inputs, dropping the repeats
// of one exact version: a lockfile that installs a package at the same version in
// several places, which npm does routinely, is one subject to evaluate. The first
// entry wins, the one on the earliest line, and the package counts as direct if
// any of its copies is. This is the rule gitdiff.Diff applies to the two sides of
// a diff, so diff and scan report the same subjects for the same file.
func entryInputs(path string, lf *lockfile.Lockfile) []checks.Input {
	inputs := make([]checks.Input, 0, len(lf.Entries))
	at := make(map[model.PackageRef]int, len(lf.Entries))
	for i := range lf.Entries {
		e := &lf.Entries[i]
		in := inputFor(path, lf.Ecosystem, e)
		if j, seen := at[in.Ref]; seen {
			if in.Direct {
				inputs[j].Direct = true
				inputs[j].Lock.Direct = true
			}
			continue
		}
		at[in.Ref] = len(inputs)
		inputs = append(inputs, in)
	}
	return inputs
}

// droppedNote words the entries a parser could not read as one line, whatever
// their number: a partial parse must be visible, and a lockfile full of workspace
// links must not bury the report. label names the file the entries came from.
func droppedNote(label string, dropped []string) string {
	if len(dropped) == 0 {
		return ""
	}
	listed := dropped
	var more string
	if len(listed) > maxDroppedListed {
		listed = listed[:maxDroppedListed]
		more = fmt.Sprintf(", and %d more", len(dropped)-maxDroppedListed)
	}
	counted := "entries were"
	if len(dropped) == 1 {
		counted = "entry was"
	}
	return fmt.Sprintf("%s: %d %s not read (%s%s)", label, len(dropped), counted, strings.Join(listed, "; "), more)
}

// parseLockfileAt reads and parses one lockfile from disk.
func parseLockfileAt(path string) (*lockfile.Lockfile, error) {
	f, err := os.Open(path) // #nosec G304 -- the path is a lockfile the user named or one found under the directory they named
	if err != nil {
		return nil, fmt.Errorf("read the lockfile: %w", err)
	}
	defer f.Close()
	return lockfile.Parse(path, f)
}

// findLockfiles walks root and returns the lockfiles under it, as paths relative
// to root with forward slashes, in the lexical order the walk visits them, so two
// runs over one tree report the same files in the same order. Directories in
// pruned are not descended into, and a name no parser recognizes is not opened:
// internal/lockfile decides what a lockfile is, so a format added later is found
// here without a change.
//
// A directory that cannot be read is skipped rather than failing the walk: a scan
// of a large tree must not stop at the one directory whose permissions differ.
// The reason is logged.
func findLockfiles(root string, log *slog.Logger) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				log.Debug("skipping a directory that cannot be read", "path", path, "error", err)
				return fs.SkipDir
			}
			log.Debug("skipping a file that cannot be read", "path", path, "error", err)
			return nil
		}
		if d.IsDir() {
			if path != root && pruned[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if _, ok := lockfile.For(d.Name()); !ok {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return fmt.Errorf("locate %s under %s: %w", path, root, relErr)
		}
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}
	return found, nil
}
