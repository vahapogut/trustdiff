package cli

import (
	"errors"
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
	_ "github.com/vahapogut/trustdiff/internal/lockfile/bun"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/cargo"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/deno"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/npm"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/pipreq"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/pnpm"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/poetry"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/uv"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/yarn"
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

// maxDroppedListed is how many items one note spells out before it says only how
// many are left, so a file that drops a hundred entries, or a change that removes
// two thousand, costs one line like every other file.
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

// unreadFails reports whether something the run could not read should make the
// exit code 3. It is the policy's own answer for a data source that could not be
// consulted, read from the top-level setting: an unread lockfile belongs to no
// ecosystem, so there is no override to apply.
func unreadFails(pol *policy.Policy, incomplete bool) bool {
	return incomplete && pol.Effective("").OnDataUnavailable == policy.OnDataUnavailableFail
}

// writeNotes prints the lines that belong beside the report rather than in it:
// which lockfiles were compared, what a change removed, what a parser could not
// read, how much work a scan is about to do. The human format is the one a person
// reads, so there they go to stdout above the cards, followed by a blank line.
//
// The document formats keep stdout to the document alone, so their notes go to
// stderr. They are not logged: the logger is silent below warn unless -v, and
// these lines say what was not evaluated, which is what a gate reading the SARIF
// most needs to be told.
func (a *App) writeNotes(lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	out, trailer := a.Stdout, "\n"
	if a.Opts.Format != "human" {
		out, trailer = a.Stderr, ""
	}
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString(trailer)
	if _, err := io.WriteString(out, b.String()); err != nil {
		return fmt.Errorf("write the notes: %w", err)
	}
	return nil
}

// inputFor turns one lockfile entry into a subject to evaluate. path is the
// lockfile as the report should name it, slash separated. The entry is copied,
// so the input owns the entry the checks read.
// baseEntry copies the base side of a changed pair so the input owns it, filling in
// the ecosystem the file states when the entry left it empty. It does for the base
// entry what inputFor does for the head one, so the check that compares the two
// reads one shape.
func baseEntry(eco model.Ecosystem, e *lockfile.Entry) *lockfile.Entry {
	entry := *e
	if entry.Ref.Ecosystem == "" {
		entry.Ref.Ecosystem = eco
	}
	return &entry
}

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
	counted := "entries were"
	if len(dropped) == 1 {
		counted = "entry was"
	}
	return fmt.Sprintf("%s: %d %s not read (%s)", label, len(dropped), counted, listSome(dropped))
}

// listSome spells out the first few of a list and counts the rest, so one note is
// one line whether it carries three items or three thousand.
func listSome(items []string) string {
	listed := items
	var more string
	if len(listed) > maxDroppedListed {
		listed = listed[:maxDroppedListed]
		more = fmt.Sprintf(", and %d more", len(items)-maxDroppedListed)
	}
	return strings.Join(listed, "; ") + more
}

// parseLockfileAt reads and parses one lockfile from disk. openPath is where the
// file is on this machine and name is what the report calls it, which is what the
// parser's messages carry.
func parseLockfileAt(openPath, name string) (*lockfile.Lockfile, error) {
	f, err := openLockfile(openPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return lockfile.Parse(name, f)
}

// openLockfile opens a file to parse it, and only if it is a plain file.
//
// A lockfile in a pull request is text the author chose, and git records a
// symbolic link as a blob holding the link text, so a fork can commit
// package-lock.json as a link to any path on the runner. Following it would put
// whatever that file holds into the report, into the SARIF uploaded to code
// scanning and into the registry lookups. The git side of this package refuses a
// path outside the repository for the same reason; this is the filesystem side of
// that rule.
func openLockfile(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	// The caller names the file in the note or the message it builds from this,
	// so the reason says what is wrong and not where.
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return nil, errors.New("a symbolic link, not a lockfile: trustdiff does not follow links out of the tree it evaluates")
	case !fi.Mode().IsRegular():
		return nil, errors.New("not a regular file, so not a lockfile trustdiff reads")
	}
	f, err := os.Open(path) // #nosec G304 -- the path is a lockfile the user named or one found under the directory they named, and Lstat above has refused everything that is not a plain file
	if err != nil {
		return nil, err
	}
	return f, nil
}

// findLockfiles walks root and returns the lockfiles under it, as paths relative
// to root with forward slashes, in the lexical order the walk visits them, so two
// runs over one tree report the same files in the same order. Directories in
// pruned are not descended into, and a name no parser recognizes is not opened:
// internal/lockfile decides what a lockfile is, so a format added later is found
// here without a change.
//
// A directory that cannot be read is skipped rather than failing the walk: a scan
// of a large tree must not stop at the one directory whose permissions differ. It
// is returned in unreadable, as a path relative to root, because a subtree nobody
// looked at is not a pass and the run has to say so.
func findLockfiles(root string, log *slog.Logger) (found, unreadable []string, err error) {
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				log.Debug("skipping a directory that cannot be read", "path", path, "error", err)
				if rel, relErr := relativeTo(root, path); relErr == nil {
					unreadable = append(unreadable, rel)
				} else {
					unreadable = append(unreadable, filepath.ToSlash(path))
				}
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
		// The whole path, not the name: one format is identified by the directory
		// it sits in, and lockfile.For asks about the parent when the base name
		// answers nothing.
		if _, ok := lockfile.For(path); !ok {
			return nil
		}
		rel, relErr := relativeTo(root, path)
		if relErr != nil {
			return fmt.Errorf("locate %s under %s: %w", path, root, relErr)
		}
		found = append(found, rel)
		return nil
	})
	if walkErr != nil {
		return nil, nil, fmt.Errorf("walk %s: %w", root, walkErr)
	}
	return found, unreadable, nil
}

// relativeTo names a path the way the report should, relative to the root of the
// walk and separated by forward slashes.
func relativeTo(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// unreadableNote words the directories a walk was refused, capped like
// droppedNote: a tree nobody could read must be one visible line, not a silent
// pass and not a hundred lines.
func unreadableNote(dirs []string) string {
	if len(dirs) == 0 {
		return ""
	}
	counted := "directories were"
	if len(dirs) == 1 {
		counted = "directory was"
	}
	return fmt.Sprintf("%d %s not read (%s): the lockfiles inside were not evaluated", len(dirs), counted, listSome(dirs))
}
