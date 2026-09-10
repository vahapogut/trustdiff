package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/baseline"
	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/gitdiff"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/report"
)

// baselineCheck is the check a maintainer set change is reported as. The drift
// the baseline command reports is the same finding TD003 makes during a run, made
// for a package no run would have been given a subject for, so it carries the same
// id, the same policy name and therefore the same level and the same allow list.
const baselineCheck = "maintainers-changed"

// baselineCheckID is that check's stable id.
const baselineCheckID = "TD003"

func (a *App) newBaselineCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "baseline [<path>]",
		Short: "Snapshot the current trust signals of all locked packages",
		Long: `Record who maintains every package the lockfiles under a path lock, who published
the release that is locked, and what provenance that release carried, in
.trustdiff/baseline.json. Commit the file: it is what lets trustdiff answer for
the registries that only answer about now. PyPI records no publisher per version
and crates.io keeps no maintainer history, so without a baseline the
publisher-changed and maintainers-changed checks report themselves as skipped
there.

The path is the working directory by default, and the file is the one found
upward from it, the way the policy file is found, so a command run in one package
of a monorepo writes the repository's baseline.

This asks a registry about every locked package, so it is as slow as scan. It
also reports the packages whose maintainer set changed since the record it is
replacing, which is the one thing no run over a lockfile change can see: nothing
about the lockfile moved, so there was no version for a check to be given.

Entries for packages the project no longer locks are dropped, unless a lockfile
could not be read, in which case nothing is dropped and the run says why.`,
		Args: cobra.MaximumNArgs(1),
		RunE: a.runBaseline,
	}
}

func (a *App) runBaseline(cmd *cobra.Command, args []string) error {
	root := "."
	if len(args) == 1 {
		root = args[0]
	}
	st, err := a.settle()
	if err != nil {
		return err
	}
	dir, paths, unreadable, err := a.scanTargets(root)
	if err != nil {
		return err
	}
	inputs, read, notes := a.readLockfiles(dir, paths)
	if note := unreadableNote(unreadable); note != "" {
		notes = append(notes, note)
	}
	incomplete := len(read) < len(paths) || len(unreadable) > 0

	path, err := a.baselinePath(dir)
	if err != nil {
		return err
	}
	// The record the run is about to write into is read first: it is what the
	// packages whose maintainers changed are compared with, and the write replaces
	// every signal this run managed to observe.
	recorded, err := a.readBaseline(path)
	if err != nil {
		return err
	}

	loader, err := loaderFactory(a)
	if err != nil {
		return Usagef("%v", err)
	}
	now := baselineClock(st)
	refs := inputRefs(inputs)
	if err := a.writeNotes(append([]string{fmt.Sprintf("observing %s of %s",
		countOf(len(refs), "package", "packages"),
		countOf(len(read), "lockfile", "lockfiles"))}, notes...)); err != nil {
		return err
	}

	observed, problems, unavailable := baseline.Observe(cmd.Context(), loader, refs, now, a.Opts.Jobs)
	changes := baseline.Compare(recorded, observed)
	// A run that could not read every lockfile must not delete the record of the
	// packages it therefore never saw, so pruning is left to a complete run.
	keep := refs
	if incomplete {
		keep = nil
	}
	dropped, err := baseline.Update(path, observed, keep, now)
	if err != nil {
		return fmt.Errorf("update the baseline: %w", err)
	}
	if err := a.writeNotes(append([]string{baselineWritten(path, len(observed), dropped, incomplete)}, problems...)); err != nil {
		return err
	}

	rep := report.Build(driftSubjects(changes, st.pol, now), report.CurrentTool(), report.Policy{
		Path:     st.policyPath,
		Cooldown: st.cooldown,
		FailOn:   a.Opts.FailOn,
	}, st.failOn)
	// Something the run could not read, a lockfile or a registry answer, makes the
	// record incomplete, and the policy decides whether that is worth an exit code.
	// A registry that did not answer is put to the policy of its own package's
	// ecosystem, the way a check outcome is; a lockfile no parser got through
	// belongs to no ecosystem and is put to the top-level setting. The rest of the
	// problem lines are not outages at all: a package locked at two versions and a
	// registry that lists nobody are answers, and exit code 3 says a data source
	// was unavailable.
	if rep.Summary.ExitCode == ExitOK && (unreadFails(st.pol, incomplete) || refsDataUnavailableFail(st.pol, unavailable)) {
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

// evaluateWithBaseline runs the checks over the inputs, writes the report and
// returns the exit code as an error, the way check does: 1 for findings at or
// above --fail-on, 3 when a data source was unavailable and the policy says fail.
// A run with no inputs still writes a report, so a document format always gets a
// document. It is what diff and scan end with.
//
// incomplete says that something the run should have looked at could not be read:
// a lockfile no parser got through, a directory the walk was refused. The notes
// name it, and the exit code follows on_data_unavailable, because a report that
// covers less than it was asked to is the same kind of partial answer as one a
// registry did not respond to.
//
// The project's baseline is attached to the loader, so that TD002 and TD003 can
// answer for the registries that keep no history, and what the run observed is
// written back into it when --update-baseline was given. The baseline is the one
// thing a run needs that the loader does not fetch: it has to be read before the
// loader is built and written after the checks have run, from that same loader,
// whose memo makes the second pass free.
func (a *App) evaluateWithBaseline(ctx context.Context, cmd *cobra.Command, st *settings, inputs []checks.Input, incomplete bool, dir string) error {
	path, err := a.baselinePath(dir)
	if err != nil {
		return err
	}
	set, err := a.baselineSet(ctx, cmd, path)
	if err != nil {
		return err
	}
	loader, err := loaderFactory(a)
	if err != nil {
		return Usagef("%v", err)
	}
	runner := &checks.Runner{
		Loader:  withBaseline(loader, set),
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
	if rep.Summary.ExitCode == ExitOK && (dataUnavailableFails(st.pol, outcomes) || unreadFails(st.pol, incomplete)) {
		rep.SetExitCode(ExitUnavailable)
	}
	if err := st.writer.Write(a.Stdout, rep); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	// The baseline is written after the report, so a run that is killed while
	// writing it has still said what it found, and only when the report stopped at
	// nothing. A run that reported a maintainer takeover would otherwise record the
	// attacker's set as the new truth, in the file the README tells people to
	// commit, and the next run would compare with it and pass.
	if update, _ := cmd.Flags().GetBool("update-baseline"); update {
		if err := a.updateBaseline(ctx, st, loader, inputs, path, rep.Summary.ExitCode); err != nil {
			return err
		}
	}
	if rep.Summary.ExitCode != ExitOK {
		return Exit(rep.Summary.ExitCode, nil)
	}
	return nil
}

// updateBaseline records what the run observed, which is what --update-baseline
// asks for, unless the report exits with anything but 0. The run's own loader is
// used: every answer it needs is already memoized, so this costs no request.
//
// A failure here is returned as a plain error, which is exit code 2. It cannot
// take an exit code away from the findings, because a run with findings does not
// reach the write in the first place.
func (a *App) updateBaseline(ctx context.Context, st *settings, src baseline.Signals, inputs []checks.Input, path string, exitCode int) error {
	if exitCode != ExitOK {
		return a.writeNotes([]string{fmt.Sprintf(
			"the baseline was not updated: the run exits %d, and a record refreshed by a run that reported something is a record of what it reported",
			exitCode)})
	}
	// The packages a registry did not answer for are already in the outcomes the
	// report was built from, so what they are worth has been decided above.
	observed, problems, _ := baseline.Observe(ctx, src, inputRefs(inputs), baselineClock(st), a.Opts.Jobs)
	dropped, err := baseline.Update(path, observed, nil, baselineClock(st))
	if err != nil {
		return fmt.Errorf("update the baseline: %w", err)
	}
	return a.writeNotes(append([]string{baselineWritten(path, len(observed), dropped, true)}, problems...))
}

// refsDataUnavailableFail reports whether a data source that did not answer for
// one of these packages should make the exit code 3, asking the policy of each
// package's own ecosystem the way dataUnavailableFails asks it for a check
// outcome.
func refsDataUnavailableFail(pol *policy.Policy, refs []model.PackageRef) bool {
	for _, ref := range refs {
		if pol.Effective(ref.Ecosystem).OnDataUnavailable == policy.OnDataUnavailableFail {
			return true
		}
	}
	return false
}

// readLockfiles parses the lockfiles of a directory into subjects to observe. It
// is what scan does before it evaluates, with the same rule: one file no parser
// gets through is named beside the run and costs nothing but its own entries.
func (a *App) readLockfiles(dir string, paths []string) (inputs []checks.Input, read, notes []string) {
	read = make([]string, 0, len(paths))
	for _, rel := range paths {
		lf, err := parseLockfileAt(filepath.Join(dir, filepath.FromSlash(rel)), rel)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: not read (%s); its entries were not observed", rel, reason(rel, err)))
			continue
		}
		read = append(read, rel)
		inputs = append(inputs, entryInputs(rel, lf)...)
		if note := droppedNote(rel, lf.Dropped); note != "" {
			notes = append(notes, note)
		}
	}
	return inputs, read, notes
}

// inputRefs is the refs of the subjects a run was given, in their order.
func inputRefs(inputs []checks.Input) []model.PackageRef {
	refs := make([]model.PackageRef, 0, len(inputs))
	for i := range inputs {
		refs = append(refs, inputs[i].Ref)
	}
	return refs
}

// baselineClock is the run's clock with the runner's own fallback applied, so
// that an observation is stamped with the same time the checks judged by.
func baselineClock(st *settings) time.Time {
	if st.now.IsZero() {
		return time.Now()
	}
	return st.now
}

// baselinePath is the file the run reads and writes: the one found upward from
// dir, the way the policy file is found, or the one this directory would hold
// when the project has none yet.
//
// The answer is always absolute, as Find's is. A relative path is what a run
// started in the working directory would get for a baseline that is not there,
// and baselineSet has to place that path inside the repository to read the base
// revision's copy of it: a relative path cannot be placed, the comparison reads
// as "outside the repository", and the base revision is then never consulted.
// That is the whole gate, turned off by deleting a file.
func (a *App) baselinePath(dir string) (string, error) {
	found, ok, err := baseline.Find(dir)
	if err != nil {
		return "", Usagef("%v", err)
	}
	if ok {
		return found, nil
	}
	path, err := filepath.Abs(baseline.Path(dir))
	if err != nil {
		return "", Usagef("resolve %q: %v", baseline.Path(dir), err)
	}
	return path, nil
}

// readBaseline loads the project's baseline. A project that has none is not a
// failure and answers nil; a file that cannot be read is, because a run that
// carried on without it would report every check that needs a record as skipped
// and a gate would read that as nothing to see.
func (a *App) readBaseline(path string) (*baseline.File, error) {
	f, err := baseline.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		a.Opts.Log.Debug("no baseline found", "path", path)
		return nil, nil //nolint:nilnil // no baseline is the ordinary case and not a failure
	case err != nil:
		return nil, Usagef("%v", err)
	}
	a.Opts.Log.Debug("baseline loaded", "path", path, "packages", len(f.Packages))
	return f, nil
}

// baselineSet is the baseline as this run sees it: the file the working tree
// holds and, when the run compares against a git revision, the file that revision
// held.
//
// The second side is what makes a pull request gate honest. The baseline in the
// working tree is a file like any other and the change under review may have
// edited it, so the record the base revision holds is read too and wins wherever
// the two disagree. A revision that has no baseline is what a change adding the
// file looks like, and a repository that cannot be read at all leaves the base
// side empty rather than failing the run: the working tree's record still answers.
func (a *App) baselineSet(ctx context.Context, cmd *cobra.Command, path string) (*baseline.Set, error) {
	head, err := a.readBaseline(path)
	if err != nil {
		return nil, err
	}
	set := &baseline.Set{Head: head}
	base := cmd.Flags().Lookup("base")
	baseFile := cmd.Flags().Lookup("base-file")
	if base == nil || (baseFile != nil && baseFile.Value.String() != "") {
		// scan, and diff comparing against a file rather than a revision: there is
		// no revision to read a second copy from.
		return set, nil
	}
	repo, err := gitdiff.Open(ctx, "")
	if err != nil {
		a.Opts.Log.Debug("no repository to read the base revision's baseline from", "error", err)
		return set, nil
	}
	sha, err := repo.ResolveBase(ctx, base.Value.String())
	if err != nil {
		a.Opts.Log.Debug("no base revision to read the baseline at", "error", err)
		return set, nil
	}
	// Both sides are resolved first. A temporary directory is a link to another
	// place on macOS (/var against /private/var) and carries a short name on
	// Windows (RUNNER~1), while git always answers with the resolved path, and an
	// unresolved comparison then reads as "outside the repository" and quietly
	// falls back to the working tree's own record, which is the copy a pull
	// request may have written.
	rel, relErr := filepath.Rel(resolve(repo.Root()), resolve(path))
	if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// A baseline outside the repository (an absolute --policy style path, a
		// working directory above the root) has no copy in the history to read, and
		// the working tree's record still answers.
		a.Opts.Log.Debug("the baseline is outside the repository", "path", path, "root", repo.Root(), "error", relErr)
		return set, nil
	}
	at, err := baseline.AtRevision(ctx, repo, sha, rel)
	switch {
	case errors.Is(err, gitdiff.ErrNotAtRev):
		a.Opts.Log.Debug("the base revision has no baseline", "path", rel, "base", sha)
		return set, nil
	case err != nil:
		// A baseline the base revision cannot serve is a broken record, not a
		// missing one, and the run stops rather than comparing with the copy the
		// change under review supplied.
		return nil, Usagef("%v", err)
	}
	set.Base = at
	return set, nil
}

// withBaseline attaches the baseline to a run's data loader, which is how a check
// reaches it: internal/checks.BaselineLoader is an optional method on the Loader,
// the way the deps.dev findings are, because Subject.Loader is the one thing on a
// subject a command can put its own data into.
//
// The wrapper carries the deps.dev findings method only when the wrapped loader
// has it, so that attaching a baseline never changes what the runner can ask for.
func withBaseline(loader checks.Loader, set *baseline.Set) checks.Loader {
	wrapped := baselineLoader{Loader: loader, set: set}
	if findings, ok := loader.(checks.DepsDevFindingsLoader); ok {
		return baselineFindingsLoader{baselineLoader: wrapped, findings: findings}
	}
	return wrapped
}

// baselineLoader is a data loader that also serves the project's baseline.
type baselineLoader struct {
	checks.Loader
	set *baseline.Set
}

// Baseline returns the record of a package, which is what TD002 and TD003 read.
func (l baselineLoader) Baseline(ref model.PackageRef) (baseline.Record, bool) {
	return l.set.Lookup(ref)
}

// baselineFindingsLoader is a baselineLoader over a loader that serves the
// deps.dev findings, forwarding them unchanged.
type baselineFindingsLoader struct {
	baselineLoader
	findings checks.DepsDevFindingsLoader
}

func (l baselineFindingsLoader) DepsDevFindings(ctx context.Context, ref model.PackageRef) ([]depsdev.Finding, error) {
	return l.findings.DepsDevFindings(ctx, ref)
}

// baselineWritten words what a write did, so a person sees the file change and a
// log shows what was dropped. merged says the run recorded only what it looked at
// and left the rest of the file alone, which is what --update-baseline does.
func baselineWritten(path string, observed int, dropped []baseline.Entry, merged bool) string {
	line := fmt.Sprintf("recorded %s in %s",
		countOf(observed, "package", "packages"), filepath.ToSlash(path))
	if merged {
		line += ", leaving the rest of the file alone"
	}
	if len(dropped) == 0 {
		return line
	}
	refs := make([]string, 0, len(dropped))
	for i := range dropped {
		refs = append(refs, dropped[i].Package().String())
	}
	return line + fmt.Sprintf("; dropped %s no longer locked (%s)",
		countOf(len(dropped), "entry", "entries"), listSome(refs))
}

// driftSubjects turns the maintainer set changes into the report a person reads.
//
// This is the shape the runner has no room for. A run evaluates a package
// version only where a lockfile line installs it, and a maintainer set that
// changed while the locked version stayed put moves no version and therefore
// produces no subject; the baseline
// command has one for every package it observed, so it reports the change itself,
// as the finding TD003 would have made, with the level and the allow list the
// policy gives that check.
func driftSubjects(changes []baseline.Change, pol *policy.Policy, now time.Time) []report.Subject {
	subjects := make([]report.Subject, 0, len(changes))
	for i := range changes {
		c := &changes[i]
		setting, ok := pol.Effective(c.Now.Ecosystem).Check(baselineCheck)
		if !ok || setting.Level == model.LevelOff {
			continue
		}
		ref := c.Now.Ref()
		if _, allowed := pol.Allowed(baselineCheck, ref, now); allowed {
			continue
		}
		subjects = append(subjects, report.Subject{
			Ref:       ref,
			Evaluated: []string{baselineCheckID},
			Findings:  []model.Finding{driftFinding(c, setting.Level, now)},
		})
	}
	return subjects
}

// driftFinding words one maintainer set change the way TD003 words the same
// comparison during a run, so a reader who has seen one has seen the other.
func driftFinding(c *baseline.Change, level model.Level, now time.Time) model.Finding {
	changes := make([]string, 0, 2)
	if len(c.Added) > 0 {
		changes = append(changes, "added "+strings.Join(c.Added, ", "))
	}
	if len(c.Removed) > 0 {
		changes = append(changes, "removed "+strings.Join(c.Removed, ", "))
	}
	days := int(c.Was.Age(now) / (24 * time.Hour))
	explanation := fmt.Sprintf("the baseline recorded %s as maintainers of %s when %s was observed, %d days ago; the registry lists %s now: %s",
		strings.Join(c.Was.Maintainers, ", "), c.Was.Package(), c.Was.Version, days,
		strings.Join(c.Now.Maintainers, ", "), strings.Join(changes, " and "))
	if !c.VersionMoved() {
		explanation += "; the locked version did not move, so nothing but the baseline says this happened"
	}
	return model.Finding{
		ID:          baselineCheckID,
		Name:        baselineCheck,
		Level:       level,
		Ref:         c.Now.Ref(),
		Title:       "Maintainers changed since the baseline: " + strings.Join(changes, ", "),
		Explanation: explanation,
		Evidence: map[string]any{
			"baseline_maintainers": c.Was.Maintainers,
			"maintainers":          c.Now.Maintainers,
			"added":                c.Added,
			"removed":              c.Removed,
			"baseline_version":     c.Was.Version,
			"baseline_observed_at": c.Was.ObservedAt.UTC().Format(time.RFC3339),
			"baseline_age_days":    days,
		},
	}
}

// resolve follows the links in a path so that two spellings of one directory
// compare equal.
//
// A path that does not exist is resolved through the deepest ancestor that does,
// and its own last elements are appended unchanged. The file that is not there is
// the case that matters: a baseline the change under review deleted still has to
// be placed inside the repository so that the base revision's copy is read, and a
// path left in the spelling it arrived in would compare as though it lay
// somewhere else altogether, because a temporary directory is a link on macOS
// (/var against /private/var) and carries a short name on Windows (RUNNER~1)
// while git always answers with the resolved one.
func resolve(path string) string {
	if evaluated, err := filepath.EvalSymlinks(path); err == nil {
		return evaluated
	}
	parent := filepath.Dir(path)
	if parent == path {
		// The root of a volume, which either resolved above or cannot be resolved
		// at all; there is nothing left to walk up to.
		return path
	}
	return filepath.Join(resolve(parent), filepath.Base(path))
}
