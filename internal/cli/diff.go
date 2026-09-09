package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/gitdiff"
	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// shortSHA is how many characters of an object name the notes print. Twelve is
// what git itself falls back to for a large repository, and it is unambiguous
// everywhere a reader would paste it.
const shortSHA = 12

func (a *App) newDiffCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff [<path>]",
		Short: "Evaluate lockfile changes against a git base",
		Long: `Evaluate only the lockfile entries that were added or changed since a git base.
The default base is the merge-base of HEAD with origin/main, or with origin/HEAD
when the default branch goes by another name, or HEAD~1 in a clone with no remote.
Name another one with --base; a CI job passes the base commit of the pull request.
A named base is taken as the fork point, the way "git diff <base>...HEAD" reads
it, so what the base branch gained meanwhile is not read as a change of this one.

The lockfiles compared are the ones the change touched and a parser reads. With
--base-file the comparison is against that file instead of against a commit, and
the head side is the path given here, or the lockfile of the same name in the
repository.

Entries the change removed are listed and never fetched: a version that is gone
has nothing left to evaluate.`,
		Args: cobra.MaximumNArgs(1),
		RunE: a.runDiff,
	}
	cmd.Flags().String("base", "", "git ref to compare against (default: merge-base with origin/main)")
	cmd.Flags().String("base-file", "", "compare against this lockfile instead of a git ref")
	cmd.Flags().Bool("update-baseline", false, "write the observed trust signals to .trustdiff/baseline.json")
	return cmd
}

func (a *App) runDiff(cmd *cobra.Command, args []string) error {
	base, err := cmd.Flags().GetString("base")
	if err != nil {
		return Usagef("--base: %v", err)
	}
	baseFile, err := cmd.Flags().GetString("base-file")
	if err != nil {
		return Usagef("--base-file: %v", err)
	}
	if base != "" && baseFile != "" {
		return Usagef("--base and --base-file cannot be combined: the base is either a git ref or a file, not both")
	}
	update, err := cmd.Flags().GetBool("update-baseline")
	if err != nil {
		return Usagef("--update-baseline: %v", err)
	}
	if update {
		return Usagef("--update-baseline: the baseline arrives with the baseline command in a later release")
	}
	if len(args) == 1 && baseFile == "" {
		return Usagef("diff takes a path only with --base-file, which says what to compare %s against", args[0])
	}

	st, err := a.settle()
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	// Every path this command reports is relative to the repository root, so the
	// repository is found first whichever base was named.
	repo, err := gitdiff.Open(ctx, "")
	if err != nil {
		return Usagef("%v", err)
	}
	repo.Log = a.Opts.Log

	var comparisons []*comparison
	var extra []string
	var against string
	if baseFile != "" {
		against = filepath.ToSlash(filepath.Clean(baseFile))
		c, err := a.compareWithFile(ctx, repo, baseFile, args)
		if err != nil {
			return err
		}
		comparisons = []*comparison{c}
	} else {
		sha, err := repo.ResolveBase(ctx, base)
		if err != nil {
			return Usagef("%v", err)
		}
		against = describeBase(base, sha)
		if comparisons, extra, err = a.compareWithRevision(ctx, repo, sha); err != nil {
			return err
		}
	}

	inputs, notes, incomplete := diffPlan(comparisons, against)
	if err := a.writeNotes(append(notes, extra...)); err != nil {
		return err
	}
	return a.evaluate(ctx, st, inputs, incomplete)
}

// comparison is one lockfile seen from both sides.
type comparison struct {
	// path is the head lockfile, relative to the repository root, forward
	// slashes. It is the path every location and every note names.
	path string
	// changes is what the head file locks that the base did not.
	changes gitdiff.Changes
	// ecosystem is the head file's ecosystem, for the formats that state it once
	// for the file rather than per entry.
	ecosystem model.Ecosystem
	// dropped and baseDropped are the entries the parsers could not read, head
	// side and base side. A dropped base entry is worth as much as a dropped head
	// one: it makes a package that was there all along look added.
	dropped     []string
	baseDropped []string
	// unread and baseUnread say why a whole side could not be read, empty when it
	// was. A base nothing could read leaves every head entry looking added, which
	// is what a lockfile migrating between format versions does and exactly what
	// deserves evaluating; a head nothing could read is compared with nothing at
	// all, because its entries are unknown rather than gone.
	unread     string
	baseUnread string
}

// diffPlan turns the comparisons into the subjects to evaluate and the lines to
// print beside the report. Removed entries are listed and never fetched.
// incomplete reports whether a side of a comparison could not be read, so the
// caller can let the exit code say that the answer covers less than it was asked
// to.
func diffPlan(comparisons []*comparison, against string) (inputs []checks.Input, notes []string, incomplete bool) {
	quiet := true
	for _, c := range comparisons {
		if !c.changes.Empty() || c.unread != "" || c.baseUnread != "" {
			quiet = false
		}
	}

	paths := make([]string, 0, len(comparisons))
	for _, c := range comparisons {
		paths = append(paths, c.path)
		switch {
		case c.unread != "":
			notes = append(notes, fmt.Sprintf("%s: not read (%s); its entries were not compared", c.path, c.unread))
			incomplete = true
		case !quiet:
			notes = append(notes, fmt.Sprintf("compared %s with %s", c.path, against))
		}
		if c.baseUnread != "" {
			notes = append(notes, fmt.Sprintf("%s at %s: not read (%s); every entry of the file reads as added",
				c.path, against, c.baseUnread))
			incomplete = true
		}
		for i := range c.changes.Added {
			inputs = append(inputs, inputFor(c.path, c.ecosystem, &c.changes.Added[i]))
		}
		for i := range c.changes.Changed {
			in := inputFor(c.path, c.ecosystem, &c.changes.Changed[i].Head)
			// The version the project had until this change, which the checks
			// compare against as well as the release before the new one.
			in.BaseVersion = c.changes.Changed[i].Base.Ref.Version
			inputs = append(inputs, in)
		}
		if note := removedNote(c.path, c.changes.Removed); note != "" {
			notes = append(notes, note)
		}
		if note := droppedNote(c.path, c.dropped); note != "" {
			notes = append(notes, note)
		}
		if note := droppedNote(c.path+" at "+against, c.baseDropped); note != "" {
			notes = append(notes, note)
		}
	}
	if quiet {
		notes = append([]string{quietNote(paths, against)}, notes...)
	}
	return inputs, notes, incomplete
}

// removedNote words the entries a change deleted as one line, capped the way
// droppedNote caps a partial parse: a project moving from npm to pnpm deletes a
// package-lock.json of two thousand entries, and the report it deletes them from
// must stay readable.
func removedNote(path string, removed []lockfile.Entry) string {
	if len(removed) == 0 {
		return ""
	}
	refs := make([]string, 0, len(removed))
	for i := range removed {
		refs = append(refs, removed[i].Ref.String())
	}
	counted := "entries"
	if len(removed) == 1 {
		counted = "entry"
	}
	return fmt.Sprintf("removed %d %s from %s (%s)", len(removed), counted, path, listSome(refs))
}

// quietNote is the line a run with nothing to evaluate prints: which lockfiles
// were compared and that they hold the same versions, or that the change touched
// no lockfile at all, which is what most pull requests look like.
func quietNote(paths []string, against string) string {
	if len(paths) == 0 {
		return fmt.Sprintf("no lockfile changed since %s", against)
	}
	return fmt.Sprintf("nothing changed in %s compared with %s", strings.Join(paths, ", "), against)
}

// compareWithRevision compares every lockfile the change touched against the
// revision. A file the change added has no base side, one it deleted has no head
// side, and both are the ordinary cases rather than failures. The notes it
// returns beside the comparisons are about the files git cannot compare at all.
func (a *App) compareWithRevision(ctx context.Context, repo *gitdiff.Repo, sha string) ([]*comparison, []string, error) {
	changed, err := repo.ChangedFiles(ctx, sha)
	if err != nil {
		return nil, nil, Usagef("%v", err)
	}
	comparisons := make([]*comparison, 0, 2)
	for _, path := range changed {
		if _, ok := lockfile.For(path); !ok {
			continue
		}
		baseLF, baseUnread, err := lockfileAtRevision(ctx, repo, sha, path)
		if err != nil {
			return nil, nil, err
		}
		headLF, unread := lockfileInTree(repo.Abs(path), path)
		comparisons = append(comparisons, newComparison(path, baseLF, headLF, baseUnread, unread))
	}
	a.Opts.Log.Debug("lockfiles to compare", "count", len(comparisons), "changed files", len(changed))
	return comparisons, a.untrackedNotes(ctx, repo), nil
}

// untrackedNotes names the lockfiles the working tree holds and git does not
// track. A file that was written and never added is invisible to a comparison
// against a revision, and saying nothing about it would report it as unchanged,
// which is the one answer it must not get. Failing to ask git is not worth
// stopping the run for, so it is logged and the run goes on.
func (a *App) untrackedNotes(ctx context.Context, repo *gitdiff.Repo) []string {
	untracked, err := repo.UntrackedLockfiles(ctx)
	if err != nil {
		a.Opts.Log.Debug("could not list the untracked lockfiles", "error", err)
		return nil
	}
	switch len(untracked) {
	case 0:
		return nil
	case 1:
		return []string{fmt.Sprintf("%s is not tracked by git, so it was not compared; git add it to have it evaluated", untracked[0])}
	default:
		return []string{fmt.Sprintf("%d lockfiles are not tracked by git, so they were not compared (%s); git add them to have them evaluated",
			len(untracked), listSome(untracked))}
	}
}

// compareWithFile compares one lockfile in the working tree against a file the
// user named. The head side is the path given on the command line, or the
// lockfile of the same name the repository tracks.
func (a *App) compareWithFile(ctx context.Context, repo *gitdiff.Repo, baseFile string, args []string) (*comparison, error) {
	baseLF, err := parseLockfileAt(baseFile, baseFile)
	if err != nil {
		return nil, Usagef("--base-file %s: %s", baseFile, reason(baseFile, err))
	}
	openPath, headPath, err := a.headFor(ctx, repo, baseFile, args)
	if err != nil {
		return nil, err
	}
	headLF, unread := lockfileInTree(openPath, headPath)
	if headLF == nil && unread == "" {
		return nil, Usagef("%s does not exist: name the lockfile to compare against %s", headPath, baseFile)
	}
	if headLF != nil && headLF.Format != baseLF.Format {
		return nil, Usagef("%s is a %s and %s is a %s: a base file can only be compared with a lockfile of its own format",
			baseFile, baseLF.Format, headPath, headLF.Format)
	}
	return newComparison(headPath, baseLF, headLF, "", unread), nil
}

// headFor decides which lockfile the base file is compared against: the one named
// on the command line, or the single lockfile of that name the repository tracks.
// Two files of the same name is the monorepo case and the user has to say which.
// It returns the path to open, which is the one the user typed and is resolved
// against the working directory, and the path the report names, which is relative
// to the repository root.
func (a *App) headFor(ctx context.Context, repo *gitdiff.Repo, baseFile string, args []string) (openPath, headPath string, err error) {
	if len(args) == 1 {
		return args[0], repoRelative(repo, args[0]), nil
	}
	tracked, err := repo.Lockfiles(ctx)
	if err != nil {
		return "", "", Usagef("%v", err)
	}
	name := filepath.Base(baseFile)
	matching := make([]string, 0, 2)
	for _, path := range tracked {
		if strings.EqualFold(filepath.Base(path), name) {
			matching = append(matching, path)
		}
	}
	switch len(matching) {
	case 1:
		return repo.Abs(matching[0]), matching[0], nil
	case 0:
		return "", "", Usagef("no lockfile found: the repository tracks no %s to compare %s against; name one as an argument", name, baseFile)
	default:
		return "", "", Usagef("the repository tracks %d files named %s (%s): name the one to compare %s against as an argument",
			len(matching), name, strings.Join(matching, ", "), baseFile)
	}
}

// newComparison diffs the two sides and keeps what the notes need. Either side
// may be nil, which is a lockfile the change added or deleted, or one nothing
// could read. A head side nothing could read is not diffed at all: its entries
// are unknown, and a comparison against nothing would report every entry of the
// base as removed.
func newComparison(path string, base, head *lockfile.Lockfile, baseUnread, unread string) *comparison {
	c := &comparison{path: path, baseUnread: baseUnread, unread: unread}
	if unread == "" {
		c.changes = gitdiff.Diff(base, head)
	}
	if head != nil {
		c.ecosystem = head.Ecosystem
		c.dropped = head.Dropped
	}
	if base != nil {
		if c.ecosystem == "" {
			c.ecosystem = base.Ecosystem
		}
		c.baseDropped = base.Dropped
	}
	return c
}

// lockfileAtRevision parses what the revision recorded for the path. A path the
// revision does not have is a lockfile the change adds, and its base side is
// nothing rather than an error. A file no parser gets through comes back as a
// reason to report beside the run: a lockfile that changed format between the two
// revisions, npm 6 to npm 7 or pnpm 5 to pnpm 9, is an ordinary pull request and
// every entry of its head side still deserves evaluating. The error is kept for
// git itself failing, which leaves nothing to compare.
func lockfileAtRevision(ctx context.Context, repo *gitdiff.Repo, sha, path string) (*lockfile.Lockfile, string, error) {
	data, err := repo.FileAt(ctx, sha, path)
	if errors.Is(err, gitdiff.ErrNotAtRev) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", Usagef("%v", err)
	}
	lf, err := lockfile.Parse(path, bytes.NewReader(data))
	if err != nil {
		return nil, reason(path, err), nil
	}
	return lf, "", nil
}

// lockfileInTree parses the working tree's copy. A file that is not there is a
// lockfile the change deleted, and its head side is nothing: both returns are
// empty. A file that is there and cannot be read or parsed comes back as the
// reason, so the run reports it and keeps the findings of every other lockfile.
func lockfileInTree(openPath, path string) (*lockfile.Lockfile, string) {
	f, err := openLockfile(openPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ""
	}
	if err != nil {
		return nil, reason(path, err)
	}
	defer f.Close()
	lf, err := lockfile.Parse(path, f)
	if err != nil {
		return nil, reason(path, err)
	}
	return lf, ""
}

// reason words a failure for a note or a message that already names the file: its
// first line, without the leading file name a parser puts there, so the line
// reads as one sentence instead of naming the same file twice.
func reason(name string, err error) string {
	line, _, _ := strings.Cut(err.Error(), "\n")
	line = strings.TrimSpace(line)
	return strings.TrimSpace(strings.TrimPrefix(line, name+":"))
}

// repoRelative names a path the way the report should: relative to the repository
// root with forward slashes when the file is inside it, and as given, cleaned,
// when it is not.
func repoRelative(repo *gitdiff.Repo, path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(path))
	}
	rel, err := filepath.Rel(repo.Root(), abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(filepath.Clean(path))
	}
	return filepath.ToSlash(rel)
}

// describeBase words the revision the run compared against: the base the user
// named together with the fork point it was taken back to, or the commit alone
// when there was no ref or the ref named that very commit, where saying it twice
// adds nothing.
func describeBase(ref, sha string) string {
	short := sha[:min(len(sha), shortSHA)]
	if ref == "" || strings.HasPrefix(sha, ref) {
		return short
	}
	return fmt.Sprintf("%s (fork point %s)", shortenRev(ref), short)
}

// shortenRev abbreviates a ref that is itself a full object name, which is what a
// CI job passes, so a note carries twelve characters rather than forty. Anything
// else is a name a person chose and is printed as it is.
func shortenRev(ref string) string {
	if len(ref) != 40 {
		return ref
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ref
		}
	}
	return ref[:shortSHA]
}
