package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/gitdiff"
	"github.com/vahapogut/trustdiff/internal/lockfile"
)

func (a *App) newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [<path>]",
		Short: "Evaluate every entry of every lockfile found under a path",
		Long: `Evaluate every entry of every lockfile found under a path, the working directory
by default. A path that names one lockfile evaluates that file alone. The walk
skips .git, node_modules, vendor, target, dist and .venv, because the lockfiles
inside those belong to a dependency or to a build rather than to the project.

This asks a registry about every locked package, so it is slow by design and it
says how much work it is about to do before it starts. Use it for a first look at
a project or for an audit; a pull request wants diff, which evaluates only what
the change added or modified.

Locations are named from the root of the repository when the path is inside one,
which is what diff already does and what a code scanning service resolves a SARIF
location against, and from the path given here when it is not.`,
		Args: cobra.MaximumNArgs(1),
		RunE: a.runScan,
	}
	cmd.Flags().Bool("update-baseline", false, "write the observed trust signals to .trustdiff/baseline.json")
	return cmd
}

func (a *App) runScan(cmd *cobra.Command, args []string) error {
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
	// Every path the report carries is named from the repository root, so that a
	// service reading the SARIF resolves it against the checkout and lands on the
	// file this run read. Nothing on disk is opened through it: dir stays the place
	// the files are, and this is only what they are called.
	prefix := a.repositoryPrefix(cmd.Context(), dir)

	var inputs []checks.Input
	var notes []string
	read := make([]string, 0, len(paths))
	for _, rel := range paths {
		named := prefix + rel
		lf, err := parseLockfileAt(filepath.Join(dir, filepath.FromSlash(rel)), named)
		if err != nil {
			// One lockfile no parser gets through must not cost the findings of
			// every other one: it is named beside the report and the scan carries
			// on. A file in the middle of a format migration is the ordinary case.
			notes = append(notes, fmt.Sprintf("%s: not read (%s); its entries were not evaluated", named, reason(named, err)))
			continue
		}
		read = append(read, named)
		inputs = append(inputs, entryInputs(named, lf)...)
		if note := droppedNote(named, lf.Dropped); note != "" {
			notes = append(notes, note)
		}
	}
	if note := unreadableNote(prefixAll(prefix, unreadable)); note != "" {
		notes = append(notes, note)
	}

	// The count comes before the run rather than with the report: a person who
	// reads "evaluating 1843 entries" knows to wait instead of interrupting. It
	// counts the files that were read, and the notes below say what was not.
	counts := fmt.Sprintf("evaluating %s of %s",
		countOf(len(inputs), "entry", "entries"),
		countOf(len(read), "lockfile", "lockfiles"))
	if len(read) > 0 {
		counts += ": " + strings.Join(read, ", ")
	}
	if err := a.writeNotes(append([]string{counts}, notes...)); err != nil {
		return err
	}
	incomplete := len(read) < len(paths) || len(unreadable) > 0
	return a.evaluateWithBaseline(cmd.Context(), cmd, st, inputs, incomplete, dir)
}

// repositoryPrefix is the path from the root of the repository that contains dir to
// dir itself, with a trailing slash, and the empty string when dir is not inside a
// git working tree or git is not installed.
//
// A report that names a lockfile "package-lock.json" when the file is at
// "frontend/package-lock.json" is not merely terse: a code scanning service resolves
// a SARIF artifact location against the checkout root, so the annotation lands on a
// different file, or on nothing. diff never had the problem, because git names every
// path from the root, and this is what makes scan agree with it.
//
// Both sides are resolved through symlinks before they are compared, because git
// prints the resolved root and a temporary directory on macOS is reached by two
// names. A dir that still does not sit under the root, which no correct answer
// produces, falls back to naming paths as they were given.
func (a *App) repositoryPrefix(ctx context.Context, dir string) string {
	repo, err := gitdiff.Open(ctx, dir)
	if err != nil {
		return ""
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	rel, err := filepath.Rel(repo.Root(), abs)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == "" || rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	return rel + "/"
}

// prefixAll names every path in a list from the same place.
func prefixAll(prefix string, paths []string) []string {
	if prefix == "" || len(paths) == 0 {
		return paths
	}
	named := make([]string, len(paths))
	for i, p := range paths {
		named[i] = prefix + p
	}
	return named
}

// scanTargets returns the directory to read from, the lockfiles under it, named
// relative to that directory with forward slashes, and the directories the walk
// was not allowed to read. A path that names one file is that file alone, so the
// command can be pointed at a single lockfile; a path that names a directory is
// walked.
func (a *App) scanTargets(root string) (dir string, paths, unreadable []string, err error) {
	info, err := os.Stat(root)
	if err != nil {
		return "", nil, nil, Usagef("%v", err)
	}
	if !info.IsDir() {
		if _, ok := lockfile.For(root); !ok {
			return "", nil, nil, Usagef("no parser reads %s: trustdiff reads %s", root, strings.Join(parserNames(), ", "))
		}
		return filepath.Dir(root), []string{filepath.ToSlash(filepath.Base(root))}, nil, nil
	}
	paths, unreadable, err = findLockfiles(root, a.Opts.Log)
	if err != nil {
		return "", nil, nil, Usagef("%v", err)
	}
	if len(paths) == 0 && len(unreadable) == 0 {
		return "", nil, nil, Usagef("no lockfile found under %s: trustdiff reads %s", root, strings.Join(parserNames(), ", "))
	}
	// A tree that holds no readable lockfile but kept the walk out of part of
	// itself is not an empty tree: the run goes on so the note names the
	// directories that were refused, and the exit code follows the policy.
	return root, paths, unreadable, nil
}

// parserNames lists the formats the binary can read, for the messages that say a
// path holds none of them.
func parserNames() []string {
	parsers := lockfile.Parsers()
	names := make([]string, 0, len(parsers))
	for _, p := range parsers {
		names = append(names, p.Name())
	}
	return names
}

// countOf words a count with its noun, so a line reads "1 lockfile" and
// "2 lockfiles" rather than carrying a number nothing names.
func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
