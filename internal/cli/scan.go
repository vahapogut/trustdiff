package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/checks"
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

Locations are relative to the path given here.`,
		Args: cobra.MaximumNArgs(1),
		RunE: a.runScan,
	}
	cmd.Flags().Bool("update-baseline", false, "write the observed trust signals to .trustdiff/baseline.json")
	return cmd
}

func (a *App) runScan(cmd *cobra.Command, args []string) error {
	update, err := cmd.Flags().GetBool("update-baseline")
	if err != nil {
		return Usagef("--update-baseline: %v", err)
	}
	if update {
		return Usagef("--update-baseline: the baseline arrives with the baseline command in a later release")
	}
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

	var inputs []checks.Input
	var notes []string
	read := make([]string, 0, len(paths))
	for _, rel := range paths {
		lf, err := parseLockfileAt(filepath.Join(dir, filepath.FromSlash(rel)), rel)
		if err != nil {
			// One lockfile no parser gets through must not cost the findings of
			// every other one: it is named beside the report and the scan carries
			// on. A file in the middle of a format migration is the ordinary case.
			notes = append(notes, fmt.Sprintf("%s: not read (%s); its entries were not evaluated", rel, reason(rel, err)))
			continue
		}
		read = append(read, rel)
		inputs = append(inputs, entryInputs(rel, lf)...)
		if note := droppedNote(rel, lf.Dropped); note != "" {
			notes = append(notes, note)
		}
	}
	if note := unreadableNote(unreadable); note != "" {
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
	return a.evaluate(cmd.Context(), st, inputs, incomplete)
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
