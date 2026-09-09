package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/gitdiff"
)

// The git hooks trustdiff can install. Both run the same command; the choice is
// when the answer should arrive: pre-commit on every commit, pre-push once
// before the branch leaves the machine.
const (
	preCommitHook = "pre-commit"
	prePushHook   = "pre-push"
)

// hookMarker is the line that says trustdiff wrote a hook file. install refuses
// to replace a file that does not carry it unless --force, and uninstall removes
// only files that carry it, so a hook somebody else wrote is never lost to a
// typo. The version in the marker is the script's, not the tool's: it changes
// only when an older installed hook has to be recognized as older.
const hookMarker = "# trustdiff-managed-hook v1"

// hookFileMode is what git needs to run a hook: executable by its owner. git
// itself installs the sample hooks with these bits.
const hookFileMode fs.FileMode = 0o755

// wroteHook reports whether trustdiff wrote the file. The marker is the second
// line of every script hookScript has written, so the test is positional: a file
// that only mentions the marker, in a comment or in a note about a hook that used
// to be there, is somebody else's and uninstall must leave it alone.
func wroteHook(contents string) bool {
	lines := strings.Split(contents, "\n")
	return len(lines) > 1 && strings.TrimRight(lines[1], "\r") == hookMarker
}

// hookScript is the file install writes. It is a POSIX shell script because that
// is what git runs on every platform trustdiff supports, including Windows,
// where git ships its own shell.
//
// The script stays out of the way when it cannot do its work: without trustdiff
// on PATH it says so and lets the commit through, because a hook that blocks
// every commit after someone removes the binary teaches people to pass
// --no-verify by reflex.
func hookScript(hook string) string {
	return fmt.Sprintf(`#!/bin/sh
%s
#
# Installed by "trustdiff hook install", and rewritten by the next install, so
# configure the checks in .trustdiff.yaml rather than here. Remove it with
# "trustdiff hook uninstall".
#
# To get past it once: TRUSTDIFF_SKIP=1 git commit ..., or git commit --no-verify,
# which skips every hook.
set -eu

if [ -n "${TRUSTDIFF_SKIP-}" ]; then
	echo "trustdiff: TRUSTDIFF_SKIP is set, skipping the %s hook" >&2
	exit 0
fi

if ! command -v trustdiff >/dev/null 2>&1; then
	echo "trustdiff: not on PATH, skipping the %s hook" >&2
	exit 0
fi

exec trustdiff diff --fail-on block
`, hookMarker, hook, hook)
}

// hookResult is the --format json shape of "hook install" and "hook uninstall".
type hookResult struct {
	Hook   string `json:"hook"`
	Path   string `json:"path"`
	Action string `json:"action"`
}

// hook subcommands: install writes the hook that runs diff before a commit or a
// push, uninstall takes it away. Both work on the repository the working
// directory is in.
func (a *App) newHookCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage the git pre-commit and pre-push hook that runs diff",
		Long: `Install or remove a git hook that runs "trustdiff diff --fail-on block", so a
lockfile change is evaluated before it is committed or pushed.

The hook is written to the hooks directory of the repository the working
directory is in. A repository that sets core.hooksPath elsewhere runs the hooks
in that directory instead, and the file trustdiff writes here is ignored: copy it
across, or unset core.hooksPath.`,
		// See newCacheCommand: without these two, a mistyped subcommand exits 0.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}

	install := &cobra.Command{
		Use:   "install",
		Short: "Install the git hook",
		Long: `Write the pre-commit hook, or the pre-push hook with --pre-push, so that the
change about to be committed or pushed is evaluated with "trustdiff diff
--fail-on block".

An existing hook that trustdiff wrote is rewritten. Any other hook is left alone
and the command exits 2, because it is somebody's script: move it aside, or pass
--force to replace it, which discards it.`,
		Args: cobra.NoArgs,
		RunE: a.runHookInstall,
	}
	install.Flags().Bool("pre-push", false, "install as the pre-push hook instead of the pre-commit hook")
	install.Flags().Bool("force", false, "replace an existing hook that trustdiff did not write, discarding it")

	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the git hook",
		Long: `Remove the pre-commit hook, or the pre-push hook with --pre-push, if trustdiff
wrote it. A hook file that does not carry the trustdiff marker as its second line
is left alone, however often it mentions the marker elsewhere, and so is a hook
that is not there at all: both are reported and both exit 0.`,
		Args: cobra.NoArgs,
		RunE: a.runHookUninstall,
	}
	uninstall.Flags().Bool("pre-push", false, "remove the pre-push hook instead of the pre-commit hook")

	cmd.AddCommand(install, uninstall)
	return cmd
}

func (a *App) runHookInstall(cmd *cobra.Command, _ []string) error {
	hook, err := hookFromFlags(cmd)
	if err != nil {
		return err
	}
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return Usagef("--force: %v", err)
	}
	path, err := a.hookFilePath(cmd.Context(), hook)
	if err != nil {
		return err
	}

	existing, err := readHookFile(path)
	if err != nil {
		return Usagef("%v", err)
	}
	script := hookScript(hook)
	var action, line string
	switch {
	case existing == "":
		action, line = "installed", fmt.Sprintf("installed the trustdiff %s hook: %s", hook, path)
	case existing == script:
		// Nothing to write: saying so is more useful than reporting a write that
		// changed nothing, and it keeps a second install out of the file's mtime.
		return a.reportHook(hookResult{Hook: hook, Path: path, Action: "unchanged"},
			fmt.Sprintf("the trustdiff %s hook is already installed: %s", hook, path))
	case wroteHook(existing):
		action, line = "updated", fmt.Sprintf("updated the trustdiff %s hook: %s", hook, path)
	case force:
		action, line = "replaced", fmt.Sprintf("replaced the %s hook with the trustdiff hook: %s", hook, path)
	default:
		return Usagef("%s exists and trustdiff did not write it: move it aside, or pass --force to replace it (its contents are lost)", path)
	}

	if err := writeHookFile(path, script); err != nil {
		return Usagef("%v", err)
	}
	return a.reportHook(hookResult{Hook: hook, Path: path, Action: action}, line)
}

func (a *App) runHookUninstall(cmd *cobra.Command, _ []string) error {
	hook, err := hookFromFlags(cmd)
	if err != nil {
		return err
	}
	path, err := a.hookFilePath(cmd.Context(), hook)
	if err != nil {
		return err
	}

	existing, err := readHookFile(path)
	if err != nil {
		return Usagef("%v", err)
	}
	switch {
	case existing == "":
		return a.reportHook(hookResult{Hook: hook, Path: path, Action: "absent"},
			fmt.Sprintf("no %s hook to remove: %s does not exist", hook, path))
	case !wroteHook(existing):
		return a.reportHook(hookResult{Hook: hook, Path: path, Action: "kept"},
			fmt.Sprintf("left %s alone: trustdiff did not write it", path))
	}
	if err := os.Remove(path); err != nil {
		return Usagef("remove %s: %v", path, err)
	}
	return a.reportHook(hookResult{Hook: hook, Path: path, Action: "removed"},
		fmt.Sprintf("removed the trustdiff %s hook: %s", hook, path))
}

// reportHook prints what happened, as a line or as the json shape.
func (a *App) reportHook(result hookResult, line string) error {
	if a.Opts.Format == "json" {
		return a.writeJSON(result)
	}
	_, err := fmt.Fprintln(a.Stdout, line)
	return err
}

// hookFromFlags reads --pre-push and names the hook to work on.
func hookFromFlags(cmd *cobra.Command) (string, error) {
	prePush, err := cmd.Flags().GetBool("pre-push")
	if err != nil {
		return "", Usagef("--pre-push: %v", err)
	}
	if prePush {
		return prePushHook, nil
	}
	return preCommitHook, nil
}

// hookFilePath is where the named hook belongs in the repository the working
// directory is in.
func (a *App) hookFilePath(ctx context.Context, hook string) (string, error) {
	repo, err := gitdiff.Open(ctx, "")
	if err != nil {
		if errors.Is(err, gitdiff.ErrNotRepository) {
			return "", Usagef("%v: run \"trustdiff hook\" inside the repository whose hooks you want to manage", err)
		}
		return "", Usagef("%v", err)
	}
	dir, err := hooksDir(repo.Root())
	if err != nil {
		return "", Usagef("%v", err)
	}
	return filepath.Join(dir, hook), nil
}

// hooksDir is the directory git runs the hooks of the working tree at root from.
// That is <root>/.git/hooks in the ordinary case. When .git is a file, which is
// how git records a linked worktree or a submodule, it names the directory
// holding that tree's git data, and hooks live in the common directory that data
// points at, so the hook installed from a worktree is the one every worktree of
// the repository runs.
func hooksDir(root string) (string, error) {
	dir, err := gitDir(root)
	if err != nil {
		return "", err
	}
	common, err := commonDir(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(common, "hooks"), nil
}

// gitDir resolves <root>/.git to the directory that holds the repository data.
func gitDir(root string) (string, error) {
	path := filepath.Join(root, ".git")
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if info.IsDir() {
		return path, nil
	}
	// #nosec G304 -- the path is the .git entry of the repository root that git
	// itself just printed, not a path a caller chose.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	const prefix = "gitdir:"
	rest, ok := strings.CutPrefix(firstLine(string(data)), prefix)
	if !ok {
		return "", fmt.Errorf("%s does not name a git directory: expected a line beginning with %q", path, prefix)
	}
	return resolveGitPath(root, rest), nil
}

// commonDir follows the "commondir" file a linked worktree carries. Without it,
// the git directory is the common one.
func commonDir(gitDir string) (string, error) {
	path := filepath.Join(gitDir, "commondir")
	// #nosec G304 -- the path is built from the git directory resolved above.
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return gitDir, nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	line := firstLine(string(data))
	if line == "" {
		return gitDir, nil
	}
	return resolveGitPath(gitDir, line), nil
}

// resolveGitPath reads a path git wrote into one of its own files: it is either
// absolute or relative to the directory the file sits in, and git writes it with
// forward slashes on every platform.
func resolveGitPath(base, path string) string {
	path = filepath.FromSlash(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	return filepath.Clean(path)
}

// firstLine trims a file down to its first line without surrounding space, which
// is the shape of every one-line file git writes.
func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(line)
}

// readHookFile returns the hook file's contents, or the empty string when there
// is no such file. A directory in its place is reported rather than silently
// treated as absent.
func readHookFile(path string) (string, error) {
	// #nosec G304 -- the path is <hooks directory>/<one of two literal names>,
	// built from the repository root git printed.
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(data), nil
}

// writeHookFile writes the script, creating the hooks directory if a repository
// that has none needs one.
func writeHookFile(path, script string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// #nosec G306 -- git runs the file, so it has to carry the executable bits;
	// these are the bits git gives its own sample hooks.
	if err := os.WriteFile(path, []byte(script), hookFileMode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile applies the mode only when it creates the file, so an existing
	// hook that lost its executable bit gets it back here.
	if err := os.Chmod(path, hookFileMode); err != nil {
		return fmt.Errorf("make %s executable: %w", path, err)
	}
	return nil
}
