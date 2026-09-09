package cli

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// newHookRepo makes an empty repository under t.TempDir(), makes it the working
// directory and returns its path. The repository is isolated from the machine's
// git configuration the way internal/gitdiff isolates its own: the two
// configuration files are named inside the temporary directory and never
// created, which git reads as empty.
func newHookRepo(t *testing.T) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not on PATH")
	}
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "absent-global-gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", filepath.Join(dir, "absent-system-gitconfig"))
	cmd := exec.CommandContext(t.Context(), git, "init", "--quiet")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	t.Chdir(dir)
	return dir
}

// hookFile is the path of a hook in the repository at dir. The tests read it
// through this path rather than comparing what the command printed, because a
// temporary directory can be reached by two names (macOS answers /var and
// /private/var for the same directory) and git prints the resolved one.
func hookFile(dir, hook string) string {
	return filepath.Join(dir, ".git", "hooks", hook)
}

func readHook(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a path this test built.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestHookInstallWritesAnExecutableHook(t *testing.T) {
	dir := newHookRepo(t)

	code, stdout, stderr := run(t, "hook", "install")
	if code != ExitOK || stderr != "" {
		t.Fatalf("hook install: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "installed the trustdiff pre-commit hook") {
		t.Errorf("stdout = %q, want it to name what it installed", stdout)
	}

	path := hookFile(dir, "pre-commit")
	script := readHook(t, path)
	for _, want := range []string{"#!/bin/sh", hookMarker, "trustdiff diff --fail-on block", "TRUSTDIFF_SKIP"} {
		if !strings.Contains(script, want) {
			t.Errorf("hook script does not contain %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "\r\n") {
		t.Error("hook script has CRLF line endings; git runs it with sh")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no executable bit, and git for Windows does not need one.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o100 == 0 {
		t.Errorf("hook mode = %v, want the owner execute bit set", info.Mode().Perm())
	}
}

func TestHookInstallTwiceChangesNothing(t *testing.T) {
	dir := newHookRepo(t)
	if code, _, stderr := run(t, "hook", "install"); code != ExitOK {
		t.Fatalf("first install: exit %d, stderr %q", code, stderr)
	}
	path := hookFile(dir, "pre-commit")
	first := readHook(t, path)

	code, stdout, stderr := run(t, "hook", "install")
	if code != ExitOK || stderr != "" {
		t.Fatalf("second install: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "already installed") {
		t.Errorf("stdout = %q, want it to say the hook is already installed", stdout)
	}
	if got := readHook(t, path); got != first {
		t.Error("the second install rewrote the hook")
	}
}

func TestHookInstallRewritesItsOwnOlderHook(t *testing.T) {
	dir := newHookRepo(t)
	path := hookFile(dir, "pre-commit")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	old := "#!/bin/sh\n" + hookMarker + "\nexec trustdiff diff\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run(t, "hook", "install")
	if code != ExitOK || stderr != "" {
		t.Fatalf("hook install: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "updated the trustdiff pre-commit hook") {
		t.Errorf("stdout = %q, want it to report an update", stdout)
	}
	if !strings.Contains(readHook(t, path), "--fail-on block") {
		t.Error("the older hook was not rewritten")
	}
}

func TestHookInstallRefusesAForeignHookUnlessForced(t *testing.T) {
	dir := newHookRepo(t)
	path := hookFile(dir, "pre-commit")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	foreign := "#!/bin/sh\necho someone else wrote this\n"
	if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run(t, "hook", "install")
	if code != ExitUsage {
		t.Fatalf("hook install over a foreign hook: exit %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "--force") {
		t.Errorf("stderr = %q, want it to mention --force", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if got := readHook(t, path); got != foreign {
		t.Fatal("the foreign hook was changed without --force")
	}

	code, stdout, stderr = run(t, "hook", "install", "--force")
	if code != ExitOK || stderr != "" {
		t.Fatalf("hook install --force: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "replaced the pre-commit hook") {
		t.Errorf("stdout = %q, want it to report a replacement", stdout)
	}
	if !strings.Contains(readHook(t, path), hookMarker) {
		t.Error("--force did not write the trustdiff hook")
	}
}

func TestHookUninstallRemovesOnlyTheTrustdiffHook(t *testing.T) {
	dir := newHookRepo(t)
	path := hookFile(dir, "pre-commit")

	// Nothing installed yet.
	code, stdout, stderr := run(t, "hook", "uninstall")
	if code != ExitOK || stderr != "" {
		t.Fatalf("uninstall with nothing to remove: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "no pre-commit hook to remove") {
		t.Errorf("stdout = %q, want it to say there was nothing to remove", stdout)
	}

	// A hook trustdiff did not write stays.
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	foreign := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(path, []byte(foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run(t, "hook", "uninstall")
	if code != ExitOK || stderr != "" {
		t.Fatalf("uninstall over a foreign hook: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "left") {
		t.Errorf("stdout = %q, want it to say the file was left alone", stdout)
	}
	if got := readHook(t, path); got != foreign {
		t.Fatal("a hook trustdiff did not write was changed")
	}

	// The trustdiff hook goes.
	if code, _, stderr := run(t, "hook", "install", "--force"); code != ExitOK {
		t.Fatalf("install --force: exit %d, stderr %q", code, stderr)
	}
	code, stdout, stderr = run(t, "hook", "uninstall")
	if code != ExitOK || stderr != "" {
		t.Fatalf("uninstall: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "removed the trustdiff pre-commit hook") {
		t.Errorf("stdout = %q, want it to report the removal", stdout)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the hook file is still there: %v", err)
	}
}

func TestHookPrePushIsSeparateFromPreCommit(t *testing.T) {
	dir := newHookRepo(t)

	code, stdout, stderr := run(t, "hook", "install", "--pre-push")
	if code != ExitOK || stderr != "" {
		t.Fatalf("hook install --pre-push: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "installed the trustdiff pre-push hook") {
		t.Errorf("stdout = %q, want it to name the pre-push hook", stdout)
	}
	if _, err := os.Stat(hookFile(dir, "pre-commit")); !os.IsNotExist(err) {
		t.Errorf("--pre-push also wrote the pre-commit hook: %v", err)
	}
	if !strings.Contains(readHook(t, hookFile(dir, "pre-push")), "skipping the pre-push hook") {
		t.Error("the pre-push hook does not name itself")
	}

	// Removing the pre-commit hook leaves the pre-push hook alone.
	if code, _, _ := run(t, "hook", "uninstall"); code != ExitOK {
		t.Fatalf("uninstall: exit %d", code)
	}
	if _, err := os.Stat(hookFile(dir, "pre-push")); err != nil {
		t.Errorf("uninstall without --pre-push removed the pre-push hook: %v", err)
	}
	if code, _, _ := run(t, "hook", "uninstall", "--pre-push"); code != ExitOK {
		t.Fatalf("uninstall --pre-push: exit %d", code)
	}
	if _, err := os.Stat(hookFile(dir, "pre-push")); !os.IsNotExist(err) {
		t.Errorf("the pre-push hook is still there: %v", err)
	}
}

func TestHookJSONOutput(t *testing.T) {
	newHookRepo(t)
	code, stdout, stderr := run(t, "--format", "json", "hook", "install")
	if code != ExitOK || stderr != "" {
		t.Fatalf("hook install: exit %d, stderr %q", code, stderr)
	}
	var got hookResult
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout)
	}
	if got.Hook != preCommitHook || got.Action != "installed" || got.Path == "" {
		t.Errorf("hook install --format json = %+v", got)
	}
}

func TestHookOutsideARepositoryIsAUsageError(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "absent-global-gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", filepath.Join(dir, "absent-system-gitconfig"))
	t.Chdir(dir)

	code, _, stderr := run(t, "hook", "install")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "not a git repository") {
		t.Errorf("stderr = %q, want it to say there is no repository", stderr)
	}
}

// The two tests below run the installed file the way git does. They need a
// shell, which every platform trustdiff supports has, but a machine without one
// skips them rather than pretending the script was checked.
func lookBash(t *testing.T) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not on PATH")
	}
	return bash
}

// runHookScript runs the hook file with bash, with PATH set to pathDir alone, so
// the test decides whether the script finds a trustdiff.
func runHookScript(t *testing.T, bash, hook, workDir, pathDir string) (string, int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bash, hook)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), "PATH="+pathDir)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %s: %v\n%s", hook, err, out)
		}
		code = exitErr.ExitCode()
	}
	return string(out), code
}

func TestInstalledHookRunsTrustdiffDiff(t *testing.T) {
	bash := lookBash(t)
	dir := newHookRepo(t)
	if code, _, stderr := run(t, "hook", "install"); code != ExitOK {
		t.Fatalf("hook install: exit %d, stderr %q", code, stderr)
	}

	// A trustdiff on PATH that records how the hook called it. It is a shell
	// script using nothing but builtins, so the test never leaves the shell.
	binDir := t.TempDir()
	recorded := filepath.ToSlash(filepath.Join(binDir, "args"))
	fake := "#!/bin/sh\necho \"$@\" > '" + recorded + "'\n"
	if err := os.WriteFile(filepath.Join(binDir, "trustdiff"), []byte(fake), hookFileMode); err != nil {
		t.Fatal(err)
	}

	out, code := runHookScript(t, bash, hookFile(dir, "pre-commit"), dir, binDir)
	if code != 0 {
		t.Fatalf("the hook exited %d\n%s", code, out)
	}
	args, err := os.ReadFile(filepath.FromSlash(recorded)) // #nosec G304 -- a path this test built.
	if err != nil {
		t.Fatalf("the hook did not run the trustdiff on PATH: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(args)); got != "diff --fail-on block" {
		t.Errorf("the hook ran trustdiff %q, want %q", got, "diff --fail-on block")
	}
}

func TestInstalledHookPassesWhenTrustdiffIsMissing(t *testing.T) {
	bash := lookBash(t)
	dir := newHookRepo(t)
	if code, _, stderr := run(t, "hook", "install"); code != ExitOK {
		t.Fatalf("hook install: exit %d, stderr %q", code, stderr)
	}

	out, code := runHookScript(t, bash, hookFile(dir, "pre-commit"), dir, t.TempDir())
	if code != 0 {
		t.Fatalf("the hook exited %d, want 0: a missing binary must not block a commit\n%s", code, out)
	}
	if !strings.Contains(out, "not on PATH") {
		t.Errorf("output = %q, want it to say trustdiff is not on PATH", out)
	}
}
