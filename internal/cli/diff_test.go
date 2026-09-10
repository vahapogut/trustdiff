package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/report"
)

// The lockfiles the diff tests commit and change. They lock the package the fake
// loader serves, so a version bump produces the findings check_test.go documents:
// 2.0.0 is one day old and published by an account that did not publish 1.0.0.
const (
	baseLock = `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture",
      "dependencies": {
        "trustdiff-fixture-lib": "^1.0.0"
      }
    },
    "node_modules/trustdiff-fixture-gone": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-gone/-/trustdiff-fixture-gone-1.0.0.tgz",
      "integrity": "sha512-Zm9ydGhlYmFzZQ=="
    },
    "node_modules/trustdiff-fixture-lib": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-lib/-/trustdiff-fixture-lib-1.0.0.tgz",
      "integrity": "sha512-Zm9ydGhlbGli"
    }
  }
}
`
	// headLock bumps the locked version, drops one package and adds another, which
	// is every kind of change one lockfile can carry.
	headLock = `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture",
      "dependencies": {
        "trustdiff-fixture-lib": "^2.0.0"
      }
    },
    "node_modules/trustdiff-fixture-added": {
      "version": "1.2.3",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-added/-/trustdiff-fixture-added-1.2.3.tgz",
      "integrity": "sha512-YWRkZWQ="
    },
    "node_modules/trustdiff-fixture-lib": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-lib/-/trustdiff-fixture-lib-2.0.0.tgz",
      "integrity": "sha512-Zm9ydGhlbGli"
    }
  }
}
`
)

// secretName is the marker a file outside the tree carries, and secretLock is
// that file: a lockfile that parses, so following a link to it would put its
// entry names into the report, into the SARIF uploaded to code scanning and into
// the registry lookups. No test may find the marker in any output.
const (
	secretName = "trustdiff-fixture-private-token-abcdef"
	secretLock = `{
  "name": "outside",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "outside"},
    "node_modules/` + secretName + `": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
      "integrity": "sha512-A"
    }
  }
}
`
)

// gitRepo is a repository built for one test under t.TempDir().
type gitRepo struct {
	t   *testing.T
	git string
	dir string
}

// newGitRepo makes an empty repository, isolated from the machine's git
// configuration: a global or system core.autocrlf would otherwise rewrite what
// the tests commit, and Git for Windows ships one. The two configuration files
// are named inside the temporary directory and never created, which git reads as
// empty. The command under test inherits the test process environment, so this
// isolates it too. The test is skipped when git is not installed.
func newGitRepo(t *testing.T) *gitRepo {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not on PATH")
	}
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "absent-global-gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", filepath.Join(dir, "absent-system-gitconfig"))
	r := &gitRepo{t: t, git: git, dir: dir}
	r.run("init", "--quiet")
	return r
}

// run executes one git command in the repository and fails the test if it does
// not succeed.
func (r *gitRepo) run(args ...string) string {
	r.t.Helper()
	cmd := exec.CommandContext(r.t.Context(), r.git, args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=trustdiff tests",
		"GIT_AUTHOR_EMAIL=tests@trustdiff.invalid",
		"GIT_COMMITTER_NAME=trustdiff tests",
		"GIT_COMMITTER_EMAIL=tests@trustdiff.invalid",
		"GIT_AUTHOR_DATE=2026-01-02T03:04:05+00:00",
		"GIT_COMMITTER_DATE=2026-01-02T03:04:05+00:00",
		"LC_ALL=C",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// write puts content at a repository-relative path, creating directories.
func (r *gitRepo) write(rel, content string) {
	r.t.Helper()
	path := filepath.Join(r.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		r.t.Fatalf("create the directory of %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		r.t.Fatalf("write %s: %v", rel, err)
	}
}

// commit stages everything and commits it, returning the new object name.
func (r *gitRepo) commit(message string) string {
	r.t.Helper()
	r.run("add", "--all")
	r.run("commit", "--quiet", "--message", message)
	return r.run("rev-parse", "HEAD")
}

// diffFixture sets a diff test up: the fake loader, the pinned clock, an
// isolated policy lookup and a repository as the working directory.
func diffFixture(t *testing.T) *gitRepo {
	t.Helper()
	useFakeLoader(t)
	r := newGitRepo(t)
	chdir(t, r.dir)
	return r
}

// lineOf returns the 1-based line of the first line whose trimmed text is
// exactly the key npm writes, so an expected location is read out of the file
// rather than copied from the parser.
func lineOf(t *testing.T, body, key string) int {
	t.Helper()
	want := `"` + key + `": {`
	for i, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == want {
			return i + 1
		}
	}
	t.Fatalf("key %q is not in the lockfile", key)
	return 0
}

// subjectFor returns the report subject for a ref, and fails when the run did
// not evaluate it.
func subjectFor(t *testing.T, rep *report.Report, ref string) report.Subject {
	t.Helper()
	for i := range rep.Subjects {
		if rep.Subjects[i].Ref.String() == ref {
			return rep.Subjects[i]
		}
	}
	t.Fatalf("%s is not among the subjects %s", ref, strings.Join(refsOf(rep), ", "))
	return report.Subject{}
}

func refsOf(rep *report.Report) []string {
	refs := make([]string, 0, len(rep.Subjects))
	for i := range rep.Subjects {
		refs = append(refs, rep.Subjects[i].Ref.String())
	}
	return refs
}

// A change that bumps one version, adds one package and drops another evaluates
// exactly the two the head file locks, on their own lines, and says what is gone
// without fetching it.
func TestDiffEvaluatesAddedAndChangedEntries(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", baseLock)
	base := r.commit("lock the fixture")
	r.write("package-lock.json", headLock)

	code, stdout, stderr := run(t, "--format", "json", "diff", "--base", base)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 2 {
		t.Fatalf("subjects = %v, want the added and the changed entry", refsOf(&rep))
	}

	changed := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@2.0.0")
	if changed.Location == nil || changed.Location.Path != "package-lock.json" {
		t.Fatalf("location = %+v, want package-lock.json", changed.Location)
	}
	if want := lineOf(t, headLock, "node_modules/trustdiff-fixture-lib"); changed.Location.Line != want {
		t.Errorf("location line = %d, want %d", changed.Location.Line, want)
	}
	if !changed.Direct {
		t.Error("trustdiff-fixture-lib is a dependency of the project and should be reported as direct")
	}

	added := subjectFor(t, &rep, "npm:trustdiff-fixture-added@1.2.3")
	if added.Location == nil || added.Location.Line != lineOf(t, headLock, "node_modules/trustdiff-fixture-added") {
		t.Errorf("location of the added entry = %+v", added.Location)
	}

	// Every finding carries the same location, which is what SARIF annotates.
	for i := range changed.Findings {
		f := &changed.Findings[i]
		if f.Location == nil || f.Location.Line != changed.Location.Line {
			t.Errorf("finding %s has location %+v, want the subject's line %d", f.ID, f.Location, changed.Location.Line)
		}
	}

	// The removed entry is named and never fetched: it is not a subject.
	code, stdout, _ = run(t, "diff", "--base", base)
	if code != ExitFindings {
		t.Fatalf("human exit = %d, want 1", code)
	}
	for _, want := range []string{
		"compared package-lock.json with " + base[:shortSHA],
		"removed 1 entry from package-lock.json (npm:trustdiff-fixture-gone@1.0.0)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "npm:trustdiff-fixture-gone@1.0.0  ") {
		t.Errorf("the removed entry was evaluated:\n%s", stdout)
	}
}

// A change that deletes a lockfile removes every entry it held, and a project
// leaving npm for pnpm deletes two thousand of them. The report the gate exists
// to show must not be buried under one line per entry.
func TestDiffSummarizesManyRemovals(t *testing.T) {
	r := diffFixture(t)
	const removals = 60
	var b strings.Builder
	b.WriteString("{\n  \"name\": \"fixture\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"\": {\"name\": \"fixture\"}")
	for i := range removals {
		fmt.Fprintf(&b, ",\n    %q: {\"version\": \"1.0.%d\", \"resolved\": \"https://registry.npmjs.org/p/-/p-1.0.%d.tgz\", \"integrity\": \"sha512-A\"}",
			fmt.Sprintf("node_modules/trustdiff-fixture-p%d", i), i, i)
	}
	b.WriteString("\n  }\n}\n")
	r.write("package-lock.json", b.String())
	base := r.commit("lock the fixture")
	if err := os.Remove(filepath.Join(r.dir, "package-lock.json")); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := run(t, "diff", "--base", base)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	want := fmt.Sprintf("removed %d entries from package-lock.json (npm:trustdiff-fixture-p0@1.0.0; npm:trustdiff-fixture-p1@1.0.1; npm:trustdiff-fixture-p2@1.0.2, and %d more)",
		removals, removals-maxDroppedListed)
	if !strings.Contains(stdout, want) {
		t.Errorf("stdout lacks %q:\n%s", want, stdout)
	}
	if n := strings.Count(stdout, "removed "); n != 1 {
		t.Errorf("the removals take %d lines, want one summary line:\n%s", n, stdout)
	}
}

// An entry that keeps its version while its resolved location moves to another
// git repository is a change of what gets installed, and the gate exists to catch
// exactly that.
func TestDiffReportsARepointedGitSource(t *testing.T) {
	r := diffFixture(t)
	lock := func(owner, rev string) string {
		return fmt.Sprintf(`{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture",
      "dependencies": {
        "trustdiff-fixture-lib": "github:%s/lib"
      }
    },
    "node_modules/trustdiff-fixture-lib": {
      "version": "1.0.0",
      "resolved": "git+ssh://git@github.com/%s/lib.git#%s"
    }
  }
}
`, owner, owner, strings.Repeat(rev, 40))
	}
	r.write("package-lock.json", lock("good", "a"))
	base := r.commit("lock the fixture")
	r.write("package-lock.json", lock("attacker", "b"))

	code, stdout, stderr := run(t, "--format", "json", "diff", "--base", base)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	s := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@1.0.0")
	if len(s.Findings) == 0 {
		t.Errorf("the repointed entry was evaluated without a finding: %+v", s)
	}
}

// A base named on the command line is the fork point, the way git diff base...HEAD
// reads it. action.yml passes the tip of the base branch, which keeps moving while
// a pull request is open; what was merged into it meanwhile is not this change.
func TestDiffNamedBaseIsTheForkPoint(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", baseLock)
	fork := r.commit("lock the fixture")
	// Somebody else bumps the same dependency on the base branch.
	r.write("package-lock.json", headLock)
	mainTip := r.commit("bump the dependency on main")
	// The pull request forks before that and touches no lockfile at all.
	r.run("checkout", "--quiet", "-b", "pr", fork)
	r.write("README.md", "fixture\n")
	r.commit("document the fixture")

	code, stdout, stderr := run(t, "diff", "--base", mainTip)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	want := fmt.Sprintf("no lockfile changed since %s (fork point %s)", mainTip[:shortSHA], fork[:shortSHA])
	if !strings.Contains(stdout, want) {
		t.Errorf("stdout lacks %q:\n%s", want, stdout)
	}
}

// With no --base the fork point is looked for, and in a clone without a remote
// that is the commit before this one.
func TestDiffDefaultBaseIsTheForkPoint(t *testing.T) {
	r := diffFixture(t)
	r.write("README.md", "fixture\n")
	r.commit("first")
	r.write("package-lock.json", baseLock)
	r.commit("lock the fixture")
	r.write("package-lock.json", headLock)

	code, stdout, stderr := run(t, "--format", "json", "diff")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 2 {
		t.Fatalf("subjects = %v, want the two entries the change touched", refsOf(&rep))
	}
}

// A lockfile the change adds has no base side, so every entry it locks is new.
func TestDiffLockfileAddedByTheChange(t *testing.T) {
	r := diffFixture(t)
	r.write("README.md", "fixture\n")
	base := r.commit("first")
	r.write("package-lock.json", headLock)
	// Staged and not committed is what a lockfile looks like mid-change; git sees
	// it, and an untracked file it would not.
	r.run("add", "package-lock.json")

	code, stdout, stderr := run(t, "--format", "json", "diff", "--base", base)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 2 {
		t.Fatalf("subjects = %v, want every entry of the new lockfile", refsOf(&rep))
	}
	subjectFor(t, &rep, "npm:trustdiff-fixture-lib@2.0.0")
	subjectFor(t, &rep, "npm:trustdiff-fixture-added@1.2.3")
}

// A lockfile the change rewrote without moving a version has nothing to
// evaluate. The run says which file it compared and that nothing changed, and
// exits 0.
func TestDiffNothingChanged(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", baseLock)
	base := r.commit("lock the fixture")
	// The project's own name is not an entry, so the file differs while the
	// locked versions do not.
	r.write("package-lock.json", strings.ReplaceAll(baseLock, `"name": "fixture"`, `"name": "fixture-renamed"`))

	code, stdout, stderr := run(t, "diff", "--base", base)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	want := "nothing changed in package-lock.json compared with " + base[:shortSHA]
	if !strings.Contains(stdout, want) {
		t.Errorf("stdout lacks %q:\n%s", want, stdout)
	}

	code, stdout, _ = run(t, "--format", "json", "diff", "--base", base)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0\n%s", code, stdout)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 0 || rep.Summary.Subjects != 0 {
		t.Fatalf("subjects = %v, want none", refsOf(&rep))
	}
}

// A change that touches no lockfile is the ordinary pull request, and it must
// not fail the job.
func TestDiffWithoutLockfileChanges(t *testing.T) {
	r := diffFixture(t)
	r.write("README.md", "fixture\n")
	base := r.commit("first")
	r.write("README.md", "fixture, revised\n")

	code, stdout, stderr := run(t, "diff", "--base", base)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	if want := "no lockfile changed since " + base[:shortSHA]; !strings.Contains(stdout, want) {
		t.Errorf("stdout lacks %q:\n%s", want, stdout)
	}
}

// --base-file compares the working tree against a file instead of a commit.
func TestDiffBaseFile(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", headLock)
	r.commit("lock the fixture")

	// The base file lives outside the repository, the way a CI job saves the
	// lockfile of the target branch before checking the pull request out.
	baseDir := t.TempDir()
	basePath := filepath.Join(baseDir, "package-lock.json")
	if err := os.WriteFile(basePath, []byte(baseLock), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
	}{
		{name: "head found by name", args: []string{"--format", "json", "diff", "--base-file", basePath}},
		{name: "head named as an argument", args: []string{"--format", "json", "diff", "--base-file", basePath, "package-lock.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tt.args...)
			if code != ExitFindings {
				t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
			}
			rep := decodeReport(t, stdout)
			if len(rep.Subjects) != 2 {
				t.Fatalf("subjects = %v, want the added and the changed entry", refsOf(&rep))
			}
			changed := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@2.0.0")
			if changed.Location == nil || changed.Location.Path != "package-lock.json" {
				t.Fatalf("location = %+v, want the head lockfile of the repository", changed.Location)
			}
		})
	}

	// The human output names the file it compared against.
	_, stdout, _ := run(t, "diff", "--base-file", basePath)
	if !strings.Contains(stdout, "compared package-lock.json with "+filepath.ToSlash(basePath)) {
		t.Errorf("stdout does not name the base file:\n%s", stdout)
	}
}

// Two files named on the command line are compared wherever they are. A release
// archive is tried out in a download directory, and a build compares two files it
// fetched, so a repository is not something either can be asked for.
func TestDiffBaseFileNeedsNoRepository(t *testing.T) {
	useFakeLoader(t)
	dir := t.TempDir()
	// Keep git from finding a repository above the temporary directory, so the
	// test fails the way it would in a download directory rather than picking up
	// whatever repository the tests run inside.
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	writeFile(t, dir, "base/package-lock.json", baseLock)
	writeFile(t, dir, "head/package-lock.json", headLock)
	chdir(t, dir)

	code, stdout, stderr := run(t, "--format", "json", "diff",
		"--base-file", "base/package-lock.json", "head/package-lock.json")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 2 {
		t.Fatalf("subjects = %v, want the added and the changed entry", refsOf(&rep))
	}
	changed := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@2.0.0")
	if changed.Location == nil || changed.Location.Path != "head/package-lock.json" {
		t.Fatalf("location = %+v, want the head file as it was named", changed.Location)
	}
}

// The lockfile entry reaches the checks that judge it: an entry resolved from a
// git remote without a hash is what TD013 and TD014 exist to report, on the line
// the entry sits on.
func TestDiffReportsLockfileEntryChecks(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", baseLock)
	base := r.commit("lock the fixture")
	const exotic = `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture",
      "dependencies": {
        "trustdiff-fixture-lib": "^2.0.0"
      }
    },
    "node_modules/trustdiff-fixture-gone": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-gone/-/trustdiff-fixture-gone-1.0.0.tgz",
      "integrity": "sha512-Zm9ydGhlYmFzZQ=="
    },
    "node_modules/trustdiff-fixture-lib": {
      "version": "2.0.0",
      "resolved": "git+https://github.com/example/trustdiff-fixture-lib.git#f00ba7"
    }
  }
}
`
	r.write("package-lock.json", exotic)

	code, stdout, stderr := run(t, "--format", "json", "diff", "--base", base)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	s := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@2.0.0")
	found := map[string]bool{}
	for i := range s.Findings {
		found[s.Findings[i].ID] = true
		if s.Findings[i].Location == nil {
			t.Errorf("finding %s carries no location", s.Findings[i].ID)
		}
	}
	for _, id := range []string{"TD013", "TD014"} {
		if !found[id] {
			t.Errorf("%s did not report the lockfile entry; findings %v, skipped %v", id, found, s.Skipped)
		}
	}
	if line := lineOf(t, exotic, "node_modules/trustdiff-fixture-lib"); s.Location.Line != line {
		t.Errorf("location line = %d, want %d", s.Location.Line, line)
	}
}

// A partial parse is visible: the entries a parser could not read are one line of
// the human output, per lockfile.
func TestDiffReportsDroppedEntries(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", baseLock)
	base := r.commit("lock the fixture")
	const withLink = `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture",
      "dependencies": {
        "trustdiff-fixture-lib": "^1.0.0"
      }
    },
    "node_modules/trustdiff-fixture-lib": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-lib/-/trustdiff-fixture-lib-1.0.0.tgz",
      "integrity": "sha512-Zm9ydGhlbGli"
    },
    "node_modules/fixture-ui": {
      "resolved": "packages/ui",
      "link": true
    }
  }
}
`
	r.write("package-lock.json", withLink)

	code, stdout, stderr := run(t, "diff", "--base", base)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "package-lock.json: 1 entry was not read") {
		t.Errorf("stdout does not report the dropped entry:\n%s", stdout)
	}
	if !strings.Contains(stdout, "node_modules/fixture-ui") {
		t.Errorf("the dropped entry is not named:\n%s", stdout)
	}
}

// A lockfile in a pull request is text its author chose, and git records a
// symbolic link as a blob holding the link text. Reading through it would put a
// file from outside the repository into the report, into the SARIF and into the
// registry lookups.
func TestDiffRefusesASymlinkedLockfile(t *testing.T) {
	r := diffFixture(t)
	r.write("README.md", "fixture\n")
	base := r.commit("first")

	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(secretLock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(r.dir, "package-lock.json")); err != nil {
		t.Skipf("this machine does not let the test process create a symbolic link: %v", err)
	}
	r.run("add", "--all")

	code, stdout, stderr := run(t, "diff", "--base", base)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "package-lock.json: not read (a symbolic link") {
		t.Errorf("stdout does not refuse the link:\n%s", stdout)
	}
	if strings.Contains(stdout+stderr, secretName) {
		t.Errorf("the file the link points at was read:\n%s%s", stdout, stderr)
	}
}

// One lockfile no parser gets through must not cost the findings of the others.
// Aborting the run would also make a package-lock.json migrating from npm 6 to
// npm 7 a hard failure, which is an ordinary pull request.
func TestDiffKeepsTheFindingsOfTheLockfilesItCanRead(t *testing.T) {
	r := diffFixture(t)
	r.write("README.md", "fixture\n")
	base := r.commit("first")
	r.write("web/package-lock.json", headLock)
	r.write("api/package-lock.json", "{ this is not JSON\n")
	r.run("add", "--all")

	code, stdout, stderr := run(t, "diff", "--base", base)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "api/package-lock.json: not read (") {
		t.Errorf("stdout does not say the unreadable lockfile was skipped:\n%s", stdout)
	}
	if !strings.Contains(stdout, "npm:trustdiff-fixture-lib@2.0.0") {
		t.Errorf("the readable lockfile lost its findings:\n%s", stdout)
	}
}

// A base side no parser gets through is what a lockfile changing format version
// looks like, npm 6 to npm 7 or pnpm 5 to pnpm 9. The head file is perfectly
// readable and every entry it locks deserves evaluating.
func TestDiffEvaluatesTheHeadWhenTheBaseWillNotParse(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", `{
  "name": "fixture",
  "lockfileVersion": 1,
  "dependencies": {
    "trustdiff-fixture-lib": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-lib/-/trustdiff-fixture-lib-1.0.0.tgz",
      "integrity": "sha512-Zm9ydGhlbGli"
    }
  }
}
`)
	base := r.commit("lock the fixture with npm 6")
	r.write("package-lock.json", headLock)

	code, stdout, stderr := run(t, "diff", "--base", base)
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "package-lock.json at "+base[:shortSHA]+": not read (") {
		t.Errorf("stdout does not say the base side was not read:\n%s", stdout)
	}
	if !strings.Contains(stdout, "every entry of the file reads as added") {
		t.Errorf("stdout does not say what that means for the comparison:\n%s", stdout)
	}
	if !strings.Contains(stdout, "npm:trustdiff-fixture-lib@2.0.0") {
		t.Errorf("the head entries were not evaluated:\n%s", stdout)
	}
}

// A lockfile that was written and never added is invisible to git. Reporting it
// as unchanged is the one answer it must not get.
func TestDiffNamesAnUntrackedLockfile(t *testing.T) {
	r := diffFixture(t)
	r.write("README.md", "fixture\n")
	base := r.commit("first")
	r.write("package-lock.json", headLock)

	code, stdout, stderr := run(t, "diff", "--base", base)
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	want := "package-lock.json is not tracked by git, so it was not compared; git add it to have it evaluated"
	if !strings.Contains(stdout, want) {
		t.Errorf("stdout lacks %q:\n%s", want, stdout)
	}
}

func TestDiffUsageErrors(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", baseLock)
	base := r.commit("lock the fixture")
	outside := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(outside, []byte(baseLock), 0o600); err != nil {
		t.Fatal(err)
	}
	notALockfile := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(notALockfile, []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A lockfile of a format the repository holds no file of, so the head side
	// cannot be found.
	otherFormat := filepath.Join(t.TempDir(), "Cargo.lock")
	if err := os.WriteFile(otherFormat, []byte(cargoLock), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "both bases", args: []string{"diff", "--base", base, "--base-file", outside}, want: "cannot be combined"},
		{name: "unresolvable base", args: []string{"diff", "--base", "no-such-ref"}, want: "resolve base"},
		{name: "path without a base file", args: []string{"diff", "package-lock.json"}, want: "only with --base-file"},
		{name: "base file no parser reads", args: []string{"diff", "--base-file", notALockfile}, want: "no parser for this lockfile"},
		{name: "base file the repository has no head for", args: []string{"diff", "--base-file", otherFormat}, want: "no lockfile found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tt.args...)
			if code != ExitUsage || !strings.Contains(stderr, tt.want) {
				t.Fatalf("exit = %d, stderr = %q, want a usage error containing %q", code, stderr, tt.want)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty: stdout is reserved for reports", stdout)
			}
		})
	}
}

// Outside a repository there is nothing to compare against, and the message says
// so rather than reporting an empty diff.
func TestDiffOutsideARepository(t *testing.T) {
	useFakeLoader(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	dir := t.TempDir()
	// Keep git from finding a repository above the temporary directory.
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	chdir(t, dir)

	code, stdout, stderr := run(t, "diff", "--base", "HEAD")
	if code != ExitUsage || !strings.Contains(stderr, "not a git repository") {
		t.Fatalf("exit = %d, stderr = %q\n%s", code, stderr, stdout)
	}
}

// TestDiffReportsASameVersionIntegritySwap pins finding F2 of
// docs/review-2026-09-10.md. A published release is immutable, so one version under
// two hashes means the lockfile was written against bytes that were not the release.
// gitdiff classified the entry as changed all along; nothing downstream ever saw the
// base entry, so every check passed and the run exited 0.
func TestDiffReportsASameVersionIntegritySwap(t *testing.T) {
	base := readRegressionFixture(t, "f2-lockfile-entry-changed", "base", "package-lock.json")
	head := readRegressionFixture(t, "f2-lockfile-entry-changed", "head", "package-lock.json")
	useFakeLoader(t)
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	writeFile(t, dir, "base/package-lock.json", base)
	writeFile(t, dir, "head/package-lock.json", head)
	chdir(t, dir)

	code, stdout, stderr := run(t, "--format", "json", "diff",
		"--base-file", "base/package-lock.json", "head/package-lock.json")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitFindings, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	s := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@1.0.0")

	var found *model.Finding
	for i := range s.Findings {
		if s.Findings[i].ID == "TD016" {
			found = &s.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("no TD016 finding; the report carried %d findings for the changed entry", len(s.Findings))
	}
	if found.Level != model.LevelBlock {
		t.Errorf("level = %s, want block", found.Level)
	}
	if found.Name != "lockfile-entry-changed" {
		t.Errorf("name = %q, want lockfile-entry-changed", found.Name)
	}
	if got := found.Evidence["signal"]; got != "integrity-changed" {
		t.Errorf("signal = %v, want integrity-changed", got)
	}
	if got := found.Evidence["base_integrity"]; got != "sha512-Zm9ydGhlbGli" {
		t.Errorf("base_integrity = %v, want the hash the base file recorded", got)
	}
	if got := found.Evidence["integrity"]; got != "sha512-YXR0YWNrZXJ0YXJiYWxs" {
		t.Errorf("integrity = %v, want the hash the head file records", got)
	}
}

// TestDiffReportsARepointedNestedCopy is the diff half of finding F3 of
// docs/review-2026-09-10.md. The change leaves the hoisted copy of the version
// alone and repoints the copy nested under another package at an archive of its
// own, with no hash. Before the fix both copies of both files collapsed into the
// first of them, the two files then held the same one entry, and the run said
// nothing had changed. The base file holds one entry for the version because its
// two copies did agree, so the repointed copy arrives as an install that is new.
func TestDiffReportsARepointedNestedCopy(t *testing.T) {
	base := readRegressionFixture(t, "f3-nested-duplicate-divergent-copy", "base", "package-lock.json")
	head := readRegressionFixture(t, "f3-nested-duplicate-divergent-copy", "head", "package-lock.json")
	useFakeLoader(t)
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	writeFile(t, dir, "base/package-lock.json", base)
	writeFile(t, dir, "head/package-lock.json", head)
	chdir(t, dir)

	code, stdout, stderr := run(t, "--format", "json", "diff",
		"--base-file", "base/package-lock.json", "head/package-lock.json")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitFindings, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 1 {
		t.Fatalf("subjects = %v, want the repointed copy alone: nothing else in the file moved", refsOf(&rep))
	}
	s := rep.Subjects[0]
	if s.Ref.String() != "npm:trustdiff-fixture-lib@1.0.0" {
		t.Fatalf("subject = %s, want the nested copy of the library", s.Ref)
	}
	want := lineOf(t, head, "node_modules/trustdiff-fixture-wrapper/node_modules/trustdiff-fixture-lib")
	if s.Location == nil || s.Location.Line != want {
		t.Fatalf("location = %+v, want the nested line %d", s.Location, want)
	}
	found := map[string]model.Level{}
	for i := range s.Findings {
		found[s.Findings[i].ID] = s.Findings[i].Level
	}
	if found["TD013"] != model.LevelBlock {
		t.Errorf("TD013 = %s, want block (findings %v, skipped %v)", found["TD013"], found, s.Skipped)
	}
	if found["TD014"] != model.LevelWarn {
		t.Errorf("TD014 = %s, want warn (findings %v, skipped %v)", found["TD014"], found, s.Skipped)
	}
}
