package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// cargoLock is a second format, so a scan proves it reads whatever a parser is
// registered for rather than only the one format a test happens to write. The fake
// loader does not serve crates.io, so every check that reads a data source is
// skipped for it; the two that read the entry alone still judge it, and find nothing
// to report in a registry install that carries a checksum.
const cargoLock = `version = 3

[[package]]
name = "trustdiff-fixture-crate"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"
`

// nestedLock locks the same version twice, the way npm records a package
// installed both at the top level and under another dependency.
const nestedLock = `{
  "name": "web",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "web",
      "dependencies": {
        "trustdiff-fixture-lib": "^2.0.0"
      }
    },
    "node_modules/trustdiff-fixture-lib": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-lib/-/trustdiff-fixture-lib-2.0.0.tgz",
      "integrity": "sha512-Zm9ydGhlbGli"
    },
    "node_modules/trustdiff-fixture-added/node_modules/trustdiff-fixture-lib": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-lib/-/trustdiff-fixture-lib-2.0.0.tgz",
      "integrity": "sha512-Zm9ydGhlbGli"
    }
  }
}
`

// scanFixture sets a scan test up: the fake loader, the pinned clock, an isolated
// policy lookup and a tree as the working directory.
func scanFixture(t *testing.T) string {
	t.Helper()
	useFakeLoader(t)
	dir := t.TempDir()
	chdir(t, dir)
	return dir
}

// readRegressionFixture reads a file under testdata/regressions, which is where the
// scenario of each review finding is pinned so it cannot come back. Call it before a
// test changes directory: the path is relative to this package, and scanFixture moves
// the working directory away from it.
func readRegressionFixture(t *testing.T, elem ...string) string {
	t.Helper()
	parts := append([]string{"..", "..", "testdata", "regressions"}, elem...)
	// #nosec G304 -- a fixture of this repository.
	data, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// writeFile puts content at a path relative to dir, creating directories.
func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A scan reads every lockfile the walk finds, names how much work it is about to
// do, and points every subject at the file it came from.
func TestScanEvaluatesEveryLockfile(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)
	writeFile(t, dir, "web/package-lock.json", nestedLock)
	writeFile(t, dir, "rust/Cargo.lock", cargoLock)
	// None of these belongs to the project: they are installed, vendored or built.
	for _, rel := range []string{
		"node_modules/left-pad/package-lock.json",
		"vendor/other/package-lock.json",
		"rust/target/debug/Cargo.lock",
		"dist/package-lock.json",
		".venv/package-lock.json",
	} {
		writeFile(t, dir, rel, baseLock)
	}

	code, stdout, stderr := run(t, "--format", "json", "scan")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	rep := decodeReport(t, stdout)

	paths := make([]string, 0, len(rep.Subjects))
	for i := range rep.Subjects {
		if rep.Subjects[i].Location == nil {
			t.Fatalf("subject %s carries no location", rep.Subjects[i].Ref)
		}
		paths = append(paths, rep.Subjects[i].Location.Path)
	}
	slices.Sort(paths)
	want := []string{"package-lock.json", "package-lock.json", "rust/Cargo.lock", "web/package-lock.json"}
	if !slices.Equal(paths, want) {
		t.Fatalf("locations = %v, want %v", paths, want)
	}
	subjectFor(t, &rep, "cargo:trustdiff-fixture-crate@0.1.0")

	// The same version locked twice in one file is one subject as long as the two
	// copies agree about what they install, on the earliest line, and it counts as
	// direct because one of the two copies is.
	nested := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@2.0.0")
	if nested.Location.Path != "web/package-lock.json" {
		t.Fatalf("location = %s, want the nested lockfile", nested.Location.Path)
	}
	if line := lineOf(t, nestedLock, "node_modules/trustdiff-fixture-lib"); nested.Location.Line != line {
		t.Errorf("location line = %d, want the first of the two copies at %d", nested.Location.Line, line)
	}
	if !nested.Direct {
		t.Error("the top level copy is a dependency of the project, so the subject is direct")
	}

	// The human run says how much work it is about to do, before the cards.
	code, stdout, _ = run(t, "scan")
	if code != ExitFindings {
		t.Fatalf("human exit = %d, want 1", code)
	}
	want0 := "evaluating 4 entries of 3 lockfiles: package-lock.json, rust/Cargo.lock, web/package-lock.json"
	if !strings.HasPrefix(stdout, want0) {
		t.Errorf("stdout does not open with %q:\n%s", want0, stdout)
	}
}

// A scan of one file reads that file alone.
func TestScanOfASingleFile(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "web/package-lock.json", nestedLock)

	code, stdout, stderr := run(t, "--format", "json", "scan", filepath.Join("web", "package-lock.json"))
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 1 {
		t.Fatalf("subjects = %v, want the one entry of the file", refsOf(&rep))
	}
	if got := rep.Subjects[0].Location.Path; got != "package-lock.json" {
		t.Errorf("location path = %q, want the file the scan was pointed at", got)
	}
}

// The entries a parser could not read are one line per lockfile.
func TestScanReportsDroppedEntries(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "fixture"
    },
    "node_modules/trustdiff-fixture-lib": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-lib/-/trustdiff-fixture-lib-1.0.0.tgz",
      "integrity": "sha512-Zm9ydGhlbGli"
    },
    "node_modules/fixture-ui": {
      "resolved": "packages/ui",
      "link": true
    },
    "node_modules/fixture-no-version": {
      "resolved": "https://registry.npmjs.org/fixture-no-version/-/fixture-no-version-1.0.0.tgz"
    }
  }
}
`)

	code, stdout, stderr := run(t, "scan")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "package-lock.json: 2 entries were not read") {
		t.Errorf("stdout does not report the dropped entries:\n%s", stdout)
	}
	for _, want := range []string{"node_modules/fixture-ui", "node_modules/fixture-no-version"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout does not name %s:\n%s", want, stdout)
		}
	}
}

// The document formats keep stdout to the document, so the notes go to stderr.
// They are what says how much was evaluated and what was not, and the format the
// Action uses is one of these, so they may not depend on -v.
func TestScanNotesStayOutOfTheDocument(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)
	writeFile(t, dir, "broken/package-lock.json", "{ this is not JSON\n")

	code, stdout, stderr := run(t, "--format", "json", "scan")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)", code, stderr)
	}
	decodeReport(t, stdout) // the document alone, or this does not parse
	for _, want := range []string{
		"evaluating 2 entries of 1 lockfile: package-lock.json",
		"broken/package-lock.json: not read (",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q without -v:\n%s", want, stderr)
		}
	}
}

// One lockfile no parser gets through must not cost the findings of the others,
// and the count line says what was actually evaluated.
func TestScanKeepsTheFindingsOfTheLockfilesItCanRead(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "web/package-lock.json", nestedLock)
	writeFile(t, dir, "api/package-lock.json", "{ this is not JSON\n")

	code, stdout, stderr := run(t, "scan")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)\n%s", code, stderr, stdout)
	}
	for _, want := range []string{
		"evaluating 1 entry of 1 lockfile: web/package-lock.json",
		"api/package-lock.json: not read (",
		"npm:trustdiff-fixture-lib@2.0.0",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

// A lockfile that is a symbolic link is not read: following it would put a file
// from outside the tree being evaluated into the report and into the lookups.
func TestScanRefusesASymlinkedLockfile(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "ok/package-lock.json", baseLock)
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(secretLock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "package-lock.json")); err != nil {
		t.Skipf("this machine does not let the test process create a symbolic link: %v", err)
	}

	code, stdout, stderr := run(t, "scan")
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

// A subtree the walk is not allowed to read holds lockfiles nobody looked at, so
// the run says so instead of reporting a pass over what it could see.
func TestScanReportsDirectoriesItCannotRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a directory's readability is an ACL on Windows, which chmod does not set")
	}
	if os.Getuid() == 0 {
		t.Skip("root reads a directory whatever its mode says")
	}
	dir := scanFixture(t)
	writeFile(t, dir, "ok/package-lock.json", baseLock)
	writeFile(t, dir, "locked/inner/package-lock.json", nestedLock)
	locked := filepath.Join(dir, "locked")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	// Put the mode back, or the temporary directory cannot be removed.
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	code, stdout, stderr := run(t, "scan")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	want := "1 directory was not read (locked): the lockfiles inside were not evaluated"
	if !strings.Contains(stdout, want) {
		t.Errorf("stdout lacks %q without -v:\n%s", want, stdout)
	}
}

func TestScanUsageErrors(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "notes.txt", "nothing here\n")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "no lockfile under the path", args: []string{"scan"}, want: "no lockfile found under"},
		{name: "path that does not exist", args: []string{"scan", "no-such-directory"}, want: "no-such-directory"},
		{name: "file no parser reads", args: []string{"scan", "notes.txt"}, want: "no parser reads"},
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

// The message that says a path holds no lockfile names the formats trustdiff
// reads, so a reader learns what to look for.
func TestScanNamesTheFormatsItReads(t *testing.T) {
	scanFixture(t)
	_, _, stderr := run(t, "scan")
	for _, format := range []string{"Cargo.lock", "package-lock.json", "pnpm-lock.yaml", "uv.lock"} {
		if !strings.Contains(stderr, format) {
			t.Errorf("the message does not name %s:\n%s", format, stderr)
		}
	}
}

// TestScanJudgesTheLockfileEntryOfAnUnknownPackage pins finding F1 of
// docs/review-2026-09-10.md. A package the registry does not know must still be judged
// by the checks that read the lockfile entry and nothing else, because a pull request
// adding a git dependency, or any name that was never published, is the case those
// checks exist for. Before the fix the registry's "not found" skipped every check,
// including the two whose whole subject is the entry, and the run exited 0.
func TestScanJudgesTheLockfileEntryOfAnUnknownPackage(t *testing.T) {
	lock := readRegressionFixture(t, "f1-unknown-package-git-source", "package-lock.json")
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", lock)

	code, stdout, stderr := run(t, "--format", "json", "scan")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, ExitFindings, stderr)
	}
	rep := decodeReport(t, stdout)
	s := subjectFor(t, &rep, "npm:trustdiff-fixture-exotic@1.0.0")

	levels := map[string]string{}
	for _, f := range s.Findings {
		levels[f.ID] = f.Level.String()
	}
	if levels["TD013"] != "block" {
		t.Errorf("TD013 = %q, want block: a git dependency is what exotic-source exists to report", levels["TD013"])
	}
	if levels["TD014"] != "warn" {
		t.Errorf("TD014 = %q, want warn: the entry pins a branch rather than a commit, so nothing guards it", levels["TD014"])
	}
	// Every other check still reports the registry's answer, which is what it is.
	for _, sk := range s.Skipped {
		if sk.Check == "TD013" || sk.Check == "TD014" {
			t.Errorf("%s was skipped: %s", sk.Check, sk.Reason)
		}
	}
}

// TestScanKeepsACopyThatInstallsSomethingElse pins finding F3 of
// docs/review-2026-09-10.md. A lockfile names a version once per place it installs
// it, and those places are one subject only while they agree about what they
// install. Before the fix every repeat of a version collapsed into the first of
// them, so a copy nested under another package, repointed at an archive of its own
// and stripped of its hash, was folded into the clean copy above it and neither
// TD013 nor TD014 was ever shown the line that carried it.
func TestScanKeepsACopyThatInstallsSomethingElse(t *testing.T) {
	lock := readRegressionFixture(t, "f3-nested-duplicate-divergent-copy", "head", "package-lock.json")
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", lock)

	code, stdout, stderr := run(t, "--format", "json", "scan")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitFindings, stderr, stdout)
	}
	rep := decodeReport(t, stdout)

	const ref = "npm:trustdiff-fixture-lib@1.0.0"
	var copies []int
	for i := range rep.Subjects {
		if rep.Subjects[i].Ref.String() == ref {
			copies = append(copies, i)
		}
	}
	if len(copies) != 2 {
		t.Fatalf("%s has %d subjects, want the copy the file resolves from the registry and the one it does not (subjects %s)",
			ref, len(copies), strings.Join(refsOf(&rep), ", "))
	}
	clean, nested := rep.Subjects[copies[0]], rep.Subjects[copies[1]]

	// Each copy is reported on its own line, which is the line a reviewer has to read.
	if want := lineOf(t, lock, "node_modules/trustdiff-fixture-lib"); clean.Location == nil || clean.Location.Line != want {
		t.Errorf("the first copy is at %+v, want line %d", clean.Location, want)
	}
	if want := lineOf(t, lock, "node_modules/trustdiff-fixture-wrapper/node_modules/trustdiff-fixture-lib"); nested.Location == nil || nested.Location.Line != want {
		t.Errorf("the repointed copy is at %+v, want line %d", nested.Location, want)
	}
	for i := range clean.Findings {
		if id := clean.Findings[i].ID; id == "TD013" || id == "TD014" {
			t.Errorf("%s reported the copy the file resolves from the registry under its hash: %s", id, clean.Findings[i].Title)
		}
	}

	found := map[string]model.Level{}
	for i := range nested.Findings {
		found[nested.Findings[i].ID] = nested.Findings[i].Level
	}
	if found["TD013"] != model.LevelBlock {
		t.Errorf("TD013 = %s, want block: the copy resolves from a URL of its own, which is what exotic-source exists to report (findings %v, skipped %v)",
			found["TD013"], found, nested.Skipped)
	}
	if found["TD014"] != model.LevelWarn {
		t.Errorf("TD014 = %s, want warn: nothing guards whatever that URL serves (findings %v, skipped %v)",
			found["TD014"], found, nested.Skipped)
	}
}
