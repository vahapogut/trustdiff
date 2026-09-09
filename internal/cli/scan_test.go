package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// cargoLock is a second format, so a scan proves it reads whatever a parser is
// registered for rather than only the one format a test happens to write. The
// fake loader does not serve crates.io, so its entry is reported as skipped.
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

	// The same version locked twice in one file is one subject, on the earliest
	// line, and it counts as direct because one of the two copies is.
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
		{name: "update-baseline", args: []string{"scan", "--update-baseline"}, want: "later release"},
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
