package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/checks"
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

// TestScanSkipsAChecksWholeAnswerWhenOneSourceWasDown pins finding F4 of
// docs/review-2026-09-10.md. A check that reads two sources and found nothing on
// the one that answered has not cleared the version; it has read half the
// evidence. Before the fix TD009, TD011 and TD012 returned an empty result there,
// so they landed in evaluated, the report carried no trace of the outage, and
// on_data_unavailable: fail exited 0 for a package nobody could ask OSV, deps.dev
// or the download counts about.
func TestScanSkipsAChecksWholeAnswerWhenOneSourceWasDown(t *testing.T) {
	lock := readRegressionFixture(t, "f4-one-source-down", "package-lock.json")
	tests := []struct {
		name string
		down []string
		// want maps a check to the outage its skip reason has to name.
		want map[string]string
	}{
		{
			name: "osv and the download counts are down",
			down: []string{checks.SourceOSV, checks.SourceDownloads},
			want: map[string]string{
				"TD009": "osv unavailable: connection refused",
				"TD010": "osv unavailable: connection refused",
				"TD012": "downloads unavailable: connection refused",
			},
		},
		{
			name: "deps.dev is down",
			down: []string{checks.SourceDepsDev},
			want: map[string]string{
				"TD009": "deps.dev unavailable: connection refused",
				"TD011": "deps.dev unavailable: connection refused",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := scanFixture(t)
			down := map[string]bool{}
			for _, source := range tt.down {
				down[source] = true
			}
			useDownLoader(t, down)
			writeFile(t, dir, "package-lock.json", lock)
			writePolicy(t, "version: 1\non_data_unavailable: fail\n")

			code, stdout, stderr := run(t, "--format", "json", "scan")
			if code != ExitUnavailable {
				t.Fatalf("exit = %d, want %d: a source nobody could ask is what on_data_unavailable: fail is for (stderr %q)\n%s",
					code, ExitUnavailable, stderr, stdout)
			}
			rep := decodeReport(t, stdout)
			s := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@1.0.0")
			if len(s.Findings) != 0 {
				t.Fatalf("findings = %v, want none: the fixture is a clean release", s.Findings)
			}
			reasons := map[string]string{}
			for _, sk := range s.Skipped {
				reasons[sk.Check] = sk.Reason
			}
			for id, want := range tt.want {
				if slices.Contains(s.Evaluated, id) {
					t.Errorf("%s is evaluated although %s: a pass on half the evidence is not a pass", id, want)
					continue
				}
				if !strings.Contains(reasons[id], want) {
					t.Errorf("%s skipped with %q, want the outage %q", id, reasons[id], want)
				}
			}
		})
	}
}

// TestScanReportsAnUnhashedRequirementsPin pins finding F5 of
// docs/review-2026-09-10.md. A requirements.txt that pins versions and hashes nothing
// is the file most Python projects have, and every line of it is a package an install
// fetches with nothing to check the bytes against. Before the fix the parser dropped
// every one of them, so the file produced no entry at all: it became a note beside
// the report, integrity-missing never fired for pip, and no check ever saw a pin a
// pull request had added.
func TestScanReportsAnUnhashedRequirementsPin(t *testing.T) {
	req := readRegressionFixture(t, "f5-requirements-without-hash", "requirements.txt")
	dir := scanFixture(t)
	writeFile(t, dir, "requirements.txt", req)

	code, stdout, stderr := run(t, "--format", "json", "--fail-on", "warn", "scan")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitFindings, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	s := subjectFor(t, &rep, "pypi:trustdiff-fixture-unhashed@1.0.0")
	if s.Location == nil || s.Location.Path != "requirements.txt" || s.Location.Line != 6 {
		t.Fatalf("location = %+v, want requirements.txt line 6", s.Location)
	}
	found := map[string]model.Level{}
	for i := range s.Findings {
		found[s.Findings[i].ID] = s.Findings[i].Level
	}
	if found["TD014"] != model.LevelWarn {
		t.Errorf("TD014 = %s, want warn: a pin with no hash is what integrity-missing reports (findings %v)", found["TD014"], found)
	}
	// The pin is a subject like any other, so the checks that read PyPI report what
	// PyPI said about it rather than never being asked.
	if len(s.Skipped) == 0 {
		t.Error("nothing was skipped, so no check was ever offered the pin")
	}
	// It is in the report rather than in a note beside it: nothing about this file
	// went unread, and a note saying so would not be true.
	if strings.Contains(stderr, "not read") {
		t.Errorf("the run says something was not read:\n%s", stderr)
	}
}

// TestScanSaysSoWhenOnlyTheCrossCheckWasDown is the rest of finding F4 of
// docs/review-2026-09-10.md. Three checks reach deps.dev through the loader rather
// than through Subject.Unavailable, so the rule F4 gave the others could not see
// their failures. A name nothing on the popular list resembles was reported as
// evaluated although the half of the detection that would have caught a look-alike
// the list has no entry for never ran, and young-version skipped for a publish time
// deps.dev was the only place left to read, in a sentence that named no source at
// all, so on_data_unavailable could not count it.
func TestScanSaysSoWhenOnlyTheCrossCheckWasDown(t *testing.T) {
	lock := readRegressionFixture(t, "f4-one-source-down", "package-lock.json")
	dir := scanFixture(t)
	useDownLoader(t, map[string]bool{checks.SourceDepsDev: true})
	writeFile(t, dir, "package-lock.json", lock)
	writePolicy(t, "version: 1\non_data_unavailable: fail\n")

	code, stdout, stderr := run(t, "--format", "json", "scan")
	if code != ExitUnavailable {
		t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitUnavailable, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	s := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@1.0.0")
	reasons := map[string]string{}
	for _, sk := range s.Skipped {
		reasons[sk.Check] = sk.Reason
	}
	// TD008's own list answered and matched nothing; only the cross-check is
	// missing, and the reason has to say which half ran.
	if slices.Contains(s.Evaluated, "TD008") {
		t.Errorf("TD008 is evaluated although the deps.dev cross-check could not be made")
	}
	for _, want := range []string{"the popular list matched nothing", "deps.dev unavailable: connection refused"} {
		if !strings.Contains(reasons["TD008"], want) {
			t.Errorf("TD008 skipped with %q, want it to contain %q", reasons["TD008"], want)
		}
	}
	// The fixture's registry answer carries a publish time, so TD001 still runs.
	// What it must never do again is skip without naming what was missing.
	if r := reasons["TD001"]; r != "" && !strings.Contains(r, checks.SourceDepsDev) {
		t.Errorf("TD001 skipped with %q, want the source it could not read named", r)
	}
}

// TestScanAggregatesUnhashedRequirements is the follow-up to finding F5 of
// docs/review-2026-09-10.md. Reading a plain requirements file was the fix; one
// integrity-missing finding per line of it was not usable, because a file that
// hashes nothing is one fact about the file and not two hundred about its
// packages. pip decides that per file, so the check does too: where nothing in the
// file asks for a hash there is one finding, and where the file is hash checked the
// line that lost its hash is still reported on its own.
func TestScanAggregatesUnhashedRequirements(t *testing.T) {
	tests := []struct {
		name string
		side string
		// want maps a package to the line its own finding sits on. A package that
		// is a subject with no finding of its own is absent.
		want map[string]int
	}{
		{
			name: "a file that hashes nothing is one finding",
			side: "plain",
			want: map[string]int{"trustdiff-fixture-lib": 6},
		},
		{
			name: "a hash checked file reports the line that lost its hash",
			side: "hashed",
			want: map[string]int{"trustdiff-fixture-alpha": 8},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := readRegressionFixture(t, "f5b-requirements-aggregate", tt.side, "requirements.txt")
			dir := scanFixture(t)
			writeFile(t, dir, "requirements.txt", req)

			code, stdout, stderr := run(t, "--format", "json", "--fail-on", "warn", "scan")
			if code != ExitFindings {
				t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitFindings, stderr, stdout)
			}
			rep := decodeReport(t, stdout)

			// Every pin stays a subject in its own right, whatever the file does
			// about hashes: that is what F5 was for, and TD001, TD008, TD009 and
			// TD010 all read a pin a pull request added.
			if len(rep.Subjects) != 3 {
				t.Fatalf("subjects = %v, want all three pins", refsOf(&rep))
			}
			got := map[string]int{}
			for i := range rep.Subjects {
				s := &rep.Subjects[i]
				for j := range s.Findings {
					if s.Findings[j].ID != "TD014" {
						continue
					}
					if !slices.Contains(s.Evaluated, "TD014") && s.Findings[j].Level != model.LevelWarn {
						t.Errorf("%s TD014 level = %s, want warn", s.Ref.Name, s.Findings[j].Level)
					}
					got[s.Ref.Name] = s.Location.Line
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("TD014 findings = %v, want %v", got, tt.want)
			}
			for name, line := range tt.want {
				if got[name] != line {
					t.Errorf("TD014 for %s is on line %d, want %d", name, got[name], line)
				}
			}
		})
	}
}

// TestScanDoesNotReportTheProjectAsItsOwnDependency is finding F16 of
// docs/review-2026-09-10.md. Three lockfile formats write the repository's own
// code into the lockfile beside what it installs: uv gives the project an editable
// source, Cargo gives the root package and every workspace member a table with no
// source, and Poetry gives a sibling package a directory source. None of them is a
// dependency the project acquired, and each of them arrived with no hash, so a
// clean checkout of ripgrep reported ten warnings about its own crates. What the
// project builds from its own working tree is not something a trust report has
// anything to say about.
func TestScanDoesNotReportTheProjectAsItsOwnDependency(t *testing.T) {
	tests := []struct {
		name string
		file string
		// subjects is every package the run should evaluate, and nothing else.
		subjects []string
		// unhashed is the subjects that should carry an integrity-missing finding.
		unhashed []string
	}{
		{
			name:     "a cargo workspace is not eleven dependencies",
			file:     "cargo.lock",
			subjects: []string{"memchr"},
		},
		{
			name:     "the project uv locked is not a package uv installed",
			file:     "uv.lock",
			subjects: []string{"trustdiff-fixture-lib"},
		},
		{
			// Poetry does not write the root project, and a sibling package is a
			// dependency: it stays a subject, and TD013 still says it comes from a
			// directory. What it must not say is that a hash is missing, because a
			// directory has no artifact for one to be missing from.
			name:     "a directory dependency has no artifact to hash",
			file:     "poetry.lock",
			subjects: []string{"trustdiff-fixture-local", "trustdiff-fixture-lib"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lock := readRegressionFixture(t, "f16-the-project-is-not-a-dependency", tt.file)
			dir := scanFixture(t)
			writeFile(t, dir, tt.file, lock)

			code, stdout, stderr := run(t, "--format", "json", "--fail-on", "never", "scan")
			if code != ExitOK {
				t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitOK, stderr, stdout)
			}
			rep := decodeReport(t, stdout)

			got := make([]string, 0, len(rep.Subjects))
			var unhashed []string
			for i := range rep.Subjects {
				s := &rep.Subjects[i]
				got = append(got, s.Ref.Name)
				for j := range s.Findings {
					if s.Findings[j].ID == "TD014" {
						unhashed = append(unhashed, s.Ref.Name)
					}
				}
			}
			slices.Sort(got)
			want := slices.Clone(tt.subjects)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("subjects = %v, want %v", got, want)
			}
			slices.Sort(unhashed)
			wantUnhashed := slices.Clone(tt.unhashed)
			slices.Sort(wantUnhashed)
			if !slices.Equal(unhashed, wantUnhashed) {
				t.Errorf("integrity-missing on %v, want %v", unhashed, wantUnhashed)
			}
		})
	}
}

// newScanRepo is scanFixture inside a git repository, for the paths a report
// carries. The repository is isolated from the machine's git configuration the way
// internal/gitdiff isolates its own: the two configuration files are named inside
// the temporary directory and never created, which git reads as empty.
func newScanRepo(t *testing.T) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not on PATH")
	}
	useFakeLoader(t)
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "absent-global-gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", filepath.Join(dir, "absent-system-gitconfig"))
	cmd := exec.CommandContext(t.Context(), git, "init", "--quiet")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return dir
}

// TestScanReportsPathsFromTheRepositoryRoot is finding F17 of
// docs/review-2026-09-10.md. A SARIF file is read by a code scanning service, which
// resolves every artifact location against the checkout root, so "scan frontend"
// writing package-lock.json put the annotation on a file at the top of the
// repository: a different file, or none. diff was already right, because git names
// every path from the root, and the two commands now agree.
func TestScanReportsPathsFromTheRepositoryRoot(t *testing.T) {
	lock := readRegressionFixture(t, "f17-sarif-path-from-the-repository-root", "package-lock.json")

	tests := []struct {
		name string
		// from is the directory to run in, relative to the repository root.
		from string
		args []string
		want string
	}{
		{
			name: "a subdirectory named on the command line",
			from: ".",
			args: []string{"scan", "frontend"},
			want: "frontend/package-lock.json",
		},
		{
			// Standing in the directory does not make it the root of anything.
			name: "the working directory, which is a subdirectory",
			from: "frontend",
			args: []string{"scan"},
			want: "frontend/package-lock.json",
		},
		{
			name: "the repository root itself, which prefixes nothing",
			from: ".",
			args: []string{"scan", "."},
			want: "package-lock.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := newScanRepo(t)
			where := "frontend/package-lock.json"
			if tt.want == "package-lock.json" {
				where = "package-lock.json"
			}
			writeFile(t, dir, where, lock)
			chdir(t, filepath.Join(dir, filepath.FromSlash(tt.from)))

			args := append([]string{"--format", "sarif", "--fail-on", "never"}, tt.args...)
			code, stdout, stderr := run(t, args...)
			if code != ExitOK {
				t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitOK, stderr, stdout)
			}
			if want := `"uri": "` + tt.want + `"`; !strings.Contains(stdout, want) {
				t.Errorf("the SARIF file does not carry %s:\n%s", want, stdout)
			}

			// The json report is where a script reads the same path, so the two say
			// the same thing about the same file.
			args = append([]string{"--format", "json", "--fail-on", "never"}, tt.args...)
			code, stdout, stderr = run(t, args...)
			if code != ExitOK {
				t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitOK, stderr, stdout)
			}
			rep := decodeReport(t, stdout)
			if len(rep.Subjects) == 0 || rep.Subjects[0].Location == nil {
				t.Fatalf("no located subject in %s", stdout)
			}
			if got := rep.Subjects[0].Location.Path; got != tt.want {
				t.Errorf("location = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestScanNeverAsksAboutANameNpmCouldNeverHold is finding F25 of
// docs/review-2026-09-10.md. A lockfile in a pull request chooses its own package
// names, and the npm client put one into the download counts URL unescaped. A name
// npm's own grammar refuses cannot be on the registry, so the run reports the entry
// and asks nobody about it. The policy says on_data_unavailable: fail, which pins
// that such a name is an answer and not an outage: the exit code is the block's 1,
// not 3.
func TestScanNeverAsksAboutANameNpmCouldNeverHold(t *testing.T) {
	lock := readRegressionFixture(t, "f25-npm-name-grammar", "package-lock.json")
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", lock)
	writeFile(t, dir, ".trustdiff.yaml", "version: 1\non_data_unavailable: fail\n")

	code, stdout, stderr := run(t, "--format", "json", "--fail-on", "block", "scan")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want %d (stderr %q)\n%s", code, ExitFindings, stderr, stdout)
	}
	rep := decodeReport(t, stdout)
	hostile := map[string]bool{"evil?trustdiff=1": false, "@scope/..": false}
	for i := range rep.Subjects {
		s := &rep.Subjects[i]
		if _, bad := hostile[s.Ref.Name]; !bad {
			continue
		}
		hostile[s.Ref.Name] = true
		var reported bool
		for _, f := range s.Findings {
			if f.ID == "TD013" && f.Level == model.LevelBlock && strings.Contains(f.Explanation, "name cannot exist on the registry") {
				reported = true
			}
		}
		if !reported {
			t.Errorf("%s has no TD013 block finding: %+v", s.Ref.Name, s.Findings)
		}
		for _, sk := range s.Skipped {
			if sk.Check == "TD016" || sk.Check == "TD017" {
				continue
			}
			if !strings.HasPrefix(sk.Reason, "not a valid npm name") {
				t.Errorf("%s: %s skipped with %q, want the name named as the reason", s.Ref.Name, sk.Check, sk.Reason)
			}
		}
	}
	for name, seen := range hostile {
		if !seen {
			t.Errorf("no subject for %s; the parser dropped it rather than reporting it", name)
		}
	}
}
