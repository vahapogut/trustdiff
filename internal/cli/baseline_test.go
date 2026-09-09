package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/baseline"
	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
)

// readBaselineFile reads the baseline the working directory holds, failing the
// test when there is none.
func readBaselineFile(t *testing.T, dir string) *baseline.File {
	t.Helper()
	f, err := baseline.Load(baseline.Path(dir))
	if err != nil {
		t.Fatalf("read the baseline: %v", err)
	}
	return f
}

// baselineNow is the clock the fixtures pin through TRUSTDIFF_NOW. It is spelled
// out here rather than taken from fixtureClock, which moves the working directory
// and would undo the tree a test has just built.
var baselineNow = time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)

// writeBaselineFile puts a baseline in the working directory, the way a commit
// would.
func writeBaselineFile(t *testing.T, dir string, entries ...baseline.Entry) {
	t.Helper()
	f := baseline.New(baselineNow)
	for i := range entries {
		f.Put(&entries[i])
	}
	if err := baseline.Write(baseline.Path(dir), f); err != nil {
		t.Fatal(err)
	}
}

// recorded builds an entry for a ref with a maintainer set, observed thirty days
// before the pinned clock.
func recorded(ref string, maintainers ...string) baseline.Entry {
	r := model.MustParseRef(ref)
	return baseline.Entry{
		Ecosystem:   r.Ecosystem,
		Name:        r.Name,
		Version:     r.Version,
		ObservedAt:  baselineNow.AddDate(0, 0, -30),
		Maintainers: maintainers,
	}
}

// The command records every package the lockfiles lock, in a document that
// matches the published schema.
func TestBaselineRecordsEveryLockedPackage(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)

	code, stdout, stderr := run(t, "baseline")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stdout: %s, stderr: %s)", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "recorded 2 packages in") {
		t.Errorf("stdout does not say what was recorded:\n%s", stdout)
	}

	f := readBaselineFile(t, dir)
	if len(f.Packages) != 2 {
		t.Fatalf("packages = %+v, want both locked entries", f.Packages)
	}
	lib, ok := f.Lookup(model.MustParseRef("npm:trustdiff-fixture-lib"))
	if !ok {
		t.Fatalf("the locked package was not recorded: %+v", f.Packages)
	}
	if lib.Version != "1.0.0" || lib.Publisher != "alice" || lib.PublisherSource != baseline.FromRegistry {
		t.Errorf("entry = %+v, want the locked release and its publisher", lib)
	}
	if len(lib.Maintainers) != 2 || lib.Maintainers[0] != "alice" || lib.Maintainers[1] != "bob" {
		t.Errorf("maintainers = %v, want the registry's owner set", lib.Maintainers)
	}

	data, err := os.ReadFile(baseline.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.Compile(baseline.SchemaJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(data); err != nil {
		t.Errorf("the written baseline does not match schema/baseline.v1.json:\n%v\n%s", err, data)
	}
}

// A package the registry could not answer for is recorded without the fields
// nobody could read, and the run says so instead of inventing them.
func TestBaselineSaysWhatItCouldNotRead(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)

	_, stdout, _ := run(t, "baseline")
	if !strings.Contains(stdout, "trustdiff-fixture-gone@1.0.0: the release was not read") {
		t.Errorf("stdout does not name the release that could not be read:\n%s", stdout)
	}
	gone, ok := readBaselineFile(t, dir).Lookup(model.MustParseRef("npm:trustdiff-fixture-gone"))
	if !ok {
		t.Fatal("the package was not recorded at all")
	}
	if gone.Publisher != "" || gone.Provenance != nil {
		t.Errorf("entry = %+v, want no publisher and no provenance recorded", gone)
	}
}

// Writing the same observation twice must produce the same bytes: the file is
// committed, and a run that reordered it would show up as a change nobody made.
func TestBaselineRewriteIsStable(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)

	run(t, "baseline")
	first, err := os.ReadFile(baseline.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	run(t, "baseline")
	second, err := os.ReadFile(baseline.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("a second run rewrote the file:\n%s\n%s", first, second)
	}

	// The same again two days later. An entry whose signals a run found unchanged
	// keeps the time it carries, so a project of five hundred packages produces a
	// one line diff and not five hundred; only the file's own updated_at moves.
	later := baselineNow.Add(48 * time.Hour)
	t.Setenv(nowEnv, later.Format(time.RFC3339))
	run(t, "baseline")
	moved := readBaselineFile(t, dir)
	if !moved.UpdatedAt.Equal(later) {
		t.Errorf("updated_at = %s, want the later run's clock", moved.UpdatedAt)
	}
	for i := range moved.Packages {
		e := &moved.Packages[i]
		if !e.ObservedAt.Equal(baselineNow) {
			t.Errorf("%s observed_at = %s, want the first run's %s: nothing about its signals moved",
				e.Package(), e.ObservedAt, baselineNow)
		}
	}
}

// The case no run over a lockfile change can see: the locked version did not
// move and the maintainer set did. It is reported as the finding TD003 makes.
func TestBaselineReportsMaintainerChangeWithoutAVersionChange(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)
	writeBaselineFile(t, dir, recorded("npm:trustdiff-fixture-lib@1.0.0", "alice"))

	code, stdout, stderr := run(t, "--format", "json", "baseline")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 1 {
		t.Fatalf("subjects = %+v, want only the package whose maintainers changed", rep.Subjects)
	}
	s := rep.Subjects[0]
	if s.Ref.String() != "npm:trustdiff-fixture-lib@1.0.0" {
		t.Errorf("ref = %s", s.Ref)
	}
	if len(s.Findings) != 1 {
		t.Fatalf("findings = %+v, want one", s.Findings)
	}
	f := s.Findings[0]
	if f.ID != "TD003" || f.Name != "maintainers-changed" || f.Level != model.LevelWarn {
		t.Errorf("finding = %+v, want a TD003 warning", f)
	}
	if f.Title != "Maintainers changed since the baseline: added bob" {
		t.Errorf("title = %q", f.Title)
	}
	if !strings.Contains(f.Explanation, "the locked version did not move") {
		t.Errorf("explanation = %q, want it to say the version stayed put", f.Explanation)
	}
	if f.Evidence["baseline_age_days"] != float64(30) {
		t.Errorf("baseline_age_days = %v, want 30", f.Evidence["baseline_age_days"])
	}
	// The record is replaced by the run that reported the change.
	lib, _ := readBaselineFile(t, dir).Lookup(model.MustParseRef("npm:trustdiff-fixture-lib"))
	if len(lib.Maintainers) != 2 {
		t.Errorf("maintainers = %v, want the fresh observation written back", lib.Maintainers)
	}
}

// A snapshot drops what the project no longer locks, so the file does not grow
// forever, and says which entries went.
func TestBaselineDropsWhatIsNoLongerLocked(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)
	writeBaselineFile(t, dir, recorded("npm:trustdiff-fixture-removed@1.0.0", "alice"))

	_, stdout, _ := run(t, "baseline")
	if !strings.Contains(stdout, "dropped 1 entry no longer locked (npm:trustdiff-fixture-removed)") {
		t.Errorf("stdout does not name the dropped entry:\n%s", stdout)
	}
	if _, ok := readBaselineFile(t, dir).Lookup(model.MustParseRef("npm:trustdiff-fixture-removed")); ok {
		t.Error("the entry of a package that is no longer locked was kept")
	}
}

// A policy that turns the check off turns the drift report off with it: the
// record is still written, and nothing is reported.
func TestBaselineHonorsThePolicyLevel(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)
	writeBaselineFile(t, dir, recorded("npm:trustdiff-fixture-lib@1.0.0", "alice"))
	writePolicy(t, "version: 1\nchecks:\n  maintainers-changed: off\n")

	code, stdout, _ := run(t, "--format", "json", "baseline")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if rep := decodeReport(t, stdout); len(rep.Subjects) != 0 {
		t.Errorf("subjects = %+v, want none while the check is off", rep.Subjects)
	}
	if _, ok := readBaselineFile(t, dir).Lookup(model.MustParseRef("npm:trustdiff-fixture-lib")); !ok {
		t.Error("the observation was not written")
	}
}

// lockOf is a lockfile locking the package the fake loader serves at one version,
// so that two of them lock the same package at two versions.
func lockOf(version string) string {
	return `{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/trustdiff-fixture-lib": {
      "version": "` + version + `",
      "resolved": "https://registry.npmjs.org/trustdiff-fixture-lib/-/trustdiff-fixture-lib-` + version + `.tgz",
      "integrity": "sha512-Zm9ydGhlbGli"
    }
  }
}
`
}

// Exit code 3 says a data source was unavailable. A package the project locks at
// two versions is a line the run writes about the project, not an outage, so it
// must not raise the code even where the policy fails on unavailable data; a
// release the registry did not answer for must.
func TestBaselineExitsThreeOnlyForAnUnavailableSource(t *testing.T) {
	dir := scanFixture(t)
	writePolicy(t, "version: 1\non_data_unavailable: fail\n")
	writeFile(t, dir, "package-lock.json", lockOf("1.0.0"))
	writeFile(t, dir, "web/package-lock.json", lockOf("2.0.0"))

	code, stdout, stderr := run(t, "baseline")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0: every request was answered (stdout: %s, stderr: %s)", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "is locked at 1.0.0 and at 2.0.0") {
		t.Errorf("stdout does not report the package locked twice:\n%s", stdout)
	}

	// The same policy over a release the registry does not have exits 3, which is
	// what the setting is for.
	writeFile(t, dir, "package-lock.json", baseLock)
	if err := os.Remove(filepath.Join(dir, "web", "package-lock.json")); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr = run(t, "baseline"); code != ExitUnavailable {
		t.Fatalf("exit = %d, want 3 for a release the registry did not answer for (stdout: %s, stderr: %s)", code, stdout, stderr)
	}
}

// A baseline this binary cannot read stops the run: carrying on would report
// every check that needs a record as skipped, and a gate would read that as
// nothing to see.
func TestBaselineRefusesADocumentItCannotRead(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)
	writeFile(t, dir, ".trustdiff/baseline.json", `{"schema":"trustdiff.baseline/2","updated_at":"2026-09-09T12:00:00Z","packages":[]}`)

	code, _, stderr := run(t, "baseline")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "not a trustdiff baseline of schema version 1") {
		t.Errorf("stderr = %q", stderr)
	}
}

// baselineApp builds an App the way the root command would, for the calls diff
// and scan make into this file.
func baselineApp(t *testing.T, format string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errb bytes.Buffer
	app := &App{Stdout: &out, Stderr: &errb, Opts: Options{Format: format, FailOn: "block", Jobs: 4}}
	app.Opts.Log = slog.New(slog.NewTextHandler(&errb, &slog.HandlerOptions{Level: slog.LevelError}))
	return app, &out, &errb
}

// The call site diff and scan reach this file through: the baseline is attached
// to the loader for the checks to read, and what the run observed is written back
// when --update-baseline is given.
//
// npm records a maintainer set per version and this fixture's releases carry
// none, so TD003 falls back to the baseline, which is what a run over a PyPI or
// crates.io lockfile does for every package.
func TestEvaluateWithBaselineAnswersTheChecksAndWritesBack(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)
	writeBaselineFile(t, dir, recorded("npm:trustdiff-fixture-lib@1.0.0", "alice"))

	app, stdout, _ := baselineApp(t, "json")
	cmd := app.newScanCommand()
	if err := cmd.Flags().Set("update-baseline", "true"); err != nil {
		t.Fatal(err)
	}
	st, err := app.settle()
	if err != nil {
		t.Fatal(err)
	}
	inputs, read, _ := app.readLockfiles(dir, []string{"package-lock.json"})
	if len(read) != 1 {
		t.Fatalf("read = %v, want the lockfile", read)
	}
	err = app.evaluateWithBaseline(context.Background(), cmd, st, inputs, false, dir)

	rep := decodeReport(t, stdout.String())
	lib := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@1.0.0")
	var found bool
	for _, f := range lib.Findings {
		if f.ID != "TD003" {
			continue
		}
		found = true
		if !strings.Contains(f.Explanation, "the baseline recorded alice as maintainer") {
			t.Errorf("explanation = %q, want the record it compared with", f.Explanation)
		}
	}
	if !found {
		t.Errorf("TD003 did not answer from the baseline: findings %+v, skipped %+v", lib.Findings, lib.Skipped)
	}
	var exit *ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("err = %v, want either nothing or an exit code", err)
	}

	written := readBaselineFile(t, dir)
	entry, ok := written.Lookup(model.MustParseRef("npm:trustdiff-fixture-lib"))
	if !ok || len(entry.Maintainers) != 2 {
		t.Errorf("entry = %+v, want the fresh observation written back", entry)
	}
}

// Without --update-baseline the file is only read, never written: a pull request
// gate must not change the record it is measuring against.
func TestEvaluateWithBaselineLeavesTheFileAloneByDefault(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)
	writeBaselineFile(t, dir, recorded("npm:trustdiff-fixture-lib@1.0.0", "alice"))
	before, err := os.ReadFile(baseline.Path(dir))
	if err != nil {
		t.Fatal(err)
	}

	app, _, _ := baselineApp(t, "json")
	cmd := app.newScanCommand()
	st, err := app.settle()
	if err != nil {
		t.Fatal(err)
	}
	inputs, _, _ := app.readLockfiles(dir, []string{"package-lock.json"})
	_ = app.evaluateWithBaseline(context.Background(), cmd, st, inputs, false, dir)

	after, err := os.ReadFile(baseline.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the baseline was rewritten without --update-baseline:\n%s\n%s", before, after)
	}
}

// The pull request case. The baseline in the working tree is a file like any
// other and the change under review may have rewritten it, so the record the base
// revision holds is what the checks compare with, and the rewrite is reported as
// evidence rather than passing quietly.
func TestEvaluateWithBaselineComparesTheBaseRevision(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", baseLock)
	writeBaselineFile(t, r.dir, recorded("npm:trustdiff-fixture-lib@1.0.0", "alice"))
	r.commit("base")
	// The change adds itself to the record, which is what somebody who had just
	// taken the package over would do to keep the gate quiet.
	writeBaselineFile(t, r.dir, recorded("npm:trustdiff-fixture-lib@1.0.0", "alice", "bob"))
	r.commit("the change under review")

	app, stdout, _ := baselineApp(t, "json")
	cmd := app.newDiffCommand()
	st, err := app.settle()
	if err != nil {
		t.Fatal(err)
	}
	inputs, _, _ := app.readLockfiles(r.dir, []string{"package-lock.json"})
	_ = app.evaluateWithBaseline(context.Background(), cmd, st, inputs, false, ".")

	rep := decodeReport(t, stdout.String())
	lib := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@1.0.0")
	for _, f := range lib.Findings {
		if f.ID != "TD003" {
			continue
		}
		if f.Evidence["baseline_rewritten"] != true {
			t.Errorf("evidence = %v, want the rewrite reported", f.Evidence)
		}
		if !strings.Contains(f.Explanation, "the change under review rewrote this package's baseline entry") {
			t.Errorf("explanation = %q, want the rewrite in words", f.Explanation)
		}
		return
	}
	t.Errorf("TD003 did not compare with the base revision's record: findings %+v, skipped %+v", lib.Findings, lib.Skipped)
}

// Deleting the record is the same attack as rewriting it, with a bigger eraser,
// and it is answered the same way: the base revision's copy is read and compared.
// The deletion used to be the one that worked, because the path of a file that is
// not there was relative, could not be placed inside the repository, and the base
// side was dropped with nothing but a debug line to show for it.
func TestEvaluateWithBaselineReadsABaselineTheChangeDeleted(t *testing.T) {
	r := diffFixture(t)
	r.write("package-lock.json", baseLock)
	writeBaselineFile(t, r.dir, recorded("npm:trustdiff-fixture-lib@1.0.0", "alice"))
	r.commit("base")
	if err := os.Remove(baseline.Path(r.dir)); err != nil {
		t.Fatal(err)
	}
	r.commit("the change under review")

	app, stdout, _ := baselineApp(t, "json")
	cmd := app.newDiffCommand()
	st, err := app.settle()
	if err != nil {
		t.Fatal(err)
	}
	inputs, _, _ := app.readLockfiles(r.dir, []string{"package-lock.json"})
	_ = app.evaluateWithBaseline(context.Background(), cmd, st, inputs, false, ".")

	rep := decodeReport(t, stdout.String())
	lib := subjectFor(t, &rep, "npm:trustdiff-fixture-lib@1.0.0")
	for _, f := range lib.Findings {
		if f.ID != "TD003" {
			continue
		}
		if f.Evidence["baseline_deleted"] != true || f.Evidence["baseline_rewritten"] != true {
			t.Errorf("evidence = %v, want the deletion reported", f.Evidence)
		}
		if !strings.Contains(f.Explanation, "deleted this package's baseline entry") {
			t.Errorf("explanation = %q, want the deletion in words", f.Explanation)
		}
		return
	}
	t.Errorf("TD003 did not read the deleted record from the base revision: findings %+v, skipped %+v", lib.Findings, lib.Skipped)
}

// A run that reported something must not record what it reported. The file is the
// one the README tells people to commit, so a run that found a maintainer
// takeover would otherwise write the new set in as the truth and pass next time.
func TestEvaluateWithBaselineDoesNotWriteWhenTheRunBlocked(t *testing.T) {
	dir := scanFixture(t)
	writeFile(t, dir, "package-lock.json", baseLock)
	writeBaselineFile(t, dir, recorded("npm:trustdiff-fixture-lib@1.0.0", "alice"))
	before, err := os.ReadFile(baseline.Path(dir))
	if err != nil {
		t.Fatal(err)
	}

	app, _, stderr := baselineApp(t, "json")
	// The maintainer set change TD003 reports is a warning, so this is what a
	// project that gates on warnings sees.
	app.Opts.FailOn = "warn"
	cmd := app.newScanCommand()
	if err := cmd.Flags().Set("update-baseline", "true"); err != nil {
		t.Fatal(err)
	}
	st, err := app.settle()
	if err != nil {
		t.Fatal(err)
	}
	inputs, _, _ := app.readLockfiles(dir, []string{"package-lock.json"})
	err = app.evaluateWithBaseline(context.Background(), cmd, st, inputs, false, dir)

	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitFindings {
		t.Fatalf("err = %v, want exit code 1: the maintainer change is a finding", err)
	}
	after, readErr := os.ReadFile(baseline.Path(dir))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the run recorded the signals it blocked on:\n%s\n%s", before, after)
	}
	if !strings.Contains(stderr.String(), "the baseline was not updated") {
		t.Errorf("the run did not say why the record was left alone:\n%s", stderr)
	}
}

// The baseline is found upward from the working directory, the way the policy
// file is, so a command run in one package of a monorepo writes the repository's
// record rather than starting a second one.
func TestBaselinePathIsFoundUpwards(t *testing.T) {
	dir := scanFixture(t)
	writeBaselineFile(t, dir)
	nested := filepath.Join(dir, "packages", "web")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	app, _, _ := baselineApp(t, "human")
	got, err := app.baselinePath(nested)
	if err != nil {
		t.Fatal(err)
	}
	if got != baseline.Path(dir) {
		t.Errorf("path = %q, want %q", got, baseline.Path(dir))
	}
}
