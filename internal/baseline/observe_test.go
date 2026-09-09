package baseline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// signals is a fake Signals with canned answers, keyed by ref string for the
// releases and by "<eco>:<name>" for the owner sets. A key with no entry answers
// errUnknown, the way a registry answers for a package it does not have.
type signals struct {
	releases map[string]*model.VersionInfo
	owners   map[string][]model.Publisher
	fail     map[string]error
}

var errUnknown = errors.New("not found")

func (s *signals) VersionInfo(_ context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	if err := s.fail[ref.String()]; err != nil {
		return nil, err
	}
	if info, ok := s.releases[ref.String()]; ok {
		return info, nil
	}
	return nil, errUnknown
}

func (s *signals) Owners(_ context.Context, eco model.Ecosystem, name string) ([]model.Publisher, error) {
	key := string(eco) + ":" + name
	if err := s.fail[key]; err != nil {
		return nil, err
	}
	if owners, ok := s.owners[key]; ok {
		return owners, nil
	}
	return nil, errUnknown
}

// publishers turns names into publishers.
func publishers(names ...string) []model.Publisher {
	out := make([]model.Publisher, 0, len(names))
	for _, n := range names {
		out = append(out, model.Publisher{Name: n})
	}
	return out
}

// An npm release names its publisher, so that is what is recorded; a PyPI release
// names none and the identity of its attestation is the only publishing identity
// there is.
func TestObserveRecordsWhatEachRegistryExposes(t *testing.T) {
	src := &signals{
		releases: map[string]*model.VersionInfo{
			"npm:example-lib@4.19.2": {
				Ref:        model.MustParseRef("npm:example-lib@4.19.2"),
				Publisher:  &model.Publisher{Name: "alice"},
				Provenance: model.Provenance{Kind: model.ProvenanceSignature},
			},
			"pypi:example-tool@2.32.3": {
				Ref: model.MustParseRef("pypi:example-tool@2.32.3"),
				Provenance: model.Provenance{
					Kind: model.ProvenanceAttestation, Verified: true,
					Identity: "github:example/example-tool/publish.yml",
				},
			},
		},
		owners: map[string][]model.Publisher{
			"npm:example-lib":   publishers("alice", "bob-ci"),
			"pypi:example-tool": publishers("carol"),
		},
	}
	refs := []model.PackageRef{
		model.MustParseRef("pypi:example-tool@2.32.3"),
		model.MustParseRef("npm:example-lib@4.19.2"),
	}
	got, problems, unavailable := Observe(context.Background(), src, refs, now, 2)
	if len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
	}
	if len(unavailable) != 0 {
		t.Fatalf("unavailable = %v, want none: every lookup answered", unavailable)
	}
	if len(got) != 2 || got[0].Ecosystem != model.NPM || got[1].Ecosystem != model.PyPI {
		t.Fatalf("entries = %+v, want them sorted by ecosystem", got)
	}

	npm := got[0]
	if npm.Publisher != "alice" || npm.PublisherSource != FromRegistry {
		t.Errorf("npm publisher = %q from %q, want alice from the registry", npm.Publisher, npm.PublisherSource)
	}
	if npm.Provenance == nil || npm.Provenance.Kind != model.ProvenanceSignature {
		t.Errorf("npm provenance = %+v, want the signature", npm.Provenance)
	}
	if len(npm.Maintainers) != 2 || npm.Maintainers[0] != "alice" {
		t.Errorf("npm maintainers = %v, want alice and bob-ci", npm.Maintainers)
	}
	if !npm.ObservedAt.Equal(now) {
		t.Errorf("observed_at = %s, want the run clock", npm.ObservedAt)
	}

	pypi := got[1]
	if pypi.Publisher != "github:example/example-tool/publish.yml" || pypi.PublisherSource != FromProvenance {
		t.Errorf("pypi publisher = %q from %q, want the attestation identity", pypi.Publisher, pypi.PublisherSource)
	}
}

// What could not be read is left absent and said out loud. A gap must never be
// recorded as a fact, because the next run would read it as a change.
func TestObserveReportsWhatItCouldNotRead(t *testing.T) {
	src := &signals{
		releases: map[string]*model.VersionInfo{
			"npm:example-lib@4.19.2": {
				Ref:     model.MustParseRef("npm:example-lib@4.19.2"),
				Unknown: map[string]string{model.FacetProvenance: "the integrity API answered 503"},
			},
		},
		owners: map[string][]model.Publisher{"npm:example-lib": publishers("alice")},
		fail:   map[string]error{"cargo:example-crate": errors.New("connection refused")},
	}
	refs := []model.PackageRef{
		model.MustParseRef("npm:example-lib@4.19.2"),
		model.MustParseRef("cargo:example-crate@1.0.200"),
		model.MustParseRef("npm:example-lib"),
		model.MustParseRef("npm:example-lib@9.9.9"),
	}
	got, problems, unavailable := Observe(context.Background(), src, refs, now, 1)
	if len(got) != 2 {
		t.Fatalf("entries = %+v, want one per package that carried a version", got)
	}
	if len(unavailable) != 2 {
		t.Fatalf("unavailable = %v, want both packages: one lookup failed and one facet was not answered", unavailable)
	}
	for _, e := range got {
		if e.Provenance != nil {
			t.Errorf("%s recorded provenance although it could not be read: %+v", e.Ref(), e.Provenance)
		}
		if e.Publisher != "" {
			t.Errorf("%s recorded a publisher although none was readable", e.Ref())
		}
	}
	crate := got[0]
	if crate.Ecosystem != model.Cargo || len(crate.Maintainers) != 0 {
		t.Errorf("crate entry = %+v, want no maintainer set", crate)
	}
	want := []string{
		"npm:example-lib: no version to observe",
		"provenance was not read (the integrity API answered 503)",
		"the maintainer set was not read (connection refused)",
		"is locked at 4.19.2 and at 9.9.9; recorded 4.19.2",
	}
	joined := strings.Join(problems, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("problems do not mention %q:\n%s", w, joined)
		}
	}
}

// Update merges: a run that observed one package leaves the record of every other
// one alone, and a full snapshot drops what the project no longer locks.
func TestUpdateMergesAndSnapshotPrunes(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	if err := Write(path, file(
		entry("npm:example-lib@1.0.0", 30*day, "alice"),
		entry("cargo:example-crate@1.0.0", 30*day, "dave"),
	)); err != nil {
		t.Fatal(err)
	}

	// A partial run: one package observed, nothing pruned.
	if _, err := Update(path, []Entry{entry("npm:example-lib@2.0.0", 0, "alice", "bob-ci")}, nil, now); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 2 {
		t.Fatalf("packages = %+v, want the untouched crate kept", f.Packages)
	}
	lib, _ := f.Lookup(model.MustParseRef("npm:example-lib"))
	if lib.Version != "2.0.0" || len(lib.Maintainers) != 2 {
		t.Errorf("npm entry = %+v, want the fresh observation", lib)
	}
	if !f.UpdatedAt.Equal(now) {
		t.Errorf("updated_at = %s, want the run clock", f.UpdatedAt)
	}

	// A snapshot: the crate is no longer locked, so its record goes.
	locked := []model.PackageRef{model.MustParseRef("npm:example-lib@2.0.0")}
	dropped, err := Update(path, []Entry{entry("npm:example-lib@2.0.0", 0, "alice")}, locked, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0].Name != "example-crate" {
		t.Fatalf("dropped = %+v, want the crate", dropped)
	}
	if f, err = Load(path); err != nil || len(f.Packages) != 1 {
		t.Fatalf("packages = %+v, err = %v", f.Packages, err)
	}
}

// A project with no baseline gets one, directory and all.
func TestUpdateCreatesTheFile(t *testing.T) {
	path := Path(t.TempDir())
	if _, err := Update(path, []Entry{entry("npm:example-lib@1.0.0", 0, "alice")}, nil, now); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Schema != SchemaID || len(f.Packages) != 1 {
		t.Fatalf("file = %+v, want one entry in a fresh baseline", f)
	}
}

// A baseline this binary cannot read is a reason to stop rather than a file to
// replace: overwriting it would throw away records nobody can get back.
func TestUpdateRefusesADocumentItCannotRead(t *testing.T) {
	path := Path(t.TempDir())
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	later := `{"schema":"trustdiff.baseline/2","updated_at":"2026-09-09T12:00:00Z","packages":[]}`
	if err := os.WriteFile(path, []byte(later), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(path, []Entry{entry("npm:example-lib@1.0.0", 0, "alice")}, nil, now); !errors.Is(err, ErrWrongSchema) {
		t.Fatalf("err = %v, want ErrWrongSchema", err)
	}
}

// A run whose lookups all failed must leave the record exactly as it was. The
// maintainer set of a PyPI or crates.io package is the only answer TD002 and
// TD003 have there, and a rate limit, a 5xx, an interrupt or a package the
// registry has removed is not a reason to forget it.
func TestUpdateKeepsARecordAnObservationCouldNotMake(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	before := entry("pypi:example-tool@2.32.3", 30*day, "alice", "bob")
	before.Publisher = "github:example/example-tool/publish.yml"
	before.PublisherSource = FromProvenance
	before.Provenance = &Provenance{Kind: model.ProvenanceAttestation, Verified: true}
	if err := Write(path, file(before)); err != nil {
		t.Fatal(err)
	}

	// Everything the run asks for fails, which is what --offline, a rate limit or
	// a registry outage looks like from here.
	src := &signals{fail: map[string]error{
		"pypi:example-tool@2.32.3": errors.New("connection refused"),
		"pypi:example-tool":        errors.New("connection refused"),
	}}
	observed, problems, unavailable := Observe(context.Background(), src,
		[]model.PackageRef{model.MustParseRef("pypi:example-tool@2.32.3")}, now, 1)
	if len(unavailable) != 1 {
		t.Fatalf("unavailable = %v, want the package neither lookup answered for", unavailable)
	}
	if _, err := Update(path, observed, nil, now); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := got.Lookup(model.MustParseRef("pypi:example-tool"))
	if !ok {
		t.Fatalf("the record was deleted by a run that read nothing: %+v", got.Packages)
	}
	if len(e.Maintainers) != 2 || e.Maintainers[0] != "alice" || e.Maintainers[1] != "bob" {
		t.Errorf("maintainers = %v, want the recorded set kept", e.Maintainers)
	}
	if e.Publisher != before.Publisher || e.PublisherSource != before.PublisherSource || e.Provenance == nil {
		t.Errorf("entry = %+v, want the recorded publisher and provenance kept", e)
	}
	if !e.ObservedAt.Equal(ago(30 * day)) {
		t.Errorf("observed_at = %s, want the recorded time: nothing was observed", e.ObservedAt)
	}
	joined := strings.Join(problems, "\n")
	for _, want := range []string{"the release was not read", "the maintainer set was not read", "was kept"} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems do not say %q:\n%s", want, joined)
		}
	}
}

// A package that has no record yet and could not be read is not recorded at all:
// an entry holding a name and a timestamp claims an observation nobody made.
func TestUpdateRecordsNothingForAPackageItCouldNotRead(t *testing.T) {
	path := Path(t.TempDir())
	src := &signals{fail: map[string]error{
		"cargo:example-crate@1.0.200": errors.New("connection refused"),
		"cargo:example-crate":         errors.New("connection refused"),
	}}
	observed, _, _ := Observe(context.Background(), src,
		[]model.PackageRef{model.MustParseRef("cargo:example-crate@1.0.200")}, now, 1)
	if _, err := Update(path, observed, nil, now); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 0 {
		t.Errorf("packages = %+v, want none: nothing was read to record", f.Packages)
	}
}

// One lookup that failed must not take the other's answer with it: the maintainer
// set belongs to the package and the publisher belongs to the release.
func TestUpdateKeepsTheHalfOfARecordThatWasNotRead(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	before := entry("npm:example-lib@1.0.0", 30*day, "alice")
	before.Publisher = "alice"
	before.PublisherSource = FromRegistry
	if err := Write(path, file(before)); err != nil {
		t.Fatal(err)
	}
	// The owners answer, the release does not.
	src := &signals{
		owners: map[string][]model.Publisher{"npm:example-lib": publishers("alice", "mallory")},
		fail:   map[string]error{"npm:example-lib@2.0.0": errors.New("503 from the registry")},
	}
	observed, _, _ := Observe(context.Background(), src,
		[]model.PackageRef{model.MustParseRef("npm:example-lib@2.0.0")}, now, 1)
	if _, err := Update(path, observed, nil, now); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := f.Lookup(model.MustParseRef("npm:example-lib"))
	if len(e.Maintainers) != 2 || e.Maintainers[1] != "mallory" {
		t.Errorf("maintainers = %v, want the set the registry answered with", e.Maintainers)
	}
	if e.Publisher != "alice" || e.Version != "1.0.0" {
		t.Errorf("entry = %+v, want the release half left at the release it was read from", e)
	}
	if !e.ObservedAt.Equal(now) {
		t.Errorf("observed_at = %s, want the run clock: the maintainer set moved", e.ObservedAt)
	}
}

// A rerun that saw nothing new must rewrite no entry. The file is committed and
// compared in pull requests, so five hundred packages that did not change are
// five hundred lines nobody should have to read past.
func TestUpdateKeepsObservedAtWhenNothingChanged(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	if err := Write(path, file(entry("npm:example-lib@1.0.0", 30*day, "alice"))); err != nil {
		t.Fatal(err)
	}
	later := now.Add(7 * day)

	// The same signals, observed a week later.
	if _, err := Update(path, []Entry{entry("npm:example-lib@1.0.0", -7*day, "alice")}, nil, later); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := f.Lookup(model.MustParseRef("npm:example-lib"))
	if !e.ObservedAt.Equal(ago(30 * day)) {
		t.Errorf("observed_at = %s, want the recorded %s: nothing about the signals moved", e.ObservedAt, ago(30*day))
	}
	if !f.UpdatedAt.Equal(later) {
		t.Errorf("updated_at = %s, want the run clock: the file itself was written", f.UpdatedAt)
	}

	// A signal that did move takes the time with it, or the record would say the
	// new set has been there all along.
	if _, err := Update(path, []Entry{entry("npm:example-lib@1.0.0", -7*day, "alice", "mallory")}, nil, later); err != nil {
		t.Fatal(err)
	}
	if f, err = Load(path); err != nil {
		t.Fatal(err)
	}
	e, _ = f.Lookup(model.MustParseRef("npm:example-lib"))
	if !e.ObservedAt.Equal(later) {
		t.Errorf("observed_at = %s, want %s: the maintainer set changed", e.ObservedAt, later)
	}
}

func TestCompareReportsMaintainerChanges(t *testing.T) {
	recorded := file(
		entry("npm:example-lib@1.0.0", 30*day, "alice"),
		entry("cargo:example-crate@1.0.0", 30*day, "dave"),
		entry("pypi:example-tool@1.0.0", 30*day),
	)
	observed := []Entry{
		// The version did not move and a maintainer appeared: the case no
		// comparison of two releases can see.
		entry("npm:example-lib@1.0.0", 0, "alice", "mallory"),
		// Same set, another spelling: not a change.
		entry("cargo:example-crate@2.0.0", 0, "Dave"),
		// The record has no set to compare with.
		entry("pypi:example-tool@1.0.0", 0, "carol"),
		// Never recorded before.
		entry("npm:example-new@1.0.0", 0, "carol"),
	}
	changes := Compare(recorded, observed)
	if len(changes) != 1 {
		t.Fatalf("changes = %+v, want only the npm package", changes)
	}
	c := changes[0]
	if c.Was.Name != "example-lib" || len(c.Added) != 1 || c.Added[0] != "mallory" || len(c.Removed) != 0 {
		t.Errorf("change = %+v, want mallory added", c)
	}
	if c.VersionMoved() {
		t.Error("VersionMoved() is true although the locked version stayed put")
	}
}
