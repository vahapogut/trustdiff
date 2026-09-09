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
	got, problems := Observe(context.Background(), src, refs, now, 2)
	if len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
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
	got, problems := Observe(context.Background(), src, refs, now, 1)
	if len(got) != 2 {
		t.Fatalf("entries = %+v, want one per package that carried a version", got)
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
