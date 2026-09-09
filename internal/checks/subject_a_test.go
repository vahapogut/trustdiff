package checks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// Helpers for the tests of TD001 to TD007: a fixed clock, a fake Loader and
// Subject builders. The A suffix keeps the names apart from the helpers of the
// other check tests in this package.

// nowA is the run clock of every test; nothing here reads the wall clock.
var nowA = time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)

const dayA = 24 * time.Hour

// agoA returns the time d before the run clock.
func agoA(d time.Duration) time.Time { return nowA.Add(-d) }

// loaderA is a fake Loader. Package data is keyed by "<eco>:<name>", deps.dev
// facts by the ref string. A key without an entry answers registry.ErrNotFound.
type loaderA struct {
	versions     map[string]*registry.VersionList
	versionsErr  map[string]error
	downloads    map[string]int64
	downloadsErr map[string]error
	depsDev      map[string]*depsdev.VersionFacts
	depsDevErr   map[string]error
	// calls records every lookup in order, so tests can assert what was fetched.
	calls []string
}

var _ Loader = (*loaderA)(nil)

func keyA(eco model.Ecosystem, name string) string { return string(eco) + ":" + name }

func (l *loaderA) Prefetch(context.Context, []model.PackageRef) {}

func (l *loaderA) Versions(_ context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error) {
	k := keyA(eco, name)
	l.calls = append(l.calls, "versions "+k)
	if err := l.versionsErr[k]; err != nil {
		return nil, err
	}
	if list, ok := l.versions[k]; ok {
		return list, nil
	}
	return nil, registry.ErrNotFound
}

func (l *loaderA) VersionInfo(_ context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	l.calls = append(l.calls, "versioninfo "+ref.String())
	return nil, registry.ErrNotFound
}

func (l *loaderA) Owners(_ context.Context, eco model.Ecosystem, name string) ([]model.Publisher, error) {
	l.calls = append(l.calls, "owners "+keyA(eco, name))
	return nil, registry.ErrNotFound
}

func (l *loaderA) Downloads(_ context.Context, eco model.Ecosystem, name string) (int64, error) {
	k := keyA(eco, name)
	l.calls = append(l.calls, "downloads "+k)
	if err := l.downloadsErr[k]; err != nil {
		return -1, err
	}
	if n, ok := l.downloads[k]; ok {
		return n, nil
	}
	return -1, registry.ErrNotFound
}

func (l *loaderA) Advisories(_ context.Context, ref model.PackageRef) ([]advisory.Advisory, error) {
	l.calls = append(l.calls, "advisories "+ref.String())
	return nil, nil
}

func (l *loaderA) DepsDev(_ context.Context, ref model.PackageRef) (*depsdev.VersionFacts, error) {
	k := ref.String()
	l.calls = append(l.calls, "depsdev "+k)
	if err := l.depsDevErr[k]; err != nil {
		return nil, err
	}
	if facts, ok := l.depsDev[k]; ok {
		return facts, nil
	}
	return &depsdev.VersionFacts{Found: false}, nil
}

func (l *loaderA) SimilarNames(_ context.Context, eco model.Ecosystem, name string) ([]depsdev.Similar, error) {
	l.calls = append(l.calls, "similar "+keyA(eco, name))
	return nil, nil
}

// versionA builds a version entry with unknown downloads.
func versionA(eco model.Ecosystem, name, ver string, publishedAt time.Time) model.VersionInfo {
	return model.VersionInfo{
		Ref:             model.PackageRef{Ecosystem: eco, Name: name, Version: ver},
		PublishedAt:     publishedAt,
		WeeklyDownloads: -1,
	}
}

// listA builds a version list in the order given, with the last entry as latest.
func listA(eco model.Ecosystem, name string, versions ...model.VersionInfo) *registry.VersionList {
	list := &registry.VersionList{Ecosystem: eco, Name: name, Versions: versions}
	if len(versions) > 0 {
		list.Latest = versions[len(versions)-1].Ref.Version
	}
	return list
}

// subjectA builds a Subject at the fixed clock with the built-in policy settings
// and an evaluated version published 30 days before the run.
func subjectA(eco model.Ecosystem, name, ver string) *Subject {
	v := versionA(eco, name, ver, agoA(30*dayA))
	return &Subject{
		Ref:       v.Ref,
		Now:       nowA,
		Settings:  (*policy.Policy)(nil).Effective(eco),
		Version:   &v,
		Downloads: -1,
	}
}

// withPreviousA attaches a previous version published 60 days before the run.
func withPreviousA(s *Subject, ver string) *model.VersionInfo {
	p := versionA(s.Ref.Ecosystem, s.Ref.Name, ver, agoA(60*dayA))
	s.Previous = &p
	return s.Previous
}

// publishersA turns names into publishers.
func publishersA(names ...string) []model.Publisher {
	out := make([]model.Publisher, 0, len(names))
	for _, n := range names {
		out = append(out, model.Publisher{Name: n})
	}
	return out
}

// unavailableA records a data source as unavailable.
func unavailableA(s *Subject, source string, err error) {
	if s.Unavailable == nil {
		s.Unavailable = map[string]error{}
	}
	s.Unavailable[source] = err
}

// outcomeA is what a test expects from a Run: a number of findings, or a skip
// whose reason contains skip.
type outcomeA struct {
	findings int
	skip     string
}

// runA runs the check with the given id and asserts the shape of the result:
// skipped entries carry the check id, findings carry the id, name and subject
// ref, and every evidence map encodes as JSON.
func runA(t *testing.T, id string, s *Subject, want outcomeA) Result {
	t.Helper()
	c, ok := Lookup(id)
	if !ok {
		t.Fatalf("check %s is not registered", id)
	}
	res := c.Run(context.Background(), s)
	if want.skip != "" {
		if res.Skipped == nil {
			t.Fatalf("%s: want skipped with reason containing %q, got %d findings", id, want.skip, len(res.Findings))
		}
		if res.Skipped.Check != id {
			t.Errorf("%s: skipped.Check = %q, want %q", id, res.Skipped.Check, id)
		}
		if !strings.Contains(res.Skipped.Reason, want.skip) {
			t.Errorf("%s: skip reason %q does not contain %q", id, res.Skipped.Reason, want.skip)
		}
		if len(res.Findings) != 0 {
			t.Errorf("%s: skipped result carries %d findings", id, len(res.Findings))
		}
		return res
	}
	if res.Skipped != nil {
		t.Fatalf("%s: unexpected skip: %s", id, res.Skipped.Reason)
	}
	if len(res.Findings) != want.findings {
		t.Fatalf("%s: got %d findings, want %d: %+v", id, len(res.Findings), want.findings, res.Findings)
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.ID != id || f.Name != c.Name() {
			t.Errorf("%s: finding has id %q name %q, want %q %q", id, f.ID, f.Name, id, c.Name())
		}
		if f.Ref != s.Ref {
			t.Errorf("%s: finding ref = %s, want %s", id, f.Ref, s.Ref)
		}
		if f.Title == "" || f.Explanation == "" {
			t.Errorf("%s: finding without title or explanation: %+v", id, f)
		}
		if strings.ContainsAny(f.Title+f.Explanation, "–—") {
			t.Errorf("%s: finding text contains a dash character: %q", id, f.Title+" "+f.Explanation)
		}
		if _, err := json.Marshal(f.Evidence); err != nil {
			t.Errorf("%s: evidence does not encode as JSON: %v", id, err)
		}
	}
	return res
}

// wantTextA asserts that text contains every fragment.
func wantTextA(t *testing.T, what, text string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(text, fragment) {
			t.Errorf("%s %q does not contain %q", what, text, fragment)
		}
	}
}

// stringsA returns an evidence value that must be a []string.
func stringsA(t *testing.T, evidence map[string]any, key string) []string {
	t.Helper()
	v, ok := evidence[key]
	if !ok {
		t.Fatalf("evidence has no %q key: %v", key, evidence)
	}
	out, ok := v.([]string)
	if !ok {
		t.Fatalf("evidence[%q] is %T, want []string", key, v)
	}
	return out
}

// equalA compares two string slices.
func equalA(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestChecksTD001ToTD007Registered(t *testing.T) {
	tests := []struct {
		id         string
		name       string
		level      model.Level
		ecosystems []model.Ecosystem
	}{
		{"TD001", "young-version", model.LevelWarn, nil},
		{"TD002", "publisher-changed", model.LevelBlock, []model.Ecosystem{model.NPM, model.PyPI, model.Cargo}},
		{"TD003", "maintainers-changed", model.LevelWarn, nil},
		{"TD004", "trust-downgrade", model.LevelBlock, []model.Ecosystem{model.NPM, model.PyPI, model.Cargo}},
		{"TD005", "install-script-introduced", model.LevelBlock, []model.Ecosystem{model.NPM}},
		{"TD006", "install-script-present", model.LevelWarn, nil},
		{"TD007", "new-dependency-introduced", model.LevelWarn, nil},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			c, ok := Lookup(tt.id)
			if !ok {
				t.Fatalf("Lookup(%s) found nothing", tt.id)
			}
			if c.Name() != tt.name {
				t.Errorf("Name() = %q, want %q", c.Name(), tt.name)
			}
			if byName, ok := Lookup(tt.name); !ok || byName.ID() != tt.id {
				t.Errorf("Lookup(%s) did not return %s", tt.name, tt.id)
			}
			if setting, ok := policy.DefaultCheck(tt.name); !ok || setting.Level != tt.level {
				t.Errorf("policy default for %s = %v, want level %s", tt.name, setting, tt.level)
			}
			got := c.Ecosystems()
			if len(got) != len(tt.ecosystems) {
				t.Fatalf("Ecosystems() = %v, want %v", got, tt.ecosystems)
			}
			for i := range got {
				if got[i] != tt.ecosystems[i] {
					t.Errorf("Ecosystems() = %v, want %v", got, tt.ecosystems)
				}
			}
			for _, eco := range model.Ecosystems() {
				want := len(tt.ecosystems) == 0
				for _, e := range tt.ecosystems {
					if e == eco {
						want = true
					}
				}
				if AppliesTo(c, eco) != want {
					t.Errorf("AppliesTo(%s) = %v, want %v", eco, !want, want)
				}
			}
		})
	}
}
