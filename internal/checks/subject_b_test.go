package checks

// Shared fixtures for the TD009 to TD012 and TD015 tests: a fake Loader that
// records every call, a Subject builder with a fixed clock and the built-in
// policy, a version list builder with fixed publish times, and assertions on a
// Result. Every identifier carries a B suffix so the file coexists with the
// helpers of the other check tests in this package.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// nowB is the clock every subject built here runs with.
var nowB = time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)

// epochB is the publish time of "day 0"; dayB counts from it.
var epochB = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// dayB returns a fixed publish time n days after epochB.
func dayB(n int) time.Time { return epochB.AddDate(0, 0, n) }

// errLoaderB is what loaderB returns for a source it was told is down.
var errLoaderB = errors.New("fake loader: source down")

// loaderB is a fake Loader backed by maps. It records every call in calls so a
// test can assert that a check never fetched anything on its own; the checks in
// this file group work from the Subject alone.
type loaderB struct {
	calls      []string
	versions   map[string]*registry.VersionList
	infos      map[model.PackageRef]*model.VersionInfo
	owners     map[string][]model.Publisher
	downloads  map[string]int64
	advisories map[model.PackageRef][]advisory.Advisory
	facts      map[model.PackageRef]*depsdev.VersionFacts
	similar    map[string][]depsdev.Similar
	// down lists the source names (SourceRegistry and so on) whose methods fail.
	down map[string]bool
}

var _ Loader = (*loaderB)(nil)

func keyB(eco model.Ecosystem, name string) string { return string(eco) + ":" + name }

func (l *loaderB) record(call string) { l.calls = append(l.calls, call) }

func (l *loaderB) Prefetch(_ context.Context, refs []model.PackageRef) {
	l.record(fmt.Sprintf("Prefetch(%d)", len(refs)))
}

func (l *loaderB) Versions(_ context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error) {
	l.record("Versions(" + keyB(eco, name) + ")")
	if l.down[SourceRegistry] {
		return nil, errLoaderB
	}
	if list, ok := l.versions[keyB(eco, name)]; ok {
		return list, nil
	}
	return nil, registry.ErrNotFound
}

func (l *loaderB) VersionInfo(_ context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	l.record("VersionInfo(" + ref.String() + ")")
	if l.down[SourceRegistry] {
		return nil, errLoaderB
	}
	if info, ok := l.infos[ref]; ok {
		return info, nil
	}
	return nil, registry.ErrNotFound
}

func (l *loaderB) Owners(_ context.Context, eco model.Ecosystem, name string) ([]model.Publisher, error) {
	l.record("Owners(" + keyB(eco, name) + ")")
	if l.down[SourceOwners] {
		return nil, errLoaderB
	}
	return l.owners[keyB(eco, name)], nil
}

func (l *loaderB) Downloads(_ context.Context, eco model.Ecosystem, name string) (int64, error) {
	l.record("Downloads(" + keyB(eco, name) + ")")
	if l.down[SourceDownloads] {
		return -1, errLoaderB
	}
	if n, ok := l.downloads[keyB(eco, name)]; ok {
		return n, nil
	}
	return -1, registry.ErrUnsupported
}

func (l *loaderB) Advisories(_ context.Context, ref model.PackageRef) ([]advisory.Advisory, error) {
	l.record("Advisories(" + ref.String() + ")")
	if l.down[SourceOSV] {
		return nil, errLoaderB
	}
	return l.advisories[ref], nil
}

func (l *loaderB) DepsDev(_ context.Context, ref model.PackageRef) (*depsdev.VersionFacts, error) {
	l.record("DepsDev(" + ref.String() + ")")
	if l.down[SourceDepsDev] {
		return nil, errLoaderB
	}
	if facts, ok := l.facts[ref]; ok {
		return facts, nil
	}
	return nil, depsdev.ErrUnsupported
}

func (l *loaderB) SimilarNames(_ context.Context, eco model.Ecosystem, name string) ([]depsdev.Similar, error) {
	l.record("SimilarNames(" + keyB(eco, name) + ")")
	if l.down[SourceDepsDev] {
		return nil, errLoaderB
	}
	return l.similar[keyB(eco, name)], nil
}

// releaseB describes one version of a package for packageB.
type releaseB struct {
	Version    string
	Published  time.Time
	Prerelease bool
	Yanked     bool
	Deprecated string
}

// packageB builds a version list the way a registry client would fill it.
func packageB(eco model.Ecosystem, name string, releases ...releaseB) *registry.VersionList {
	list := &registry.VersionList{Ecosystem: eco, Name: name}
	for _, r := range releases {
		list.Versions = append(list.Versions, model.VersionInfo{
			Ref:             model.PackageRef{Ecosystem: eco, Name: name, Version: r.Version},
			PublishedAt:     r.Published,
			Prerelease:      r.Prerelease,
			Yanked:          r.Yanked,
			Deprecated:      r.Deprecated,
			WeeklyDownloads: -1,
		})
	}
	return list
}

// subjectB builds a subject for ref with the fixed clock, the built-in policy
// for its ecosystem, unknown downloads and a recording fake loader. Options
// fill in the rest.
func subjectB(t *testing.T, ref string, opts ...func(*Subject)) *Subject {
	t.Helper()
	parsed := model.MustParseRef(ref)
	s := &Subject{
		Ref:         parsed,
		Now:         nowB,
		Settings:    (*policy.Policy)(nil).Effective(parsed.Ecosystem),
		Downloads:   -1,
		Unavailable: map[string]error{},
		Loader:      &loaderB{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// withPackageB attaches a version list and derives Version and Previous from it
// the way the runner does.
func withPackageB(list *registry.VersionList) func(*Subject) {
	return func(s *Subject) {
		s.Package = list
		s.Version = registry.Find(list, s.Ref.Version)
		s.Previous = registry.Previous(list, s.Ref)
	}
}

// withVersionB sets the evaluated version's details without a version list.
func withVersionB(v *model.VersionInfo) func(*Subject) {
	return func(s *Subject) { s.Version = v }
}

// withUnavailableB marks a data source as unavailable with the given reason.
func withUnavailableB(source, reason string) func(*Subject) {
	return func(s *Subject) { s.Unavailable[source] = errors.New(reason) }
}

// withAdvisoriesB sets the OSV advisories.
func withAdvisoriesB(advisories ...advisory.Advisory) func(*Subject) {
	return func(s *Subject) { s.Advisories = advisories }
}

// withDepsDevB sets the deps.dev facts and findings.
func withDepsDevB(facts *depsdev.VersionFacts, findings ...depsdev.Finding) func(*Subject) {
	return func(s *Subject) {
		s.DepsDev = facts
		s.DepsDevFindings = findings
	}
}

// withDownloadsB sets the weekly download count.
func withDownloadsB(n int64) func(*Subject) {
	return func(s *Subject) { s.Downloads = n }
}

// withSettingB overrides the policy setting of one check.
func withSettingB(name string, setting policy.CheckSetting) func(*Subject) {
	return func(s *Subject) {
		checks := make(map[string]policy.CheckSetting, len(s.Settings.Checks)+1)
		for k, v := range s.Settings.Checks {
			checks[k] = v
		}
		checks[name] = setting
		s.Settings.Checks = checks
	}
}

// resultB runs a check on a subject and asserts that the loader was never called.
func resultB(t *testing.T, c Check, s *Subject) Result {
	t.Helper()
	res := c.Run(context.Background(), s)
	if l, ok := s.Loader.(*loaderB); ok && len(l.calls) > 0 {
		t.Errorf("%s called the loader: %v", c.ID(), l.calls)
	}
	return res
}

// assertSkippedB asserts that the result is skipped with a reason containing want.
func assertSkippedB(t *testing.T, c Check, res Result, want string) {
	t.Helper()
	if res.Skipped == nil {
		t.Fatalf("%s: want skipped, got %d findings", c.ID(), len(res.Findings))
	}
	if res.Skipped.Check != c.Name() {
		t.Errorf("%s: skipped.check = %q, want %q", c.ID(), res.Skipped.Check, c.Name())
	}
	if !strings.Contains(res.Skipped.Reason, want) {
		t.Errorf("%s: skipped reason %q does not contain %q", c.ID(), res.Skipped.Reason, want)
	}
	if len(res.Findings) != 0 {
		t.Errorf("%s: skipped result carries %d findings", c.ID(), len(res.Findings))
	}
}

// assertFindingsB asserts that the check ran and produced exactly n findings, each
// with the check's identity, the subject's ref and the effective level.
func assertFindingsB(t *testing.T, c Check, s *Subject, res Result, n int) {
	t.Helper()
	if res.Skipped != nil {
		t.Fatalf("%s: want %d findings, got skipped: %s", c.ID(), n, res.Skipped.Reason)
	}
	if len(res.Findings) != n {
		t.Fatalf("%s: want %d findings, got %d: %+v", c.ID(), n, len(res.Findings), res.Findings)
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.ID != c.ID() || f.Name != c.Name() {
			t.Errorf("finding %d: identity %s/%s, want %s/%s", i, f.ID, f.Name, c.ID(), c.Name())
		}
		if f.Ref != s.Ref {
			t.Errorf("finding %d: ref %s, want %s", i, f.Ref, s.Ref)
		}
		if want := s.Setting(c.Name()).Level; f.Level != want {
			t.Errorf("finding %d: level %s, want %s", i, f.Level, want)
		}
		if f.Title == "" || f.Explanation == "" {
			t.Errorf("finding %d: empty title or explanation: %+v", i, f)
		}
	}
}

// evidenceB returns an evidence value as a string for assertions; nested values are
// rendered with %v. Missing keys fail the test.
func evidenceB(t *testing.T, f *model.Finding, key string) string {
	t.Helper()
	v, ok := f.Evidence[key]
	if !ok {
		t.Fatalf("evidence has no key %q: %v", key, f.Evidence)
	}
	return fmt.Sprint(v)
}

// assertNoEvidenceB asserts that an evidence key is absent.
func assertNoEvidenceB(t *testing.T, f *model.Finding, key string) {
	t.Helper()
	if v, ok := f.Evidence[key]; ok {
		t.Errorf("evidence has key %q = %v, want it absent", key, v)
	}
}

// assertContainsB asserts that text contains every one of the wanted substrings.
func assertContainsB(t *testing.T, what, text string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("%s %q does not contain %q", what, text, w)
		}
	}
}
