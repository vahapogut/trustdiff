package checks

// Shared fixtures for the tests of the two checks that judge the lockfile entry
// rather than the registry, TD013 and TD014: a subject built around a
// lockfile.Entry, entry builders per source, and assertions on a Result. Every
// identifier carries a C suffix so the file coexists with the helpers of the other
// check tests in this package.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

// nowC is the clock every subject built here runs with; nothing reads the wall clock.
var nowC = time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)

// pinnedShaC is a full commit sha, as a git source writes one.
const pinnedShaC = "3f7b9c1d2e4a5b6c7d8e9f0a1b2c3d4e5f60718a"

// entryC builds a lockfile entry for a ref with the given source. The options fill
// in the rest of the fields.
func entryC(t *testing.T, ref string, source lockfile.Source, opts ...func(*lockfile.Entry)) *lockfile.Entry {
	t.Helper()
	e := &lockfile.Entry{Ref: model.MustParseRef(ref), Source: source, Line: 12}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// resolvedC sets the location the lockfile records for the entry.
func resolvedC(resolved string) func(*lockfile.Entry) {
	return func(e *lockfile.Entry) { e.Resolved = resolved }
}

// integrityC sets the hash the lockfile records for the entry.
func integrityC(integrity string) func(*lockfile.Entry) {
	return func(e *lockfile.Entry) { e.Integrity = integrity }
}

// subjectC builds a subject for ref at the fixed clock with the built-in policy for
// its ecosystem, the lockfile entry the checks read, and the location the runner
// puts on a subject that came from a lockfile. A nil entry is the ref named on the
// command line, and then there is no location either.
func subjectC(t *testing.T, ref string, entry *lockfile.Entry, opts ...func(*Subject)) *Subject {
	t.Helper()
	parsed := model.MustParseRef(ref)
	s := &Subject{
		Ref:         parsed,
		Now:         nowC,
		Settings:    (*policy.Policy)(nil).Effective(parsed.Ecosystem),
		Lock:        entry,
		Downloads:   -1,
		Unavailable: map[string]error{},
	}
	if entry != nil {
		s.Location = &model.Location{Path: lockfileNameC(parsed.Ecosystem), Line: entry.Line}
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// lockfileNameC names the lockfile an ecosystem's entries come from, so the paths
// in the assertions are the ones a reader would recognize.
func lockfileNameC(eco model.Ecosystem) string {
	switch eco {
	case model.PyPI:
		return "uv.lock"
	case model.Cargo:
		return "Cargo.lock"
	default:
		return "package-lock.json"
	}
}

// withoutLocationC drops the subject's location, which is how a lockfile entry
// reaches a check when the parser could not place it.
func withoutLocationC(s *Subject) { s.Location = nil }

// withSettingC overrides the policy setting of one check.
func withSettingC(name string, setting policy.CheckSetting) func(*Subject) {
	return func(s *Subject) {
		checks := make(map[string]policy.CheckSetting, len(s.Settings.Checks)+1)
		for k, v := range s.Settings.Checks {
			checks[k] = v
		}
		checks[name] = setting
		s.Settings.Checks = checks
	}
}

// resultC runs a check on a subject and asserts that it consulted no data source:
// these two checks read the lockfile entry alone, and a nil Loader proves it.
func resultC(t *testing.T, c Check, s *Subject) Result {
	t.Helper()
	if s.Loader != nil {
		t.Fatalf("%s: the subject carries a loader; these checks must work without one", c.ID())
	}
	return c.Run(context.Background(), s)
}

// assertSkippedC asserts that the result is skipped with a reason containing want.
func assertSkippedC(t *testing.T, c Check, res Result, want string) {
	t.Helper()
	if res.Skipped == nil {
		t.Fatalf("%s: want skipped, got %d findings", c.ID(), len(res.Findings))
	}
	if res.Skipped.Check != c.ID() {
		t.Errorf("%s: skipped.check = %q, want the check id %q", c.ID(), res.Skipped.Check, c.ID())
	}
	if !strings.Contains(res.Skipped.Reason, want) {
		t.Errorf("%s: skipped reason %q does not contain %q", c.ID(), res.Skipped.Reason, want)
	}
	if len(res.Findings) != 0 {
		t.Errorf("%s: skipped result carries %d findings", c.ID(), len(res.Findings))
	}
}

// assertFindingsC asserts that the check ran and produced exactly n findings, each
// with the check's identity, the subject's ref, the effective level, the subject's
// location and prose free of the dashes the style rules keep out.
func assertFindingsC(t *testing.T, c Check, s *Subject, res Result, n int) {
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
		if f.Location != s.Location {
			t.Errorf("finding %d: location %v, want %v", i, f.Location, s.Location)
		}
		if f.Title == "" || f.Explanation == "" {
			t.Errorf("finding %d: empty title or explanation: %+v", i, f)
		}
		if strings.ContainsAny(f.Title+f.Explanation, "–—") {
			t.Errorf("finding %d: prose contains a dash character: %q", i, f.Title+" "+f.Explanation)
		}
	}
}

// evidenceC returns an evidence value as a string; a missing key fails the test.
func evidenceC(t *testing.T, f *model.Finding, key string) string {
	t.Helper()
	v, ok := f.Evidence[key]
	if !ok {
		t.Fatalf("evidence has no key %q: %v", key, f.Evidence)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("evidence[%q] is %T, want a string", key, v)
	}
	return s
}

// assertNoEvidenceC asserts that an evidence key is absent.
func assertNoEvidenceC(t *testing.T, f *model.Finding, key string) {
	t.Helper()
	if v, ok := f.Evidence[key]; ok {
		t.Errorf("evidence has key %q = %v, want it absent", key, v)
	}
}

// assertContainsC asserts that text contains every one of the wanted substrings.
func assertContainsC(t *testing.T, what, text string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("%s %q does not contain %q", what, text, w)
		}
	}
}
