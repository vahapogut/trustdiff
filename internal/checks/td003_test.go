package checks

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/baseline"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Helpers for the checks that read the project's baseline, TD002 and TD003. The T
// suffix keeps the names apart from the other helpers of this package's tests.

// baselineLoaderT is a Loader that serves nothing but the baseline. The embedded
// interface is nil on purpose: a check that reached for a registry answer through
// it would panic here rather than quietly read a zero value.
type baselineLoaderT struct {
	Loader
	set baseline.Set
}

func (l baselineLoaderT) Baseline(ref model.PackageRef) (baseline.Record, bool) {
	return l.set.Lookup(ref)
}

// fileT builds a baseline file holding the entries, stamped with the run clock.
func fileT(entries ...*baseline.Entry) *baseline.File {
	f := baseline.New(nowA)
	for _, e := range entries {
		f.Put(e)
	}
	return f
}

// withBaselineT gives the subject a baseline holding the entries, the way a run
// in a working tree sees one.
func withBaselineT(s *Subject, entries ...*baseline.Entry) *Subject {
	s.Loader = baselineLoaderT{set: baseline.Set{Head: fileT(entries...)}}
	return s
}

// withRewrittenBaselineT gives the subject the two sides a diff sees: what the
// working tree holds and what the base revision held.
func withRewrittenBaselineT(s *Subject, head, base []*baseline.Entry) *Subject {
	s.Loader = baselineLoaderT{set: baseline.Set{Head: fileT(head...), Base: fileT(base...)}}
	return s
}

// entryT builds a baseline entry for a ref, observed daysAgo days before the run
// clock, recording the maintainer set.
func entryT(ref string, daysAgo int, maintainers ...string) *baseline.Entry {
	r := model.MustParseRef(ref)
	return &baseline.Entry{
		Ecosystem:   r.Ecosystem,
		Name:        r.Name,
		Version:     r.Version,
		ObservedAt:  agoA(time.Duration(daysAgo) * dayA),
		Maintainers: maintainers,
	}
}

// publishedByT records a publishing identity on an entry, from the given source.
func publishedByT(e *baseline.Entry, identity string, source baseline.PublisherSource) *baseline.Entry {
	e.Publisher, e.PublisherSource = identity, source
	return e
}

func TestTD003MaintainersChanged(t *testing.T) {
	tests := []struct {
		name     string
		subject  func() *Subject
		want     outcomeA
		added    []string
		removed  []string
		title    string
		text     []string
		evidence map[string][]string
	}{
		{
			name: "fires on an addition and a removal",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.Maintainers = publishersA("carol", "bob-ci")
				withPreviousA(s, "1.2.0").Maintainers = publishersA("alice", "carol")
				return s
			},
			want:    outcomeA{findings: 1},
			added:   []string{"bob-ci"},
			removed: []string{"alice"},
			title:   "Maintainers changed since 1.2.0: added bob-ci, removed alice",
			text:    []string{"1.2.0 listed alice and carol as maintainers", "1.3.0 lists bob-ci and carol", "added bob-ci and removed alice"},
			evidence: map[string][]string{
				"previous_maintainers": {"alice", "carol"},
				"maintainers":          {"bob-ci", "carol"},
			},
		},
		{
			name: "fires on an addition alone",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.Maintainers = publishersA("alice", "bob-ci")
				withPreviousA(s, "1.2.0").Maintainers = publishersA("alice")
				return s
			},
			want:    outcomeA{findings: 1},
			added:   []string{"bob-ci"},
			removed: []string{},
			title:   "Maintainers changed since 1.2.0: added bob-ci",
			text:    []string{"1.2.0 listed alice as maintainer;"},
		},
		{
			name: "fires on a removal alone",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.Maintainers = publishersA("alice")
				withPreviousA(s, "1.2.0").Maintainers = publishersA("alice", "dave", "carol")
				return s
			},
			want:    outcomeA{findings: 1},
			added:   []string{},
			removed: []string{"carol", "dave"},
			title:   "Maintainers changed since 1.2.0: removed carol and dave",
		},
		{
			name: "does not fire for the same set in another order or case",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.Maintainers = publishersA("Carol", "alice")
				withPreviousA(s, "1.2.0").Maintainers = publishersA("alice", "carol")
				return s
			},
			want: outcomeA{},
		},
		{
			name: "the registry way wins for npm even when a baseline exists",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.Maintainers = publishersA("alice", "bob-ci")
				withPreviousA(s, "1.2.0").Maintainers = publishersA("alice")
				s.Owners = publishersA("alice", "bob-ci")
				return withBaselineT(s, entryT("npm:lib@1.3.0", 2, "alice", "bob-ci"))
			},
			want:    outcomeA{findings: 1},
			added:   []string{"bob-ci"},
			removed: []string{},
			title:   "Maintainers changed since 1.2.0: added bob-ci",
		},
		{
			name: "skipped for pypi without a baseline",
			subject: func() *Subject {
				s := subjectA(model.PyPI, "requests", "2.32.0")
				s.Version.Maintainers = publishersA("alice")
				withPreviousA(s, "2.31.0").Maintainers = publishersA("bob-ci")
				return s
			},
			want: outcomeA{skip: "pypi records no maintainer set per version; the run read no baseline"},
		},
		{
			name: "skipped for cargo when the baseline holds no entry",
			subject: func() *Subject {
				s := subjectA(model.Cargo, "serde", "1.0.200")
				s.Owners = publishersA("alice")
				return withBaselineT(s, entryT("cargo:other@1.0.0", 1, "alice"))
			},
			want: outcomeA{skip: "no baseline entry for cargo:serde (record one with trustdiff baseline)"},
		},
		{
			name: "skipped when the baseline entry records no maintainer set",
			subject: func() *Subject {
				s := subjectA(model.PyPI, "requests", "2.32.0")
				s.Owners = publishersA("alice")
				return withBaselineT(s, entryT("pypi:requests@2.31.0", 10))
			},
			want: outcomeA{skip: "the baseline entry for pypi:requests records no maintainer set"},
		},
		{
			name: "skipped with the registry's reason when the owner set is unavailable",
			subject: func() *Subject {
				s := subjectA(model.Cargo, "serde", "1.0.200")
				unavailableA(s, SourceOwners, errors.New("boom"))
				return withBaselineT(s, entryT("cargo:serde@1.0.199", 5, "alice"))
			},
			want: outcomeA{skip: "owners unavailable: boom"},
		},
		{
			name: "skipped without a previous version",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.0.0")
				s.Version.Maintainers = publishersA("alice")
				return s
			},
			want: outcomeA{skip: "no earlier release"},
		},
		{
			name: "skipped when the evaluated version records no maintainers",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				withPreviousA(s, "1.2.0").Maintainers = publishersA("alice")
				return s
			},
			want: outcomeA{skip: "no maintainer set recorded for 1.3.0"},
		},
		{
			name: "skipped when the previous version records no maintainers",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.Maintainers = publishersA("alice")
				withPreviousA(s, "1.2.0")
				return s
			},
			want: outcomeA{skip: "no maintainer set recorded for the previous version 1.2.0"},
		},
		{
			name: "skipped when the version details are missing",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version = nil
				return s
			},
			want: outcomeA{skip: "version details unavailable"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runA(t, "TD003", tt.subject(), tt.want)
			if len(res.Findings) == 0 {
				return
			}
			f := res.Findings[0]
			if f.Level != model.LevelWarn {
				t.Errorf("level = %s, want warn", f.Level)
			}
			if got := stringsA(t, f.Evidence, "added"); !equalA(got, tt.added) {
				t.Errorf("added = %v, want %v", got, tt.added)
			}
			if got := stringsA(t, f.Evidence, "removed"); !equalA(got, tt.removed) {
				t.Errorf("removed = %v, want %v", got, tt.removed)
			}
			if got := f.Evidence["previous_version"]; got != "1.2.0" {
				t.Errorf("previous_version = %v, want 1.2.0", got)
			}
			for key, want := range tt.evidence {
				if got := stringsA(t, f.Evidence, key); !equalA(got, want) {
					t.Errorf("%s = %v, want %v", key, got, want)
				}
			}
			if f.Title != tt.title {
				t.Errorf("title = %q, want %q", f.Title, tt.title)
			}
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}

// crates.io keeps no maintainer history, so the baseline is the only thing that
// can answer for it. The finding says how old the record is and that the locked
// version never moved, which is the case no comparison of two releases can see.
func TestTD003FromTheBaselineForCargo(t *testing.T) {
	s := subjectA(model.Cargo, "serde", "1.0.200")
	s.Owners = publishersA("alice", "mallory")
	withBaselineT(s, entryT("cargo:serde@1.0.200", 12, "alice", "bob-ci"))

	f := runA(t, "TD003", s, outcomeA{findings: 1}).Findings[0]
	if f.Title != "Maintainers changed since the baseline: added mallory, removed bob-ci" {
		t.Errorf("title = %q", f.Title)
	}
	wantTextA(t, "explanation", f.Explanation,
		"the baseline recorded alice and bob-ci as maintainers of cargo:serde when 1.0.200 was observed, 12 days ago",
		"the registry lists alice and mallory now",
		"the locked version did not move")
	if got := stringsA(t, f.Evidence, "baseline_maintainers"); !equalA(got, []string{"alice", "bob-ci"}) {
		t.Errorf("baseline_maintainers = %v", got)
	}
	if got := stringsA(t, f.Evidence, "added"); !equalA(got, []string{"mallory"}) {
		t.Errorf("added = %v", got)
	}
	if f.Evidence["baseline_version"] != "1.0.200" || f.Evidence["baseline_age_days"] != 12 {
		t.Errorf("evidence = %v, want the record's version and age", f.Evidence)
	}
	if f.Evidence["baseline_observed_at"] != whenText(agoA(12*dayA)) {
		t.Errorf("baseline_observed_at = %v", f.Evidence["baseline_observed_at"])
	}
	if _, rewritten := f.Evidence["baseline_rewritten"]; rewritten {
		t.Errorf("evidence claims a rewrite where nothing was rewritten: %v", f.Evidence)
	}
}

// The same owner set is a pass, whatever the order and the case a registry
// answers in.
func TestTD003BaselineAgreesWithTheRegistry(t *testing.T) {
	s := subjectA(model.PyPI, "requests", "2.32.0")
	s.Owners = publishersA("Lukasa", "nateprewitt")
	withBaselineT(s, entryT("pypi:requests@2.31.0", 3, "nateprewitt", "lukasa"))
	runA(t, "TD003", s, outcomeA{})
}

// A record older than the window a project refreshes in still answers, and the
// finding says so instead of pretending to know when the change happened.
func TestTD003StaleBaselineStillAnswers(t *testing.T) {
	s := subjectA(model.PyPI, "requests", "2.32.0")
	s.Owners = publishersA("alice", "mallory")
	withBaselineT(s, entryT("pypi:requests@2.31.0", 200, "alice"))

	f := runA(t, "TD003", s, outcomeA{findings: 1}).Findings[0]
	wantTextA(t, "explanation", f.Explanation, "200 days ago", "longer ago than a baseline is meant to go unrefreshed")
	if f.Evidence["baseline_age_days"] != 200 {
		t.Errorf("baseline_age_days = %v, want 200", f.Evidence["baseline_age_days"])
	}
}

// Rewriting the record of who used to maintain a package is what an attacker with
// commit access would do, so the record the base revision holds is what the check
// compares with, and the rewrite is reported as evidence.
func TestTD003ComparesTheBaseRevisionWhenTheChangeRewroteTheEntry(t *testing.T) {
	s := subjectA(model.PyPI, "requests", "2.32.0")
	s.Owners = publishersA("alice", "mallory")
	withRewrittenBaselineT(s,
		[]*baseline.Entry{entryT("pypi:requests@2.32.0", 0, "alice", "mallory")},
		[]*baseline.Entry{entryT("pypi:requests@2.31.0", 30, "alice")})

	f := runA(t, "TD003", s, outcomeA{findings: 1}).Findings[0]
	if got := stringsA(t, f.Evidence, "added"); !equalA(got, []string{"mallory"}) {
		t.Errorf("added = %v, want mallory: the base revision's record must be the one compared", got)
	}
	if f.Evidence["baseline_rewritten"] != true {
		t.Errorf("evidence = %v, want baseline_rewritten", f.Evidence)
	}
	if got := stringsA(t, f.Evidence, "baseline_rewritten_maintainers"); !equalA(got, []string{"alice", "mallory"}) {
		t.Errorf("baseline_rewritten_maintainers = %v", got)
	}
	wantTextA(t, "explanation", f.Explanation, "the change under review rewrote this package's baseline entry, which now records alice and mallory")
}

// Deleting the entry is the same attack with a bigger eraser, and it is answered
// the same way.
func TestTD003ComparesTheBaseRevisionWhenTheChangeDeletedTheEntry(t *testing.T) {
	s := subjectA(model.Cargo, "serde", "1.0.200")
	s.Owners = publishersA("mallory")
	withRewrittenBaselineT(s, nil, []*baseline.Entry{entryT("cargo:serde@1.0.200", 5, "alice")})

	f := runA(t, "TD003", s, outcomeA{findings: 1}).Findings[0]
	if f.Evidence["baseline_deleted"] != true || f.Evidence["baseline_rewritten"] != true {
		t.Errorf("evidence = %v, want the deletion reported", f.Evidence)
	}
	wantTextA(t, "explanation", f.Explanation, "the change under review deleted this package's baseline entry")
}

// A record that was only observed again, so nothing but its timestamp moved, is
// not a rewrite and must not be reported as one.
func TestTD003ReobservationIsNotARewrite(t *testing.T) {
	s := subjectA(model.Cargo, "serde", "1.0.200")
	s.Owners = publishersA("alice", "mallory")
	withRewrittenBaselineT(s,
		[]*baseline.Entry{entryT("cargo:serde@1.0.200", 0, "alice")},
		[]*baseline.Entry{entryT("cargo:serde@1.0.200", 40, "alice")})

	f := runA(t, "TD003", s, outcomeA{findings: 1}).Findings[0]
	if _, rewritten := f.Evidence["baseline_rewritten"]; rewritten {
		t.Errorf("evidence = %v, want no rewrite for a record that was only observed again", f.Evidence)
	}
	if f.Evidence["baseline_age_days"] != 0 {
		t.Errorf("baseline_age_days = %v, want the working tree's fresher record", f.Evidence["baseline_age_days"])
	}
}

// An entry the change under review invented answers nothing. The base revision
// records nothing for the package, so the only record there is says what whoever
// wrote the change wanted it to say, and a check that read it as an observation
// would answer a takeover with the pass the takeover supplied.
func TestTD003SkipsAnEntryTheChangeAdded(t *testing.T) {
	s := subjectA(model.Cargo, "serde", "1.0.200")
	s.Owners = publishersA("mallory")
	withRewrittenBaselineT(s, []*baseline.Entry{entryT("cargo:serde@1.0.200", 0, "mallory")}, nil)
	runA(t, "TD003", s, outcomeA{skip: "the change under review added the baseline entry for cargo:serde"})

	// A run that compares against no revision is not that case: the working tree's
	// record is the only one there has ever been, and it still answers.
	scan := subjectA(model.Cargo, "serde", "1.0.200")
	scan.Owners = publishersA("mallory")
	withBaselineT(scan, entryT("cargo:serde@1.0.200", 5, "alice"))
	runA(t, "TD003", scan, outcomeA{findings: 1})
}

// A rewritten entry that names nobody is reported as an empty list and never as
// null, the way added and removed are, so that a reader can tell a record which
// claims nobody from one which claims nothing.
func TestTD003RewrittenMaintainersAreNeverNull(t *testing.T) {
	s := subjectA(model.PyPI, "requests", "2.32.0")
	s.Owners = publishersA("alice", "mallory")
	// The change kept the entry and emptied its maintainer set, which is the
	// quietest way to rewrite it.
	withRewrittenBaselineT(s,
		[]*baseline.Entry{entryT("pypi:requests@2.32.0", 0)},
		[]*baseline.Entry{entryT("pypi:requests@2.31.0", 30, "alice")})

	f := runA(t, "TD003", s, outcomeA{findings: 1}).Findings[0]
	claimed, ok := f.Evidence["baseline_rewritten_maintainers"]
	if !ok {
		t.Fatalf("evidence = %v, want what the rewritten record claims", f.Evidence)
	}
	data, err := json.Marshal(claimed)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "[]" {
		t.Errorf("baseline_rewritten_maintainers = %s, want an empty list: null cannot be told from a record that claims nothing", data)
	}
	wantTextA(t, "explanation", f.Explanation, "which now records no maintainer")
}

// The check never passes on missing data: every way of not being able to answer
// ends as a skip whose reason names both the registry and the baseline.
func TestTD003SkipNamesBothWays(t *testing.T) {
	s := withBaselineT(subjectA(model.PyPI, "requests", "2.32.0"))
	res := runA(t, "TD003", s, outcomeA{skip: "no baseline entry"})
	if !strings.Contains(res.Skipped.Reason, "pypi records no maintainer set per version") {
		t.Errorf("reason = %q, want the registry's half too", res.Skipped.Reason)
	}
	// A run that read no baseline at all says that instead, so a project without
	// one is not told to look for an entry in a file it does not have.
	none := runA(t, "TD003", subjectA(model.PyPI, "requests", "2.32.0"), outcomeA{skip: "the run read no baseline"})
	if strings.Contains(none.Skipped.Reason, "no baseline entry") {
		t.Errorf("reason = %q, want no mention of a missing entry", none.Skipped.Reason)
	}
}
