package baseline

import (
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// now is the clock every test in this package uses; nothing here reads the wall
// clock, so a run in June and a run in December write the same bytes.
var now = time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// ago returns the time d before the test clock.
func ago(d time.Duration) time.Time { return now.Add(-d) }

// entry builds an entry for a ref, observed d before the test clock.
func entry(ref string, d time.Duration, maintainers ...string) Entry {
	r := model.MustParseRef(ref)
	return Entry{
		Ecosystem:   r.Ecosystem,
		Name:        r.Name,
		Version:     r.Version,
		ObservedAt:  ago(d),
		Maintainers: maintainers,
	}
}

// file builds a baseline holding the entries.
func file(entries ...Entry) *File {
	f := New(now)
	for i := range entries {
		f.Put(&entries[i])
	}
	return f
}

func TestPutSortsAndReplaces(t *testing.T) {
	f := file(
		entry("pypi:requests@2.32.3", day, "lukasa"),
		entry("npm:express@4.19.2", day, "dougwilson"),
		entry("cargo:serde@1.0.200", day, "dtolnay"),
	)
	bumped := entry("npm:express@4.20.0", 0, "dougwilson", "wesleytodd")
	f.Put(&bumped)

	got := make([]string, 0, len(f.Packages))
	for i := range f.Packages {
		got = append(got, f.Packages[i].Ref().String())
	}
	want := []string{"cargo:serde@1.0.200", "npm:express@4.20.0", "pypi:requests@2.32.3"}
	if len(got) != len(want) {
		t.Fatalf("packages = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("packages = %v, want %v", got, want)
		}
	}
}

func TestPutNormalizesTheEntry(t *testing.T) {
	f := New(now)
	f.Put(&Entry{
		Ecosystem:   model.PyPI,
		Name:        "Zope.Interface",
		Version:     "6.0",
		ObservedAt:  time.Date(2026, time.September, 9, 12, 0, 0, 500, time.FixedZone("CET", 3600)),
		Maintainers: []string{"carol", "", "Alice", "alice", "bob"},
	})
	e := f.Packages[0]
	if e.Name != "zope-interface" {
		t.Errorf("name = %q, want the PEP 503 spelling", e.Name)
	}
	if e.ObservedAt.Location() != time.UTC || e.ObservedAt.Nanosecond() != 0 {
		t.Errorf("observed_at = %s, want UTC truncated to the second", e.ObservedAt)
	}
	want := []string{"Alice", "bob", "carol"}
	for i, name := range want {
		if e.Maintainers[i] != name {
			t.Fatalf("maintainers = %v, want %v: sorted, without repeats or empties", e.Maintainers, want)
		}
	}
	if len(e.Maintainers) != len(want) {
		t.Fatalf("maintainers = %v, want %v", e.Maintainers, want)
	}
}

// A lookup is by package: the version an entry carries only says which release
// the publisher and the provenance were read from.
func TestLookupIgnoresTheVersion(t *testing.T) {
	f := file(entry("npm:express@4.19.2", day, "dougwilson"))
	if _, ok := f.Lookup(model.MustParseRef("npm:express@9.9.9")); !ok {
		t.Error("a lookup at another version found nothing")
	}
	if _, ok := f.Lookup(model.MustParseRef("pypi:express")); ok {
		t.Error("a lookup in another ecosystem found an entry")
	}
	if _, ok := (*File)(nil).Lookup(model.MustParseRef("npm:express")); ok {
		t.Error("a nil file answered a lookup")
	}
	// PyPI names reach a lookup in whatever spelling a lockfile used.
	pypi := file(entry("pypi:zope-interface@6.0", day, "alice"))
	if _, ok := pypi.Lookup(model.PackageRef{Ecosystem: model.PyPI, Name: "Zope.Interface"}); !ok {
		t.Error("a lookup with the unnormalized name found nothing")
	}
}

func TestKeepDropsWhatIsNoLongerLocked(t *testing.T) {
	f := file(
		entry("npm:express@4.19.2", day, "dougwilson"),
		entry("npm:left-pad@1.3.0", day, "stevemao"),
		entry("cargo:serde@1.0.200", day, "dtolnay"),
	)
	dropped := f.Keep([]model.PackageRef{
		model.MustParseRef("npm:express@4.19.2"),
		model.MustParseRef("cargo:serde@1.0.200"),
	})
	if len(dropped) != 1 || dropped[0].Name != "left-pad" {
		t.Fatalf("dropped = %v, want left-pad", dropped)
	}
	if len(f.Packages) != 2 {
		t.Fatalf("packages = %v, want the two that are still locked", f.Packages)
	}
}

func TestAgeNeverRunsBackwards(t *testing.T) {
	e := entry("npm:express@4.19.2", 3*day)
	if got := e.Age(now); got != 3*day {
		t.Errorf("Age() = %s, want 72h", got)
	}
	future := entry("npm:express@4.19.2", -5*day)
	if got := future.Age(now); got != 0 {
		t.Errorf("Age() = %s, want 0 for a record dated in the future", got)
	}
}

func TestSameSignalsIgnoresTheObservationTime(t *testing.T) {
	a, b := entry("npm:express@4.19.2", day, "dougwilson"), entry("npm:express@4.19.2", 90*day, "dougwilson")
	a.normalize()
	b.normalize()
	if !a.SameSignals(&b) {
		t.Error("two observations of the same signals compare as different")
	}
	c := entry("npm:express@4.19.2", day, "dougwilson", "mallory")
	c.normalize()
	if a.SameSignals(&c) {
		t.Error("a changed maintainer set compares as the same")
	}
	d := a
	d.Provenance = &Provenance{Kind: model.ProvenanceAttestation, Verified: true}
	if a.SameSignals(&d) {
		t.Error("a changed provenance compares as the same")
	}
}

// The pull request case. The record the base revision holds wins whenever the
// change under review edited or deleted it, because a check that compared with
// the rewritten record would report the pass whoever rewrote it wanted.
func TestSetLookupPrefersTheBaseRevision(t *testing.T) {
	pkg := model.MustParseRef("pypi:requests")
	tests := []struct {
		name          string
		set           Set
		wantFound     bool
		wantVersion   string
		wantRewritten bool
		wantAdded     bool
		wantCurrent   bool
	}{
		{
			name:      "nothing recorded on either side",
			set:       Set{},
			wantFound: false,
		},
		{
			name:        "no base revision, so the working tree answers",
			set:         Set{Head: file(entry("pypi:requests@2.32.3", day, "alice"))},
			wantFound:   true,
			wantVersion: "2.32.3",
		},
		{
			name: "the change left the record alone",
			set: Set{
				Head: file(entry("pypi:requests@2.32.3", day, "alice")),
				Base: file(entry("pypi:requests@2.32.3", 30*day, "alice")),
			},
			wantFound:   true,
			wantVersion: "2.32.3",
		},
		{
			name: "the change rewrote the record",
			set: Set{
				Head: file(entry("pypi:requests@2.32.3", 0, "alice", "mallory")),
				Base: file(entry("pypi:requests@2.31.0", 30*day, "alice")),
			},
			wantFound:     true,
			wantVersion:   "2.31.0",
			wantRewritten: true,
			wantCurrent:   true,
		},
		{
			name: "the change deleted the record",
			set: Set{
				Head: file(),
				Base: file(entry("pypi:requests@2.31.0", 30*day, "alice")),
			},
			wantFound:     true,
			wantVersion:   "2.31.0",
			wantRewritten: true,
		},
		{
			// The record is one the change under review invented, so it is reported
			// as added and the checks skip on it. It used to be handed over as an
			// ordinary observation, which let a change claim its own maintainers for
			// a package nothing had ever recorded and take a pass for it.
			name: "the change added a record the base revision never had",
			set: Set{
				Head: file(entry("pypi:requests@2.32.3", 0, "alice")),
				Base: file(),
			},
			wantFound:   true,
			wantVersion: "2.32.3",
			wantAdded:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := tt.set.Lookup(pkg)
			if found != tt.wantFound {
				t.Fatalf("found = %v, want %v", found, tt.wantFound)
			}
			if !found {
				return
			}
			if got.Observed.Version != tt.wantVersion {
				t.Errorf("observed version = %q, want %q", got.Observed.Version, tt.wantVersion)
			}
			if got.Rewritten != tt.wantRewritten {
				t.Errorf("rewritten = %v, want %v", got.Rewritten, tt.wantRewritten)
			}
			if got.Added != tt.wantAdded {
				t.Errorf("added = %v, want %v", got.Added, tt.wantAdded)
			}
			if (got.Current != nil) != tt.wantCurrent {
				t.Errorf("current = %v, want present %v", got.Current, tt.wantCurrent)
			}
		})
	}
	if _, found := (*Set)(nil).Lookup(pkg); found {
		t.Error("a nil set answered a lookup")
	}
}

// A record the working tree only observed again is not a rewrite: nothing but the
// timestamp moved, and the fresher of the two is the one to compare with.
func TestSetLookupTakesTheFresherOfTwoEqualRecords(t *testing.T) {
	set := Set{
		Head: file(entry("cargo:serde@1.0.200", day, "dtolnay")),
		Base: file(entry("cargo:serde@1.0.200", 90*day, "dtolnay")),
	}
	got, _ := set.Lookup(model.MustParseRef("cargo:serde"))
	if got.Rewritten {
		t.Error("a re-observation was read as a rewrite")
	}
	if got.Observed.Age(now) != day {
		t.Errorf("age = %s, want the working tree's fresher record", got.Observed.Age(now))
	}
}
