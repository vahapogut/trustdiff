package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// historyA builds a subject whose package history is the given (version,
// publisher, age in days) triples, oldest first, and whose evaluated version is
// the last one.
func historyA(eco model.Ecosystem, releases ...releaseA) *Subject {
	name := "lib"
	versions := make([]model.VersionInfo, 0, len(releases))
	for _, r := range releases {
		v := versionA(eco, name, r.version, agoA(time.Duration(r.daysAgo)*dayA))
		if r.publisher != "" {
			v.Publisher = &model.Publisher{Name: r.publisher}
		}
		v.Prerelease, v.Yanked = r.prerelease, r.yanked
		versions = append(versions, v)
	}
	last := versions[len(versions)-1]
	s := subjectA(eco, name, last.Ref.Version)
	s.Version = &last
	s.Package = listA(eco, name, versions...)
	return s
}

type releaseA struct {
	version    string
	publisher  string
	daysAgo    int
	prerelease bool
	yanked     bool
}

func TestTD002PublisherChanged(t *testing.T) {
	tests := []struct {
		name    string
		subject func() *Subject
		want    outcomeA
		// when a finding fires
		publishers []string
		versions   []string
		window     int
		text       []string
	}{
		{
			name: "fires when the publisher is new",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.0.1", "alice", 30, false, false},
					releaseA{"1.1.0", "alice", 20, false, false},
					releaseA{"1.2.0", "alice", 10, false, false},
					releaseA{"1.3.0", "bob-ci", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"alice"},
			versions:   []string{"1.2.0", "1.1.0", "1.0.1", "1.0.0"},
			window:     5,
			text: []string{
				"the previous 4 versions (1.2.0, 1.1.0, 1.0.1, 1.0.0) were published by alice",
				"1.3.0 was published by bob-ci, an account that published none of them",
			},
		},
		{
			name: "does not fire for a returning publisher",
			subject: func() *Subject {
				return historyA(model.Cargo,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "carol", 20, false, false},
					releaseA{"1.2.0", "alice", 1, false, false})
			},
			want: outcomeA{},
		},
		{
			name: "compares account names without regard to case",
			subject: func() *Subject {
				return historyA(model.Cargo,
					releaseA{"1.0.0", "Alice", 40, false, false},
					releaseA{"1.1.0", "alice", 1, false, false})
			},
			want: outcomeA{},
		},
		{
			name: "looks back only as far as the window",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "bob-ci", 40, false, false},
					releaseA{"1.1.0", "carol", 30, false, false},
					releaseA{"1.2.0", "carol", 20, false, false},
					releaseA{"1.3.0", "bob-ci", 1, false, false})
				s.Settings.PreviousVersionsWindow = 2
				return s
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"carol"},
			versions:   []string{"1.2.0", "1.1.0"},
			window:     2,
		},
		{
			name: "falls back to the built-in window when the settings are empty",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "bob-ci", 70, false, false},
					releaseA{"1.1.0", "carol", 60, false, false},
					releaseA{"1.2.0", "carol", 50, false, false},
					releaseA{"1.3.0", "carol", 40, false, false},
					releaseA{"1.4.0", "carol", 30, false, false},
					releaseA{"1.5.0", "carol", 20, false, false},
					releaseA{"1.6.0", "bob-ci", 1, false, false})
				s.Settings.PreviousVersionsWindow = 0
				return s
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"carol"},
			versions:   []string{"1.5.0", "1.4.0", "1.3.0", "1.2.0", "1.1.0"},
			window:     5,
		},
		{
			name: "ignores yanked versions and prereleases in the history",
			subject: func() *Subject {
				return historyA(model.Cargo,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.0.1", "bob-ci", 30, false, true},
					releaseA{"1.1.0-rc.1", "bob-ci", 20, true, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"alice"},
			versions:   []string{"1.0.0"},
			window:     5,
			text:       []string{"the previous version (1.0.0) was published by alice; 1.1.0 was published by bob-ci, a different account"},
		},
		{
			name: "lists several previous publishers with their versions",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"1.0.0", "carol", 40, false, false},
					releaseA{"1.1.0", "alice", 20, false, false},
					releaseA{"1.2.0", "", 10, false, false},
					releaseA{"1.3.0", "bob-ci", 1, false, false})
			},
			want:       outcomeA{findings: 1},
			publishers: []string{"alice", "carol"},
			versions:   []string{"1.2.0", "1.1.0", "1.0.0"},
			window:     5,
			text: []string{
				"the previous 3 versions were published by alice (1.1.0) and carol (1.0.0), with no publisher recorded for 1.2.0",
			},
		},
		{
			name: "skipped when the version has no publisher",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "", 1, false, false})
			},
			want: outcomeA{skip: "no publishing account recorded for 1.1.0"},
		},
		{
			name: "skipped when no previous release has a publisher",
			subject: func() *Subject {
				return historyA(model.NPM,
					releaseA{"1.0.0", "", 40, false, false},
					releaseA{"1.0.1", "", 30, false, false},
					releaseA{"1.1.0", "alice", 1, false, false})
			},
			want: outcomeA{skip: "no publishing account recorded for the previous 2 releases"},
		},
		{
			name: "skipped for a first release",
			subject: func() *Subject {
				return historyA(model.NPM, releaseA{"1.0.0", "alice", 1, false, false})
			},
			want: outcomeA{skip: "no earlier release"},
		},
		{
			name: "skipped when the history was not loaded",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
				s.Package = nil
				unavailableA(s, SourceRegistry, errors.New("status 503"))
				return s
			},
			want: outcomeA{skip: "registry unavailable: status 503"},
		},
		{
			name: "skipped when the evaluated version is not in the list",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
				s.Package.Versions = s.Package.Versions[:1]
				return s
			},
			want: outcomeA{skip: "1.1.0 is not in the registry's version list"},
		},
		{
			name: "skipped when the evaluated version has no publish time",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
				s.Package.Versions[1].PublishedAt = time.Time{}
				return s
			},
			want: outcomeA{skip: "publish time of 1.1.0 is unknown"},
		},
		{
			name: "skipped when the version details are missing",
			subject: func() *Subject {
				s := historyA(model.NPM,
					releaseA{"1.0.0", "alice", 40, false, false},
					releaseA{"1.1.0", "bob-ci", 1, false, false})
				s.Version = nil
				return s
			},
			want: outcomeA{skip: "version details unavailable"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runA(t, "TD002", tt.subject(), tt.want)
			if len(res.Findings) == 0 {
				return
			}
			f := res.Findings[0]
			if f.Level != model.LevelBlock {
				t.Errorf("level = %s, want block", f.Level)
			}
			if got := stringsA(t, f.Evidence, "previous_publishers"); !equalA(got, tt.publishers) {
				t.Errorf("previous_publishers = %v, want %v", got, tt.publishers)
			}
			if got := stringsA(t, f.Evidence, "previous_versions"); !equalA(got, tt.versions) {
				t.Errorf("previous_versions = %v, want %v", got, tt.versions)
			}
			if got := f.Evidence["window"]; got != tt.window {
				t.Errorf("window = %v, want %d", got, tt.window)
			}
			if got := f.Evidence["publisher"]; got != "bob-ci" {
				t.Errorf("publisher = %v, want bob-ci", got)
			}
			releases, ok := f.Evidence["previous_releases"].([]map[string]any)
			if !ok || len(releases) != len(tt.versions) {
				t.Errorf("previous_releases = %v, want %d entries", f.Evidence["previous_releases"], len(tt.versions))
			}
			wantTextA(t, "title", f.Title, "Published by bob-ci")
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}

func TestTD002UsesTheRegistryRefWhenTheSubjectRefIsBare(t *testing.T) {
	s := historyA(model.NPM,
		releaseA{"1.0.0", "alice", 40, false, false},
		releaseA{"1.1.0", "bob-ci", 1, false, false})
	s.Ref = s.Ref.Package()
	s.ResolvedLatest = true
	f := runA(t, "TD002", s, outcomeA{findings: 1}).Findings[0]
	if f.Ref != s.Ref {
		t.Errorf("finding ref = %s, want the subject's bare ref %s", f.Ref, s.Ref)
	}
	wantTextA(t, "explanation", f.Explanation, "1.1.0 was published by bob-ci")
}

func TestTD002NotApplicableToPyPI(t *testing.T) {
	c, _ := Lookup("TD002")
	if AppliesTo(c, model.PyPI) {
		t.Error("TD002 applies to pypi; the brief routes PyPI through the baseline")
	}
}
