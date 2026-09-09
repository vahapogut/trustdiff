package checks

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

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
			name: "skipped for pypi until the baseline exists",
			subject: func() *Subject {
				s := subjectA(model.PyPI, "requests", "2.32.0")
				s.Version.Maintainers = publishersA("alice")
				withPreviousA(s, "2.31.0").Maintainers = publishersA("bob-ci")
				return s
			},
			want: outcomeA{skip: "baseline required (arrives in M4)"},
		},
		{
			name: "skipped for cargo until the baseline exists",
			subject: func() *Subject {
				s := subjectA(model.Cargo, "serde", "1.0.200")
				s.Version.Maintainers = publishersA("alice")
				withPreviousA(s, "1.0.199").Maintainers = publishersA("bob-ci")
				return s
			},
			want: outcomeA{skip: "baseline required (arrives in M4)"},
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
