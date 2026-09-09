package checks

import (
	"errors"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

func TestTD001YoungVersion(t *testing.T) {
	tests := []struct {
		name    string
		subject func() *Subject
		want    outcomeA
		level   model.Level
		// evidence and text fragments that must be present when a finding fires
		evidence map[string]any
		text     []string
	}{
		{
			name: "fires inside the default cooldown",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.PublishedAt = agoA(6 * time.Hour)
				return s
			},
			want:  outcomeA{findings: 1},
			level: model.LevelWarn,
			evidence: map[string]any{
				"published_at":        "2026-09-09T06:00:00Z",
				"published_at_source": "registry",
				"age":                 "6h",
				"age_seconds":         int64(6 * 3600),
				"cooldown":            "3d",
				"cooldown_seconds":    int64(3 * 24 * 3600),
				"cooldown_ends_at":    "2026-09-12T06:00:00Z",
			},
			text: []string{"1.3.0 was published on 2026-09-09T06:00:00Z", "6h before this run", "the cooldown is 3d", "2026-09-12T06:00:00Z"},
		},
		{
			name: "does not fire once the cooldown has passed",
			subject: func() *Subject {
				return subjectA(model.PyPI, "requests", "2.32.0")
			},
			want: outcomeA{},
		},
		{
			name: "age equal to the cooldown is not young",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.PublishedAt = agoA(policy.DefaultCooldown)
				return s
			},
			want: outcomeA{},
		},
		{
			name: "one second short of the cooldown is young",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.PublishedAt = agoA(policy.DefaultCooldown - time.Second)
				return s
			},
			want:     outcomeA{findings: 1},
			level:    model.LevelWarn,
			evidence: map[string]any{"age": "2d23h59m59s"},
		},
		{
			name: "uses the ecosystem override of the policy",
			subject: func() *Subject {
				s := subjectA(model.Cargo, "serde", "1.0.200")
				s.Settings = policy.Default().Effective(model.Cargo)
				s.Version.PublishedAt = agoA(5 * dayA)
				return s
			},
			want:     outcomeA{findings: 1},
			level:    model.LevelWarn,
			evidence: map[string]any{"cooldown": "1w", "age": "5d"},
			text:     []string{"the cooldown is 1w"},
		},
		{
			name: "falls back to the built-in cooldown when the settings are empty",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Settings = policy.Settings{}
				s.Version.PublishedAt = agoA(2 * dayA)
				return s
			},
			want:     outcomeA{findings: 1},
			level:    model.LevelWarn,
			evidence: map[string]any{"cooldown": "3d"},
		},
		{
			name: "takes the level from the policy",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Settings.Checks["young-version"] = policy.CheckSetting{Level: model.LevelBlock}
				s.Version.PublishedAt = agoA(time.Hour)
				return s
			},
			want:  outcomeA{findings: 1},
			level: model.LevelBlock,
		},
		{
			name: "a publish time after the run clock is young and says so",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.PublishedAt = nowA.Add(2 * time.Hour)
				return s
			},
			want:     outcomeA{findings: 1},
			level:    model.LevelWarn,
			evidence: map[string]any{"age": "-2h", "age_seconds": int64(-2 * 3600)},
			text:     []string{"2h after this run's clock"},
		},
		{
			name: "uses the deps.dev publish time when the registry has none",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.PublishedAt = time.Time{}
				s.DepsDev = &depsdev.VersionFacts{Found: true, PublishedAt: agoA(dayA)}
				return s
			},
			want:     outcomeA{findings: 1},
			level:    model.LevelWarn,
			evidence: map[string]any{"published_at_source": "deps.dev", "age": "1d"},
			text:     []string{"publish time taken from deps.dev"},
		},
		{
			name: "skipped when no source knows the publish time",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version.PublishedAt = time.Time{}
				s.DepsDev = &depsdev.VersionFacts{Found: false}
				return s
			},
			want: outcomeA{skip: "publish time of 1.3.0 is unknown"},
		},
		{
			name: "skipped with the registry's reason when it was unavailable",
			subject: func() *Subject {
				s := subjectA(model.NPM, "lib", "1.3.0")
				s.Version = nil
				unavailableA(s, SourceRegistry, errors.New("GET https://registry.npmjs.org/lib: offline and not in the cache"))
				return s
			},
			want: outcomeA{skip: "registry unavailable: GET https://registry.npmjs.org/lib: offline"},
		},
		{
			name: "skipped when the version details are missing without a recorded reason",
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
			s := tt.subject()
			res := runA(t, "TD001", s, tt.want)
			if len(res.Findings) == 0 {
				return
			}
			f := res.Findings[0]
			if f.Level != tt.level {
				t.Errorf("level = %s, want %s", f.Level, tt.level)
			}
			for key, want := range tt.evidence {
				if got := f.Evidence[key]; got != want {
					t.Errorf("evidence[%q] = %v (%T), want %v (%T)", key, got, got, want, want)
				}
			}
			wantTextA(t, "explanation", f.Explanation, tt.text...)
		})
	}
}

func TestTD001AppliesToEveryEcosystem(t *testing.T) {
	c, _ := Lookup("TD001")
	for _, eco := range model.Ecosystems() {
		s := subjectA(eco, "pkg", "1.0.0")
		s.Version.PublishedAt = agoA(time.Hour)
		res := runA(t, "TD001", s, outcomeA{findings: 1})
		if !AppliesTo(c, eco) || res.Findings[0].Ref.Ecosystem != eco {
			t.Errorf("%s: check does not apply", eco)
		}
	}
}

func TestTD001EvidenceKeysAreStable(t *testing.T) {
	s := subjectA(model.NPM, "lib", "1.3.0")
	s.Version.PublishedAt = agoA(time.Hour)
	f := runA(t, "TD001", s, outcomeA{findings: 1}).Findings[0]
	want := []string{"age", "age_seconds", "cooldown", "cooldown_ends_at", "cooldown_seconds", "published_at", "published_at_source"}
	if len(f.Evidence) != len(want) {
		t.Fatalf("evidence has %d keys, want %d: %v", len(f.Evidence), len(want), f.Evidence)
	}
	for _, key := range want {
		if _, ok := f.Evidence[key]; !ok {
			t.Errorf("evidence lacks %q", key)
		}
	}
	wantTextA(t, "title", f.Title, "1h ago", "3d cooldown")
}
