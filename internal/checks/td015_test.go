package checks

import (
	"slices"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
)

func TestVersionAnomalyRegistered(t *testing.T) {
	c := versionAnomaly{}
	for _, key := range []string{"TD015", "version-anomaly"} {
		got, ok := Lookup(key)
		if !ok || got.ID() != c.ID() {
			t.Errorf("Lookup(%q) = %v, %v; want %s", key, got, ok, c.ID())
		}
	}
	if def, ok := policy.DefaultCheck(c.Name()); !ok || def.Level != model.LevelInfo {
		t.Errorf("default setting = %+v, %v; want info", def, ok)
	}
}

// fooHistoryB is a steady 1.x history of npm:foo, seven releases over fifty days,
// with the given releases appended.
func fooHistoryB(extra ...releaseB) *registry.VersionList {
	steady := []releaseB{
		{Version: "1.0.0", Published: dayB(0)},
		{Version: "1.1.0", Published: dayB(10)},
		{Version: "1.2.0", Published: dayB(20)},
		{Version: "1.3.0", Published: dayB(30)},
		{Version: "1.4.0", Published: dayB(40)},
		{Version: "1.4.1", Published: dayB(45)},
		{Version: "1.4.2", Published: dayB(50)},
	}
	return packageB(model.NPM, "foo", slices.Concat(steady, extra)...)
}

func TestVersionAnomaly(t *testing.T) {
	c := versionAnomaly{}
	tests := []struct {
		name    string
		ref     string
		opts    []func(*Subject)
		skipped string
		signals []string // evidence "signal" of each finding, in order
		verify  func(t *testing.T, findings []model.Finding)
	}{
		{
			name:    "major jump",
			ref:     "npm:foo@9.9.9",
			opts:    []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "9.9.9", Published: dayB(60)}))},
			signals: []string{"jump"},
			verify: func(t *testing.T, findings []model.Finding) {
				f := &findings[0]
				if f.Title != "version jumps from 1.4.2 to 9.9.9" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsB(t, "explanation", f.Explanation,
					"npm:foo@9.9.9 (published 2026-03-02) raises the major from 1 to 9 from the previous release 1.4.2 (published 2026-02-20)",
					"across the 7 earlier releases, consecutive releases raised the major by at most 0 and the minor by at most 1")
				for key, want := range map[string]string{
					"version":            "9.9.9",
					"published":          "2026-03-02T00:00:00Z",
					"previous":           "1.4.2",
					"previous_published": "2026-02-20T00:00:00Z",
					"major_step":         "8",
					"minor_step":         "5",
					"earlier_releases":   "7",
					"max_major_step":     "0",
					"max_minor_step":     "1",
				} {
					if got := evidenceB(t, f, key); got != want {
						t.Errorf("%s = %s, want %s", key, got, want)
					}
				}
				assertNoEvidenceB(t, f, "earlier_version")
			},
		},
		{
			name:    "minor jump",
			ref:     "npm:foo@1.30.0",
			opts:    []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "1.30.0", Published: dayB(60)}))},
			signals: []string{"jump"},
			verify: func(t *testing.T, findings []model.Finding) {
				f := &findings[0]
				if f.Title != "minor version jumps from 1.4.2 to 1.30.0" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsB(t, "explanation", f.Explanation, "raises the minor from 4 to 30 within major 1")
				if got := evidenceB(t, f, "minor_step"); got != "26" {
					t.Errorf("minor_step = %s", got)
				}
			},
		},
		{
			name: "next major is not a jump",
			ref:  "npm:foo@2.0.0",
			opts: []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "2.0.0", Published: dayB(60)}))},
		},
		{
			name: "ten minors is not a jump",
			ref:  "npm:foo@1.14.0",
			opts: []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "1.14.0", Published: dayB(60)}))},
		},
		{
			name:    "eleven minors is a jump",
			ref:     "npm:foo@1.15.0",
			opts:    []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "1.15.0", Published: dayB(60)}))},
			signals: []string{"jump"},
		},
		{
			name: "minor jump across a major is judged by the major only",
			ref:  "npm:foo@2.40.0",
			opts: []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "2.40.0", Published: dayB(60)}))},
		},
		{
			name:    "out of order",
			ref:     "npm:foo@1.2.5",
			opts:    []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "1.2.5", Published: dayB(60)}))},
			signals: []string{"out-of-order"},
			verify: func(t *testing.T, findings []model.Finding) {
				f := &findings[0]
				if f.Title != "1.2.5 published after 1.4.2, which sorts above it" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsB(t, "explanation", f.Explanation,
					"npm:foo@1.2.5 was published on 2026-03-02 but sorts below 1.4.2, published on 2026-02-20",
					"4 earlier releases sort above it")
				for key, want := range map[string]string{
					"version":           "1.2.5",
					"earlier_version":   "1.4.2",
					"earlier_published": "2026-02-20T00:00:00Z",
					"earlier_above":     "4",
				} {
					if got := evidenceB(t, f, key); got != want {
						t.Errorf("%s = %s, want %s", key, got, want)
					}
				}
				assertNoEvidenceB(t, f, "previous")
			},
		},
		{
			name:    "both signals",
			ref:     "npm:foo@5.0.0",
			opts:    []func(*Subject){withPackageB(packageB(model.NPM, "foo", releaseB{Version: "1.0.0", Published: dayB(0)}, releaseB{Version: "9.0.0", Published: dayB(10)}, releaseB{Version: "1.0.1", Published: dayB(20)}, releaseB{Version: "5.0.0", Published: dayB(30)}))},
			signals: []string{"jump", "out-of-order"},
			verify: func(t *testing.T, findings []model.Finding) {
				jump, order := &findings[0], &findings[1]
				if got := evidenceB(t, jump, "previous"); got != "1.0.1" {
					t.Errorf("previous = %s", got)
				}
				if got := evidenceB(t, jump, "major_step"); got != "4" {
					t.Errorf("major_step = %s", got)
				}
				if got := evidenceB(t, jump, "max_major_step"); got != "8" {
					t.Errorf("max_major_step = %s", got)
				}
				if got := evidenceB(t, order, "earlier_version"); got != "9.0.0" {
					t.Errorf("earlier_version = %s", got)
				}
				if got := evidenceB(t, order, "earlier_above"); got != "1" {
					t.Errorf("earlier_above = %s", got)
				}
				assertContainsB(t, "explanation", order.Explanation, "1 earlier release sorts above it")
			},
		},
		{
			name:    "single earlier release has no cadence",
			ref:     "npm:foo@4.0.0",
			opts:    []func(*Subject){withPackageB(packageB(model.NPM, "foo", releaseB{Version: "1.0.0", Published: dayB(0)}, releaseB{Version: "4.0.0", Published: dayB(10)}))},
			signals: []string{"jump"},
			verify: func(t *testing.T, findings []model.Finding) {
				assertContainsB(t, "explanation", findings[0].Explanation, "1.0.0 is the only earlier release, so there is no cadence to compare with")
				if got := evidenceB(t, &findings[0], "earlier_releases"); got != "1" {
					t.Errorf("earlier_releases = %s", got)
				}
			},
		},
		{
			name: "prereleases and yanked versions are ignored",
			ref:  "npm:foo@1.1.0",
			opts: []func(*Subject){withPackageB(packageB(model.NPM, "foo",
				releaseB{Version: "1.0.0", Published: dayB(0)},
				releaseB{Version: "2.0.0-rc.1", Published: dayB(5), Prerelease: true},
				releaseB{Version: "3.0.0", Published: dayB(6), Yanked: true},
				releaseB{Version: "1.1.0", Published: dayB(10)},
			))},
		},
		{
			name: "history that does not parse is ignored",
			ref:  "npm:foo@1.1.0",
			opts: []func(*Subject){withPackageB(packageB(model.NPM, "foo",
				releaseB{Version: "1.0.0", Published: dayB(0)},
				releaseB{Version: "banana", Published: dayB(5)},
				releaseB{Version: "1.0.1"},
				releaseB{Version: "1.1.0", Published: dayB(10)},
			))},
		},
		{
			name: "later releases do not count",
			ref:  "npm:foo@1.1.0",
			opts: []func(*Subject){withPackageB(packageB(model.NPM, "foo",
				releaseB{Version: "1.0.0", Published: dayB(0)},
				releaseB{Version: "1.1.0", Published: dayB(10)},
				releaseB{Version: "9.0.0", Published: dayB(20)},
			))},
		},
		{
			name:    "pypi jump",
			ref:     "pypi:bar@5.0",
			opts:    []func(*Subject){withPackageB(packageB(model.PyPI, "bar", releaseB{Version: "1.0", Published: dayB(0)}, releaseB{Version: "1.2", Published: dayB(10)}, releaseB{Version: "5.0", Published: dayB(20)}))},
			signals: []string{"jump"},
			verify: func(t *testing.T, findings []model.Finding) {
				if got := evidenceB(t, &findings[0], "major_step"); got != "4" {
					t.Errorf("major_step = %s", got)
				}
			},
		},
		{
			name:    "first release",
			ref:     "npm:foo@1.0.0",
			opts:    []func(*Subject){withPackageB(packageB(model.NPM, "foo", releaseB{Version: "1.0.0", Published: dayB(0)}))},
			skipped: "no earlier release of npm:foo to compare 1.0.0 with",
		},
		{
			name:    "registry unavailable",
			ref:     "npm:foo@1.0.0",
			opts:    []func(*Subject){withUnavailableB(SourceRegistry, "boom")},
			skipped: "registry unavailable: boom",
		},
		{
			name:    "no version list",
			ref:     "npm:foo@1.0.0",
			skipped: "no version history for npm:foo",
		},
		{
			name:    "version missing from the list",
			ref:     "npm:foo@7.7.7",
			opts:    []func(*Subject){withPackageB(fooHistoryB())},
			skipped: "version 7.7.7 is not in the registry's version list",
		},
		{
			name:    "no publish time",
			ref:     "npm:foo@1.5.0",
			opts:    []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "1.5.0"}))},
			skipped: "no publish time for npm:foo@1.5.0",
		},
		{
			name:    "evaluated version does not parse",
			ref:     "npm:foo@banana",
			opts:    []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "banana", Published: dayB(60)}))},
			skipped: `version "banana" does not parse as a npm version`,
		},
		{
			name: "policy level applies",
			ref:  "npm:foo@9.9.9",
			opts: []func(*Subject){withPackageB(fooHistoryB(releaseB{Version: "9.9.9", Published: dayB(60)})),
				withSettingB("version-anomaly", policy.CheckSetting{Level: model.LevelWarn})},
			signals: []string{"jump"},
			verify: func(t *testing.T, findings []model.Finding) {
				if findings[0].Level != model.LevelWarn {
					t.Errorf("level = %s, want warn", findings[0].Level)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := subjectB(t, tt.ref, tt.opts...)
			res := resultB(t, c, s)
			if tt.skipped != "" {
				assertSkippedB(t, c, res, tt.skipped)
				return
			}
			assertFindingsB(t, c, s, res, len(tt.signals))
			for i, want := range tt.signals {
				if got := evidenceB(t, &res.Findings[i], "signal"); got != want {
					t.Errorf("finding %d: signal = %s, want %s", i, got, want)
				}
			}
			if tt.verify != nil {
				tt.verify(t, res.Findings)
			}
		})
	}
}

func TestVersionAnomalyComponents(t *testing.T) {
	tests := []struct {
		canonical string
		major     int
		minor     int
		ok        bool
	}{
		{"v1.2.3", 1, 2, true},
		{"v1.2.3-rc.1", 1, 2, true},
		{"v7.0.0", 7, 0, true},
		{"v0.10.99", 0, 10, true},
		{"1.2.3", 1, 2, true},
		{"1.2.3rc1", 1, 2, true},
		{"1.0.post1", 1, 0, true},
		{"2.1.dev0", 2, 1, true},
		{"1!2.3", 2, 3, true},
		{"7", 7, 0, true},
		{"7.", 7, 0, true},
		{"1.2+local.4", 1, 2, true},
		{"", 0, 0, false},
		{"v", 0, 0, false},
		{"banana", 0, 0, false},
		{"v99999999999999999999.0.0", 0, 0, false},
		{"1.99999999999999999999", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.canonical, func(t *testing.T) {
			major, minor, ok := versionAnomalyComponents(version.Version{Canonical: tt.canonical})
			if major != tt.major || minor != tt.minor || ok != tt.ok {
				t.Errorf("components(%q) = %d, %d, %v; want %d, %d, %v", tt.canonical, major, minor, ok, tt.major, tt.minor, tt.ok)
			}
		})
	}
}
