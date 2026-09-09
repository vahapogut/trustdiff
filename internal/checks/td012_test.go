package checks

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
)

func TestLowUsageRegistered(t *testing.T) {
	c := lowUsage{}
	for _, key := range []string{"TD012", "low-usage"} {
		got, ok := Lookup(key)
		if !ok || got.ID() != c.ID() {
			t.Errorf("Lookup(%q) = %v, %v; want %s", key, got, ok, c.ID())
		}
	}
	if def, ok := policy.DefaultCheck(c.Name()); !ok || def.Level != model.LevelInfo || def.MinWeeklyDownloads != 500 {
		t.Errorf("default setting = %+v, %v; want info with min_weekly_downloads 500", def, ok)
	}
}

func TestLowUsage(t *testing.T) {
	lowUsageFinding := depsdev.Finding{Type: "LOW_USAGE", Risk: "RISK_LOW", Detail: "few dependents"}
	notFound := depsdev.Finding{Type: "NOT_FOUND", Risk: "RISK_CRITICAL"}
	threshold := func(n int64) func(*Subject) {
		return withSettingB("low-usage", policy.CheckSetting{Level: model.LevelInfo, MinWeeklyDownloads: n})
	}

	c := lowUsage{}
	tests := []struct {
		name    string
		ref     string
		opts    []func(*Subject)
		skipped string
		want    int
		verify  func(t *testing.T, f *model.Finding)
	}{
		{
			name: "below the default threshold",
			ref:  "npm:foo@1.0.0",
			opts: []func(*Subject){withDownloadsB(42)},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "42 weekly downloads, below 500" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsB(t, "explanation", f.Explanation, "the registry reports 42 downloads in the last week for npm:foo, below the policy threshold of 500")
				if got := evidenceB(t, f, "source"); got != SourceRegistry {
					t.Errorf("source = %s", got)
				}
				if got := evidenceB(t, f, "weekly_downloads"); got != "42" {
					t.Errorf("weekly_downloads = %s", got)
				}
				if got := evidenceB(t, f, "min_weekly_downloads"); got != "500" {
					t.Errorf("min_weekly_downloads = %s", got)
				}
				assertNoEvidenceB(t, f, "deps_dev_risk")
			},
		},
		{
			name: "zero downloads",
			ref:  "cargo:foo@1.0.0",
			opts: []func(*Subject){withDownloadsB(0)},
			want: 1,
		},
		{
			name: "exactly the threshold is not below it",
			ref:  "npm:foo@1.0.0",
			opts: []func(*Subject){withDownloadsB(500)},
			want: 0,
		},
		{
			name: "popular package",
			ref:  "npm:foo@1.0.0",
			opts: []func(*Subject){withDownloadsB(1_436_537)},
			want: 0,
		},
		{
			name: "policy raises the threshold",
			ref:  "npm:foo@1.0.0",
			opts: []func(*Subject){withDownloadsB(10_000), threshold(20_000)},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "min_weekly_downloads"); got != "20000" {
					t.Errorf("min_weekly_downloads = %s", got)
				}
			},
		},
		{
			name: "threshold zero never fires from the registry",
			ref:  "npm:foo@1.0.0",
			opts: []func(*Subject){withDownloadsB(0), threshold(0)},
			want: 0,
		},
		{
			name: "registry count wins over a deps.dev finding",
			ref:  "npm:foo@1.0.0",
			opts: []func(*Subject){withDownloadsB(10_000), withDepsDevB(&depsdev.VersionFacts{Found: true}, lowUsageFinding)},
			want: 0,
		},
		{
			name: "no count, deps.dev reports low usage",
			ref:  "pypi:foo@1.0.0",
			opts: []func(*Subject){withUnavailableB(SourceDownloads, registry.ErrUnsupported.Error()), withDepsDevB(&depsdev.VersionFacts{Found: true}, lowUsageFinding)},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "deps.dev reports low usage" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsB(t, "explanation", f.Explanation,
					"downloads unavailable: not provided by this registry",
					"deps.dev reports a LOW_USAGE finding (RISK_LOW): few dependents")
				if got := evidenceB(t, f, "source"); got != SourceDepsDev {
					t.Errorf("source = %s", got)
				}
				if got := evidenceB(t, f, "deps_dev_risk"); got != "RISK_LOW" {
					t.Errorf("deps_dev_risk = %s", got)
				}
				if got := evidenceB(t, f, "deps_dev_detail"); got != "few dependents" {
					t.Errorf("deps_dev_detail = %s", got)
				}
				assertNoEvidenceB(t, f, "weekly_downloads")
				assertNoEvidenceB(t, f, "min_weekly_downloads")
			},
		},
		{
			name: "no count and no downloads reason, deps.dev reports low usage",
			ref:  "pypi:foo@1.0.0",
			opts: []func(*Subject){withDepsDevB(nil, depsdev.Finding{Type: "LOW_USAGE"})},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				assertContainsB(t, "explanation", f.Explanation, "the registry reports no download counts for pypi:foo; deps.dev reports a LOW_USAGE finding")
				assertNoEvidenceB(t, f, "deps_dev_risk")
				assertNoEvidenceB(t, f, "deps_dev_detail")
			},
		},
		{
			name: "no count, deps.dev knows the version and reports nothing",
			ref:  "pypi:foo@1.0.0",
			opts: []func(*Subject){withDepsDevB(&depsdev.VersionFacts{Found: true}, depsdev.Finding{Type: "DEPRECATED"})},
			want: 0,
		},
		{
			name:    "no count, deps.dev unavailable",
			ref:     "pypi:foo@1.0.0",
			opts:    []func(*Subject){withUnavailableB(SourceDownloads, "not provided"), withUnavailableB(SourceDepsDev, "timeout")},
			skipped: "downloads unavailable: not provided; deps.dev unavailable: timeout",
		},
		{
			name:    "no count, no deps.dev data",
			ref:     "pypi:foo@1.0.0",
			skipped: "the registry reports no download counts for pypi:foo; no deps.dev data for pypi:foo@1.0.0",
		},
		{
			name:    "no count, deps.dev has not indexed the version",
			ref:     "pypi:foo@1.0.0",
			opts:    []func(*Subject){withDepsDevB(&depsdev.VersionFacts{Found: false})},
			skipped: "deps.dev has not indexed pypi:foo@1.0.0",
		},
		{
			name:    "no count, deps.dev NOT_FOUND finding",
			ref:     "npm:foo@1.0.0",
			opts:    []func(*Subject){withDepsDevB(nil, notFound)},
			skipped: "deps.dev has not indexed npm:foo@1.0.0",
		},
		{
			name: "policy level applies",
			ref:  "npm:foo@1.0.0",
			opts: []func(*Subject){withDownloadsB(1), withSettingB("low-usage", policy.CheckSetting{Level: model.LevelWarn, MinWeeklyDownloads: 500})},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Level != model.LevelWarn {
					t.Errorf("level = %s, want warn", f.Level)
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
			assertFindingsB(t, c, s, res, tt.want)
			if tt.verify != nil && len(res.Findings) > 0 {
				tt.verify(t, &res.Findings[0])
			}
		})
	}
}
