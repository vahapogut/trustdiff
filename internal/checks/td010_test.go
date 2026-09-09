package checks

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

func TestVulnerabilityRegistered(t *testing.T) {
	c := vulnerability{}
	for _, key := range []string{"TD010", "vulnerability"} {
		got, ok := Lookup(key)
		if !ok || got.ID() != c.ID() {
			t.Errorf("Lookup(%q) = %v, %v; want %s", key, got, ok, c.ID())
		}
	}
	if def, ok := policy.DefaultCheck(c.Name()); !ok || def.MinSeverity != policy.SeverityHigh || def.Level != model.LevelBlock {
		t.Errorf("default setting = %+v, %v; want block with min_severity high", def, ok)
	}
}

// vulnerabilityIDs lists the advisory ids of the findings in order.
func vulnerabilityIDs(t *testing.T, findings []model.Finding) []string {
	t.Helper()
	ids := make([]string, 0, len(findings))
	for i := range findings {
		ids = append(ids, evidenceB(t, &findings[i], "advisory_id"))
	}
	return ids
}

func TestVulnerability(t *testing.T) {
	critical := advisory.Advisory{ID: "GHSA-crit-0000-0000", Severity: advisory.SeverityCritical, Score: 9.8, Summary: "remote code execution", URL: "https://osv.dev/vulnerability/GHSA-crit-0000-0000"}
	high := advisory.Advisory{ID: "GHSA-high-0000-0000", Severity: advisory.SeverityHigh, Score: 7.5, Aliases: []string{"CVE-2026-0001"}, Summary: "denial of service"}
	medium := advisory.Advisory{ID: "GHSA-medi-0000-0000", Severity: advisory.SeverityMedium, Score: 5.3}
	low := advisory.Advisory{ID: "GHSA-lowx-0000-0000", Severity: advisory.SeverityLow, Score: 3.1}
	unknown := advisory.Advisory{ID: "GHSA-unkn-0000-0000", Summary: "no CVSS vector published"}
	malicious := advisory.Advisory{ID: "MAL-2026-0001", Severity: advisory.SeverityCritical, Malicious: true}
	all := []advisory.Advisory{low, malicious, unknown, high, medium, critical}

	setting := func(minSeverity string) policy.CheckSetting {
		return policy.CheckSetting{Level: model.LevelBlock, MinSeverity: minSeverity}
	}

	c := vulnerability{}
	tests := []struct {
		name    string
		opts    []func(*Subject)
		skipped string
		wantIDs []string
		verify  func(t *testing.T, findings []model.Finding)
	}{
		{
			name:    "default threshold high, most severe first",
			opts:    []func(*Subject){withAdvisoriesB(all...)},
			wantIDs: []string{"GHSA-crit-0000-0000", "GHSA-high-0000-0000"},
			verify: func(t *testing.T, findings []model.Finding) {
				f := &findings[0]
				if f.Title != "GHSA-crit-0000-0000: critical severity vulnerability (CVSS 9.8)" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsB(t, "explanation", f.Explanation,
					"OSV advisory GHSA-crit-0000-0000 affects npm:foo@1.0.0 with severity critical (CVSS 9.8): remote code execution",
					"see https://osv.dev/vulnerability/GHSA-crit-0000-0000",
					"severity high or above")
				if got := evidenceB(t, f, "severity"); got != "critical" {
					t.Errorf("severity = %s", got)
				}
				if got := evidenceB(t, f, "score"); got != "9.8" {
					t.Errorf("score = %s", got)
				}
				if got := evidenceB(t, f, "min_severity"); got != "high" {
					t.Errorf("min_severity = %s", got)
				}
				if got := evidenceB(t, f, "url"); got != critical.URL {
					t.Errorf("url = %s", got)
				}
				assertNoEvidenceB(t, f, "aliases")

				f = &findings[1]
				assertContainsB(t, "explanation", f.Explanation, "GHSA-high-0000-0000 (CVE-2026-0001) affects", "severity high (CVSS 7.5): denial of service")
				if got := evidenceB(t, f, "aliases"); got != "[CVE-2026-0001]" {
					t.Errorf("aliases = %s", got)
				}
				assertNoEvidenceB(t, f, "url")
			},
		},
		{
			name:    "threshold medium counts unknown as medium",
			opts:    []func(*Subject){withAdvisoriesB(all...), withSettingB("vulnerability", setting("medium"))},
			wantIDs: []string{"GHSA-crit-0000-0000", "GHSA-high-0000-0000", "GHSA-medi-0000-0000", "GHSA-unkn-0000-0000"},
			verify: func(t *testing.T, findings []model.Finding) {
				f := &findings[3]
				if f.Title != "GHSA-unkn-0000-0000: vulnerability of unknown severity, counted as medium" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsB(t, "explanation", f.Explanation, "no usable severity, which counts as medium", "no CVSS vector published", "severity medium or above")
				if got := evidenceB(t, f, "severity"); got != "unknown" {
					t.Errorf("severity = %s", got)
				}
				if got := evidenceB(t, f, "effective_severity"); got != "medium" {
					t.Errorf("effective_severity = %s", got)
				}
				assertNoEvidenceB(t, f, "score")
			},
		},
		{
			name:    "threshold low reports everything but malicious",
			opts:    []func(*Subject){withAdvisoriesB(all...), withSettingB("vulnerability", setting("low"))},
			wantIDs: []string{"GHSA-crit-0000-0000", "GHSA-high-0000-0000", "GHSA-medi-0000-0000", "GHSA-unkn-0000-0000", "GHSA-lowx-0000-0000"},
		},
		{
			name:    "threshold critical",
			opts:    []func(*Subject){withAdvisoriesB(all...), withSettingB("vulnerability", setting("critical"))},
			wantIDs: []string{"GHSA-crit-0000-0000"},
		},
		{
			name:    "GHSA spelling of the threshold",
			opts:    []func(*Subject){withAdvisoriesB(all...), withSettingB("vulnerability", setting("MODERATE"))},
			wantIDs: []string{"GHSA-crit-0000-0000", "GHSA-high-0000-0000", "GHSA-medi-0000-0000", "GHSA-unkn-0000-0000"},
		},
		{
			name:    "empty threshold falls back to the default",
			opts:    []func(*Subject){withAdvisoriesB(all...), withSettingB("vulnerability", setting(""))},
			wantIDs: []string{"GHSA-crit-0000-0000", "GHSA-high-0000-0000"},
		},
		{
			name:    "unparsable threshold falls back to the default",
			opts:    []func(*Subject){withAdvisoriesB(all...), withSettingB("vulnerability", setting("severe"))},
			wantIDs: []string{"GHSA-crit-0000-0000", "GHSA-high-0000-0000"},
			verify: func(t *testing.T, findings []model.Finding) {
				if got := evidenceB(t, &findings[0], "min_severity"); got != "high" {
					t.Errorf("min_severity = %s", got)
				}
			},
		},
		{
			name:    "ties break by id",
			opts:    []func(*Subject){withAdvisoriesB(advisory.Advisory{ID: "GHSA-bbbb", Severity: advisory.SeverityHigh}, advisory.Advisory{ID: "GHSA-aaaa", Severity: advisory.SeverityHigh})},
			wantIDs: []string{"GHSA-aaaa", "GHSA-bbbb"},
			verify: func(t *testing.T, findings []model.Finding) {
				if f := &findings[0]; f.Title != "GHSA-aaaa: high severity vulnerability" {
					t.Errorf("title without a score = %q", f.Title)
				}
			},
		},
		{
			name:    "only low advisories under the default",
			opts:    []func(*Subject){withAdvisoriesB(low, medium, unknown)},
			wantIDs: nil,
		},
		{
			name:    "no advisories",
			wantIDs: nil,
		},
		{
			name:    "malicious advisories belong to TD009",
			opts:    []func(*Subject){withAdvisoriesB(malicious)},
			wantIDs: nil,
		},
		{
			name:    "osv unavailable",
			opts:    []func(*Subject){withUnavailableB(SourceOSV, "boom"), withAdvisoriesB(critical)},
			skipped: "osv unavailable: boom",
		},
		{
			name:    "policy level applies",
			opts:    []func(*Subject){withAdvisoriesB(critical), withSettingB("vulnerability", policy.CheckSetting{Level: model.LevelWarn, MinSeverity: "high"})},
			wantIDs: []string{"GHSA-crit-0000-0000"},
			verify: func(t *testing.T, findings []model.Finding) {
				if findings[0].Level != model.LevelWarn {
					t.Errorf("level = %s, want warn", findings[0].Level)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := subjectB(t, "npm:foo@1.0.0", tt.opts...)
			res := resultB(t, c, s)
			if tt.skipped != "" {
				assertSkippedB(t, c, res, tt.skipped)
				return
			}
			assertFindingsB(t, c, s, res, len(tt.wantIDs))
			got := vulnerabilityIDs(t, res.Findings)
			for i := range tt.wantIDs {
				if got[i] != tt.wantIDs[i] {
					t.Fatalf("finding ids = %v, want %v", got, tt.wantIDs)
				}
			}
			if tt.verify != nil {
				tt.verify(t, res.Findings)
			}
		})
	}
}
