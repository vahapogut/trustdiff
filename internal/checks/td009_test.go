package checks

import (
	"fmt"
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/advisory/osv"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

func TestMaliciousAdvisoryRegistered(t *testing.T) {
	c := maliciousAdvisory{}
	for _, key := range []string{"TD009", "malicious-advisory"} {
		got, ok := Lookup(key)
		if !ok || got.ID() != c.ID() {
			t.Errorf("Lookup(%q) = %v, %v; want %s", key, got, ok, c.ID())
		}
	}
	for _, eco := range model.Ecosystems() {
		if !AppliesTo(c, eco) {
			t.Errorf("TD009 should apply to %s", eco)
		}
	}
}

func TestMaliciousAdvisory(t *testing.T) {
	mal1 := advisory.Advisory{
		ID:        "MAL-2026-1001",
		Summary:   "Malicious code in foo (npm)",
		Malicious: true,
		URL:       "https://osv.dev/vulnerability/MAL-2026-1001",
	}
	mal2 := advisory.Advisory{ID: "MAL-2026-1002", Malicious: true, Aliases: []string{"GHSA-aaaa-bbbb-cccc"}}
	ghsa := advisory.Advisory{ID: "GHSA-xxxx-yyyy-zzzz", Severity: advisory.SeverityHigh, Score: 7.5, Summary: "Prototype pollution"}
	malFinding := depsdev.Finding{Type: "MALICIOUS", Risk: "RISK_CRITICAL", Detail: "listed by ossf/malicious-packages"}
	depFinding := depsdev.Finding{Type: "DEPRECATED", Risk: "RISK_MEDIUM"}

	c := maliciousAdvisory{}
	tests := []struct {
		name    string
		opts    []func(*Subject)
		skipped string // substring of the skip reason; empty when the check ran
		want    int    // findings when the check ran
		verify  func(t *testing.T, f *model.Finding)
	}{
		{
			name: "osv malicious advisory",
			opts: []func(*Subject){withAdvisoriesB(ghsa, mal1)},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "malicious-package advisory MAL-2026-1001" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsB(t, "explanation", f.Explanation,
					"OSV lists 1 malicious-package advisory for npm:foo@1.0.0",
					"MAL-2026-1001 (Malicious code in foo (npm)) at https://osv.dev/vulnerability/MAL-2026-1001")
				if got := evidenceB(t, f, "sources"); got != "[osv]" {
					t.Errorf("sources = %s", got)
				}
				assertNoEvidenceB(t, f, "unavailable")
				assertNoEvidenceB(t, f, "deps_dev_findings")
				entries, ok := f.Evidence["advisories"].([]map[string]any)
				if !ok || len(entries) != 1 {
					t.Fatalf("advisories = %#v", f.Evidence["advisories"])
				}
				if entries[0]["id"] != "MAL-2026-1001" || entries[0]["url"] != mal1.URL || entries[0]["summary"] != mal1.Summary {
					t.Errorf("advisory entry = %v", entries[0])
				}
				if _, ok := entries[0]["aliases"]; ok {
					t.Errorf("advisory entry carries empty aliases: %v", entries[0])
				}
			},
		},
		{
			name: "several advisories sorted by id",
			opts: []func(*Subject){withAdvisoriesB(mal2, ghsa, mal1)},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "2 malicious-package advisories" {
					t.Errorf("title = %q", f.Title)
				}
				entries, ok := f.Evidence["advisories"].([]map[string]any)
				if !ok || len(entries) != 2 {
					t.Fatalf("advisories = %#v", f.Evidence["advisories"])
				}
				if entries[0]["id"] != "MAL-2026-1001" || entries[1]["id"] != "MAL-2026-1002" {
					t.Errorf("advisory order = %v, %v", entries[0]["id"], entries[1]["id"])
				}
				if got, ok := entries[1]["aliases"].([]string); !ok || len(got) != 1 || got[0] != "GHSA-aaaa-bbbb-cccc" {
					t.Errorf("aliases = %#v", entries[1]["aliases"])
				}
				assertContainsB(t, "explanation", f.Explanation, "OSV lists 2 malicious-package advisories", "MAL-2026-1001", "MAL-2026-1002")
			},
		},
		{
			name: "deps.dev malicious finding only",
			opts: []func(*Subject){withDepsDevB(&depsdev.VersionFacts{Found: true}, depFinding, malFinding)},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "deps.dev flags the version as malicious" {
					t.Errorf("title = %q", f.Title)
				}
				assertContainsB(t, "explanation", f.Explanation,
					"deps.dev flags npm:foo@1.0.0 as malicious: MALICIOUS finding (RISK_CRITICAL): listed by ossf/malicious-packages")
				if got := evidenceB(t, f, "sources"); got != "[deps.dev]" {
					t.Errorf("sources = %s", got)
				}
				assertNoEvidenceB(t, f, "advisories")
				entries, ok := f.Evidence["deps_dev_findings"].([]map[string]any)
				if !ok || len(entries) != 1 || entries[0]["type"] != "MALICIOUS" || entries[0]["risk"] != "RISK_CRITICAL" {
					t.Errorf("deps_dev_findings = %#v", f.Evidence["deps_dev_findings"])
				}
			},
		},
		{
			name: "both sources agree",
			opts: []func(*Subject){withAdvisoriesB(mal1), withDepsDevB(&depsdev.VersionFacts{Found: true}, malFinding)},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if f.Title != "malicious-package advisory MAL-2026-1001" {
					t.Errorf("title = %q", f.Title)
				}
				if got := evidenceB(t, f, "sources"); got != "[osv deps.dev]" {
					t.Errorf("sources = %s", got)
				}
				assertContainsB(t, "explanation", f.Explanation, "OSV lists 1", "deps.dev flags")
			},
		},
		{
			name: "no advisories",
			want: 0,
		},
		{
			name: "vulnerability advisories and other deps.dev findings are not malicious",
			opts: []func(*Subject){withAdvisoriesB(ghsa), withDepsDevB(&depsdev.VersionFacts{Found: true}, depFinding)},
			want: 0,
		},
		{
			name: "osv unavailable, deps.dev flags",
			opts: []func(*Subject){withUnavailableB(SourceOSV, "boom"), withDepsDevB(&depsdev.VersionFacts{Found: true}, malFinding)},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "unavailable"); got != SourceOSV {
					t.Errorf("unavailable = %s", got)
				}
				assertContainsB(t, "explanation", f.Explanation, "OSV could not be consulted (osv unavailable: boom)")
			},
		},
		{
			// Half the evidence was never gathered, so the version is not clean: it
			// is unchecked, and the report has to say which source was down.
			name:    "osv unavailable, deps.dev clean",
			opts:    []func(*Subject){withUnavailableB(SourceOSV, "boom"), withDepsDevB(&depsdev.VersionFacts{Found: true})},
			skipped: "osv unavailable: boom",
		},
		{
			// A source that answered "I do not index this" is an answer, and the
			// other source's silence is then the whole of what there is to know.
			name: "osv does not index the ecosystem, deps.dev clean",
			opts: []func(*Subject){withDefiniteB(SourceOSV, fmt.Errorf("jsr: %w", osv.ErrUnsupported)),
				withDepsDevB(&depsdev.VersionFacts{Found: true})},
			want: 0,
		},
		{
			name: "deps.dev unavailable, osv flags",
			opts: []func(*Subject){withUnavailableB(SourceDepsDev, "timeout"), withAdvisoriesB(mal1)},
			want: 1,
			verify: func(t *testing.T, f *model.Finding) {
				if got := evidenceB(t, f, "unavailable"); got != SourceDepsDev {
					t.Errorf("unavailable = %s", got)
				}
				assertContainsB(t, "explanation", f.Explanation, "deps.dev could not be consulted (deps.dev unavailable: timeout)")
			},
		},
		{
			// The advisory held for the down source produces no finding, and with
			// nothing left the check reports the outage rather than a pass.
			name:    "data of an unavailable source is ignored",
			opts:    []func(*Subject){withUnavailableB(SourceOSV, "boom"), withAdvisoriesB(mal1), withDepsDevB(&depsdev.VersionFacts{Found: true})},
			skipped: "osv unavailable: boom",
		},
		{
			name:    "both unavailable",
			opts:    []func(*Subject){withUnavailableB(SourceOSV, "boom"), withUnavailableB(SourceDepsDev, "timeout")},
			skipped: "osv unavailable: boom; deps.dev unavailable: timeout",
		},
		{
			name: "policy level applies",
			opts: []func(*Subject){withAdvisoriesB(mal1), withSettingB("malicious-advisory", policy.CheckSetting{Level: model.LevelWarn})},
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
			s := subjectB(t, "npm:foo@1.0.0", tt.opts...)
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
