package checks

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
)

// TD009 malicious-advisory reports a version that OSV lists under a malicious-package
// advisory (an id starting with MAL-, imported from ossf/malicious-packages) or that
// deps.dev flags with a MALICIOUS finding. It applies to every ecosystem and blocks
// by default.
//
// The two sources are consulted independently. When one of them found something the
// check reports it and the explanation says which source could not be consulted, so
// a partial answer is never mistaken for a full one. When neither found anything the
// check passes only if both of them answered: a source that was an outage rather
// than a definite answer (not indexed, not configured) was never asked, and the
// check reports itself as skipped with that outage instead. Data held for a source
// that is marked unavailable is ignored.
//
// Evidence keys:
//
//	advisories         every malicious OSV advisory, sorted by id, as {id, url, summary, aliases}
//	                   (url, summary and aliases are present when the advisory carries them)
//	deps_dev_findings  every deps.dev MALICIOUS finding as {type, risk, detail}
//	                   (risk and detail are present when deps.dev returned them)
//	sources            the sources that answered, in this order: osv, deps.dev
//	unavailable        the source that could not be consulted, when one was: osv or deps.dev
//
// OSV malicious-package advisories, verified 2026-09-09: GET https://api.osv.dev/v1/vulns/MAL-2021-1
// returns id "MAL-2021-1" with summary "Malicious code in cxp-jquery (npm)"; the
// OSV client sets advisory.Advisory.Malicious for such ids, and this check relies on
// that flag alone.
//
// deps.dev finding types, verified 2026-09-09 against https://docs.deps.dev/api/v3alpha/:
// NOT_FOUND, MALICIOUS, DEPRECATED, COOLDOWN, LOW_USAGE, VULNERABLE and REMEDIATION,
// each with a RISK_* level; the docs add that a MALICIOUS package finding covers
// every version of the package. A live POST https://api.deps.dev/v3alpha/findingsbatch
// the same day returned DEPRECATED, NOT_FOUND and REMEDIATION findings in that shape;
// no MALICIOUS finding was observed live, so its name rests on the docs.

// maliciousAdvisoryFindingType is the deps.dev finding type this check looks for.
const maliciousAdvisoryFindingType = "MALICIOUS"

type maliciousAdvisory struct{}

func init() { Register(maliciousAdvisory{}) }

// ID implements Check.
func (maliciousAdvisory) ID() string { return "TD009" }

// Name implements Check.
func (maliciousAdvisory) Name() string { return "malicious-advisory" }

// Ecosystems implements Check; nil means every ecosystem.
func (maliciousAdvisory) Ecosystems() []model.Ecosystem { return nil }

// Run implements Check.
func (c maliciousAdvisory) Run(_ context.Context, s *Subject) Result {
	osvReason, osvDown := s.Skipped(SourceOSV)
	depsDevReason, depsDevDown := s.Skipped(SourceDepsDev)
	if osvDown && depsDevDown {
		return Skip(c.ID(), osvReason+"; "+depsDevReason)
	}

	var advisories []*advisory.Advisory
	if !osvDown {
		for i := range s.Advisories {
			if s.Advisories[i].Malicious {
				advisories = append(advisories, &s.Advisories[i])
			}
		}
		slices.SortFunc(advisories, func(a, b *advisory.Advisory) int { return strings.Compare(a.ID, b.ID) })
	}
	var findings []depsdev.Finding
	if !depsDevDown {
		for _, f := range s.DepsDevFindings {
			if f.Type == maliciousAdvisoryFindingType {
				findings = append(findings, f)
			}
		}
	}
	if len(advisories) == 0 && len(findings) == 0 {
		return cleanOrSkip(c, s, SourceOSV, SourceDepsDev)
	}

	evidence := map[string]any{}
	var sources, parts []string
	if len(advisories) > 0 {
		entries := make([]map[string]any, 0, len(advisories))
		descriptions := make([]string, 0, len(advisories))
		for _, a := range advisories {
			entry := map[string]any{"id": a.ID}
			if a.URL != "" {
				entry["url"] = a.URL
			}
			if a.Summary != "" {
				entry["summary"] = a.Summary
			}
			if len(a.Aliases) > 0 {
				entry["aliases"] = a.Aliases
			}
			entries = append(entries, entry)
			descriptions = append(descriptions, c.describe(a))
		}
		evidence["advisories"] = entries
		sources = append(sources, SourceOSV)
		noun := "malicious-package advisory"
		if len(advisories) > 1 {
			noun = "malicious-package advisories"
		}
		parts = append(parts, fmt.Sprintf("OSV lists %d %s for %s: %s", len(advisories), noun, s.Ref, strings.Join(descriptions, "; ")))
	}
	if len(findings) > 0 {
		entries := make([]map[string]any, 0, len(findings))
		descriptions := make([]string, 0, len(findings))
		for _, f := range findings {
			entry := map[string]any{"type": f.Type}
			if f.Risk != "" {
				entry["risk"] = f.Risk
			}
			if f.Detail != "" {
				entry["detail"] = f.Detail
			}
			entries = append(entries, entry)
			descriptions = append(descriptions, c.describeFinding(f))
		}
		evidence["deps_dev_findings"] = entries
		sources = append(sources, SourceDepsDev)
		parts = append(parts, fmt.Sprintf("deps.dev flags %s as malicious: %s", s.Ref, strings.Join(descriptions, "; ")))
	}
	evidence["sources"] = sources
	switch {
	case osvDown:
		evidence["unavailable"] = SourceOSV
		parts = append(parts, "OSV could not be consulted ("+osvReason+")")
	case depsDevDown:
		evidence["unavailable"] = SourceDepsDev
		parts = append(parts, "deps.dev could not be consulted ("+depsDevReason+")")
	}

	return Result{Findings: []model.Finding{
		NewFinding(c, s, c.title(advisories, findings), strings.Join(parts, "; "), evidence),
	}}
}

// title names the strongest evidence: the OSV advisory ids when there are any,
// otherwise the deps.dev finding.
func (maliciousAdvisory) title(advisories []*advisory.Advisory, findings []depsdev.Finding) string {
	switch {
	case len(advisories) == 1:
		return "malicious-package advisory " + advisories[0].ID
	case len(advisories) > 1:
		return fmt.Sprintf("%d malicious-package advisories", len(advisories))
	case len(findings) > 0:
		return "deps.dev flags the version as malicious"
	default:
		return "malicious package"
	}
}

// describe renders one advisory for the explanation: id, summary and URL.
func (maliciousAdvisory) describe(a *advisory.Advisory) string {
	var b strings.Builder
	b.WriteString(a.ID)
	if a.Summary != "" {
		b.WriteString(" (")
		b.WriteString(a.Summary)
		b.WriteString(")")
	}
	if a.URL != "" {
		b.WriteString(" at ")
		b.WriteString(a.URL)
	}
	return b.String()
}

// describeFinding renders one deps.dev finding for the explanation.
func (maliciousAdvisory) describeFinding(f depsdev.Finding) string {
	text := f.Type + " finding"
	if f.Risk != "" {
		text += " (" + f.Risk + ")"
	}
	if f.Detail != "" {
		text += ": " + f.Detail
	}
	return text
}
