package checks

import (
	"context"
	"fmt"

	"github.com/vahapogut/trustdiff/internal/model"
)

// TD012 low-usage reports a package few people install. The registry's weekly
// download count is compared with the policy's min_weekly_downloads (default 500).
// When the registry reports no count (Subject.Downloads is -1, which is always the
// case for PyPI) the check falls back to a deps.dev LOW_USAGE finding. It is skipped
// when neither is available, the normal outcome for PyPI without deps.dev, and also
// when the count is missing because the request for it failed rather than because the
// registry publishes none: a fallback that found nothing does not stand in for a
// count nobody read. It applies to every ecosystem and is info by default.
//
// Evidence keys:
//
//	source                where the signal came from: registry or deps.dev
//	weekly_downloads      the registry's weekly count (registry source only)
//	min_weekly_downloads  the policy threshold (registry source only)
//	deps_dev_risk         the RISK_* level of the LOW_USAGE finding, when deps.dev gave one (deps.dev source only)
//	deps_dev_detail       the finding's text, when deps.dev gave one (deps.dev source only)
//
// Download counts, verified 2026-09-09: npm GET https://api.npmjs.org/downloads/point/last-week/<name>
// returns {"downloads": N, "start", "end", "package"} for the last seven days;
// crates.io GET https://crates.io/api/v1/crates/<name> returns crate.downloads and
// crate.recent_downloads (a 90-day figure); PyPI GET https://pypi.org/pypi/<project>/json
// returns -1 for every count. The registry clients reduce what they have to the
// weekly figure in Subject.Downloads, or -1.
//
// deps.dev finding types, verified 2026-09-09 against https://docs.deps.dev/api/v3alpha/:
// LOW_USAGE is one of NOT_FOUND, MALICIOUS, DEPRECATED, COOLDOWN, LOW_USAGE,
// VULNERABLE and REMEDIATION. A live POST /v3alpha/findingsbatch the same day
// returned a package-level NOT_FOUND finding with RISK_CRITICAL for a package
// deps.dev has never seen; no LOW_USAGE finding was observed live, so its name rests
// on the docs.

// deps.dev finding types this check looks at.
const (
	lowUsageFindingType  = "LOW_USAGE"
	lowUsageNotFoundType = "NOT_FOUND"
)

type lowUsage struct{}

func init() { Register(lowUsage{}) }

// ID implements Check.
func (lowUsage) ID() string { return "TD012" }

// Name implements Check.
func (lowUsage) Name() string { return "low-usage" }

// Ecosystems implements Check; nil means every ecosystem.
func (lowUsage) Ecosystems() []model.Ecosystem { return nil }

// Run implements Check.
func (c lowUsage) Run(_ context.Context, s *Subject) Result {
	if s.Downloads >= 0 {
		return c.fromRegistry(s)
	}

	noCount, _ := s.Skipped(SourceDownloads)
	if noCount == "" {
		noCount = "the registry reports no download counts for " + s.Ref.Package().String()
	}
	if reason, down := s.Skipped(SourceDepsDev); down {
		return Skip(c.ID(), noCount+"; "+reason)
	}
	for _, f := range s.DepsDevFindings {
		if f.Type == lowUsageFindingType {
			return c.fromDepsDev(s, noCount, f.Risk, f.Detail)
		}
	}
	if (s.DepsDev != nil && !s.DepsDev.Found) || c.hasFinding(s, lowUsageNotFoundType) {
		return Skip(c.ID(), noCount+"; deps.dev has not indexed "+s.Ref.String())
	}
	if s.DepsDev == nil && len(s.DepsDevFindings) == 0 {
		return Skip(c.ID(), noCount+"; no deps.dev data for "+s.Ref.String())
	}
	// deps.dev was asked and reported nothing. That clears the package only when the
	// missing count is the registry's own answer (PyPI publishes none) rather than a
	// request that failed: a count nobody could compare with the threshold is not a
	// threshold anything passed. deps.dev needs no naming here, because a failure of
	// its own already returned above.
	return cleanOrSkip(c, s, SourceDownloads)
}

// fromRegistry compares the registry's weekly count with the policy threshold.
func (c lowUsage) fromRegistry(s *Subject) Result {
	threshold := s.Setting(c.Name()).MinWeeklyDownloads
	if s.Downloads >= threshold {
		return Result{}
	}
	evidence := map[string]any{
		"source":               SourceRegistry,
		"weekly_downloads":     s.Downloads,
		"min_weekly_downloads": threshold,
	}
	title := fmt.Sprintf("%d weekly downloads, below %d", s.Downloads, threshold)
	explanation := fmt.Sprintf("the registry reports %d downloads in the last week for %s, below the policy threshold of %d (low-usage.min_weekly_downloads)",
		s.Downloads, s.Ref.Package(), threshold)
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
}

// fromDepsDev reports the deps.dev LOW_USAGE finding.
func (c lowUsage) fromDepsDev(s *Subject, noCount, risk, detail string) Result {
	evidence := map[string]any{"source": SourceDepsDev}
	explanation := noCount + "; deps.dev reports a " + lowUsageFindingType + " finding"
	if risk != "" {
		evidence["deps_dev_risk"] = risk
		explanation += " (" + risk + ")"
	}
	if detail != "" {
		evidence["deps_dev_detail"] = detail
		explanation += ": " + detail
	}
	return Result{Findings: []model.Finding{NewFinding(c, s, "deps.dev reports low usage", explanation, evidence)}}
}

func (lowUsage) hasFinding(s *Subject, typ string) bool {
	for _, f := range s.DepsDevFindings {
		if f.Type == typ {
			return true
		}
	}
	return false
}
