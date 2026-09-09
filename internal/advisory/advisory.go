// Package advisory defines the advisory data the checks consume, independent of
// where it came from. The subpackages osv and depsdev are the two sources: OSV.dev
// for vulnerability and malicious-package advisories, deps.dev for cross-checks
// such as verified attestations, deprecation and similarly named packages.
package advisory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Severity buckets a CVSS score or a database-specific label. Unknown counts as
// Medium when a policy threshold is applied (brief section 4, TD010).
type Severity int

// Severities from least to most severe.
const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityUnknown:  "unknown",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// ParseSeverity accepts the policy spellings and the GHSA labels (MODERATE is medium).
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return SeverityLow, nil
	case "medium", "moderate":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	case "unknown", "":
		return SeverityUnknown, nil
	}
	return SeverityUnknown, fmt.Errorf("unknown severity %q", s)
}

// SeverityFromScore buckets a CVSS v3 or v4 base score with the FIRST ratings.
func SeverityFromScore(score float64) Severity {
	switch {
	case score <= 0:
		return SeverityUnknown
	case score < 4.0:
		return SeverityLow
	case score < 7.0:
		return SeverityMedium
	case score < 9.0:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// Effective is the severity used against a policy threshold: unknown counts as medium.
func (s Severity) Effective() Severity {
	if s == SeverityUnknown {
		return SeverityMedium
	}
	return s
}

// Advisory is one published advisory that affects a package version.
type Advisory struct {
	// ID is the advisory identifier, for example GHSA-xxxx or MAL-2026-1234.
	ID string `json:"id"`
	// Aliases are other identifiers for the same advisory (CVE ids).
	Aliases []string `json:"aliases,omitempty"`
	// Summary is the one-line description from the source.
	Summary string `json:"summary,omitempty"`
	// Severity is the bucketed severity; Score is the CVSS base score when known.
	Severity Severity `json:"severity"`
	Score    float64  `json:"score,omitempty"`
	// Malicious is true for malicious-package advisories (OSV MAL-*).
	Malicious bool      `json:"malicious"`
	Published time.Time `json:"published,omitempty"`
	Modified  time.Time `json:"modified,omitempty"`
	// URL points at the advisory page.
	URL string `json:"url,omitempty"`
}

// Source answers advisories for many package versions in one round trip.
type Source interface {
	// Advisories returns the advisories affecting each ref. Refs with none are
	// absent from the map; a ref the source cannot answer is reported through err.
	Advisories(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef][]Advisory, error)
}
