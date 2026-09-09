// Package advisory defines the advisory data the checks consume, independent of
// where it came from. The subpackages osv and depsdev are the two sources: OSV.dev
// for vulnerability and malicious-package advisories, deps.dev for cross-checks
// such as verified attestations, deprecation and similarly named packages.
package advisory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Severity buckets a CVSS score or a database-specific label. Unknown means the
// source published no usable severity and counts as Medium when a policy
// threshold is applied (brief section 4, TD010); None is a published rating
// (a CVSS v3 base score of 0.0, FIRST qualitative rating None) and counts as
// itself.
type Severity int

// Severities from least to most severe. Unknown sorts below None so that a
// threshold of "low" or higher never admits either.
const (
	SeverityUnknown Severity = iota
	SeverityNone
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityUnknown:  "unknown",
	SeverityNone:     "none",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// ParseSeverity accepts the policy spellings, the FIRST rating "none" and the
// GHSA labels (MODERATE is medium).
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		return SeverityNone, nil
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

// SeverityFromScore buckets a CVSS v3 or v4 base score with the FIRST ratings:
// 0.0 is None, 0.1 to 3.9 Low, 4.0 to 6.9 Medium, 7.0 to 8.9 High, 9.0 and
// above Critical. It is for a score that was computed or published; a record
// without one is SeverityUnknown, which only a negative value maps to here.
func SeverityFromScore(score float64) Severity {
	switch {
	case score < 0:
		return SeverityUnknown
	case score == 0:
		return SeverityNone
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

// Effective is the severity used against a policy threshold: unknown counts as
// medium, every published rating, None included, as itself.
func (s Severity) Effective() Severity {
	if s == SeverityUnknown {
		return SeverityMedium
	}
	return s
}

// Where an advisory's Severity bucket came from, recorded in
// Advisory.SeveritySource so a report can say which source decided when the
// bucket and the CVSS score disagree.
const (
	// SeveritySourceLabel is the source database's own label (GHSA
	// database_specific.severity), which may rate a CVSS v4 assessment while
	// Score holds the v3 base score.
	SeveritySourceLabel = "database_specific"
	// SeveritySourceCVSS3 is the base score computed from the record's CVSS v3
	// vector.
	SeveritySourceCVSS3 = "cvss_v3"
)

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
	// SeveritySource names what decided Severity: SeveritySourceLabel,
	// SeveritySourceCVSS3, or empty when nothing did (Severity is unknown).
	SeveritySource string `json:"severity_source,omitempty"`
	// Malicious is true for malicious-package advisories (OSV MAL-*).
	Malicious bool      `json:"malicious"`
	Published time.Time `json:"published,omitempty"`
	Modified  time.Time `json:"modified,omitempty"`
	// URL points at the advisory page.
	URL string `json:"url,omitempty"`
}

// Source answers advisories for many package versions in one round trip.
type Source interface {
	// Advisories returns the advisories affecting each ref. A ref with none is
	// absent from the map, and so is a ref of an ecosystem the source does not
	// index: an error mentioning the unsupported ecosystems is returned only when
	// every ref was one of them, so a caller must test support per ref
	// (osv.Ecosystem or depsdev.System is empty for such a ref) before it reads
	// an absent ref as "no advisories". A source that answered some refs and
	// not others returns the answered ones together with a *PartialError naming
	// the rest; any other error means no ref was answered.
	Advisories(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef][]Advisory, error)
}

// PartialError accompanies a partial answer from a Source: Refs are the refs
// the source could not answer and the error that lost each, every other ref
// of the call was answered and is in the map. It unwraps to Cause, the first
// error met, so errors.Is and errors.As see httpcache.ErrOffline, a
// *httpcache.StatusError or context.Canceled as they would for a total failure.
type PartialError struct {
	// Source names the source, for the message ("osv").
	Source string
	// Refs maps each unanswered ref to the error that lost it.
	Refs map[model.PackageRef]error
	// Cause is the first error met; the message and Unwrap use it.
	Cause error
}

// namedRefs bounds how many unanswered refs the message spells out.
const namedRefs = 5

func (e *PartialError) Error() string {
	names := make([]string, 0, len(e.Refs))
	for ref := range e.Refs {
		names = append(names, ref.String())
	}
	slices.Sort(names)
	listed := strings.Join(names, ", ")
	if len(names) > namedRefs {
		listed = fmt.Sprintf("%s and %d more", strings.Join(names[:namedRefs], ", "), len(names)-namedRefs)
	}
	return fmt.Sprintf("%s: no answer for %d of the refs (%s): %v", e.Source, len(names), listed, e.Cause)
}

func (e *PartialError) Unwrap() error { return e.Cause }
