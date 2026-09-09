package checks

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

// TD010 vulnerability reports every OSV advisory that affects the version and whose
// severity is at or above the policy's min_severity (default high). An advisory
// without a usable severity counts as medium, per brief section 4: it is reported
// under a low or medium threshold and passes a high one. One finding per advisory,
// most severe first. Malicious-package advisories belong to TD009 and are left out.
// The check is skipped when OSV was unavailable; deps.dev VULNERABLE findings are not
// a substitute, since a live findingsbatch on 2026-09-09 returned none for
// npm lodash 4.17.15 while OSV listed six advisories for it.
//
// Evidence keys (one finding per advisory):
//
//	advisory_id         the OSV id
//	aliases             other identifiers of the same advisory (CVE ids), when any
//	severity            the severity as reported: unknown, low, medium, high or critical
//	effective_severity  the severity compared with the threshold (unknown counts as medium)
//	score               the CVSS base score, when the advisory carries one
//	summary             the advisory's one-line summary, when any
//	url                 the advisory page, when known
//	min_severity        the threshold applied
//
// OSV shape, verified 2026-09-09: POST https://api.osv.dev/v1/querybatch returns
// {results: [{vulns: [{id, modified}]}]} and GET https://api.osv.dev/v1/vulns/<id>
// returns summary, database_specific.severity (GHSA labels such as CRITICAL),
// severity[] with CVSS vectors, aliases and references; the OSV client folds those
// into advisory.Advisory (Severity, Score, Summary, Aliases, URL).

type vulnerability struct{}

func init() { Register(vulnerability{}) }

// ID implements Check.
func (vulnerability) ID() string { return "TD010" }

// Name implements Check.
func (vulnerability) Name() string { return "vulnerability" }

// Ecosystems implements Check; nil means every ecosystem.
func (vulnerability) Ecosystems() []model.Ecosystem { return nil }

// Run implements Check.
func (c vulnerability) Run(_ context.Context, s *Subject) Result {
	if reason, down := s.Skipped(SourceOSV); down {
		return Skip(c.Name(), reason)
	}
	threshold, thresholdName := c.threshold(s)

	type match struct {
		adv       *advisory.Advisory
		effective advisory.Severity
	}
	var matches []match
	for i := range s.Advisories {
		a := &s.Advisories[i]
		if a.Malicious {
			continue
		}
		if effective := a.Severity.Effective(); effective >= threshold {
			matches = append(matches, match{adv: a, effective: effective})
		}
	}
	slices.SortFunc(matches, func(x, y match) int {
		if x.effective != y.effective {
			return cmp.Compare(y.effective, x.effective)
		}
		return strings.Compare(x.adv.ID, y.adv.ID)
	})

	findings := make([]model.Finding, 0, len(matches))
	for _, m := range matches {
		findings = append(findings, c.finding(s, m.adv, m.effective, thresholdName))
	}
	return Result{Findings: findings}
}

// threshold resolves min_severity for the subject. The policy loader validates the
// value (low, medium, high or critical), so an empty or unparsable one means the
// setting was built without the option; the built-in default applies then.
func (c vulnerability) threshold(s *Subject) (advisory.Severity, string) {
	name := s.Setting(c.Name()).MinSeverity
	if sev, err := advisory.ParseSeverity(name); err == nil && sev != advisory.SeverityUnknown {
		return sev, name
	}
	if def, ok := policy.DefaultCheck(c.Name()); ok {
		if sev, err := advisory.ParseSeverity(def.MinSeverity); err == nil && sev != advisory.SeverityUnknown {
			return sev, def.MinSeverity
		}
	}
	return advisory.SeverityHigh, advisory.SeverityHigh.String()
}

// finding builds the finding for one advisory.
func (c vulnerability) finding(s *Subject, a *advisory.Advisory, effective advisory.Severity, thresholdName string) model.Finding {
	evidence := map[string]any{
		"advisory_id":        a.ID,
		"severity":           a.Severity.String(),
		"effective_severity": effective.String(),
		"min_severity":       thresholdName,
	}
	if len(a.Aliases) > 0 {
		evidence["aliases"] = a.Aliases
	}
	if a.Score > 0 {
		evidence["score"] = a.Score
	}
	if a.Summary != "" {
		evidence["summary"] = a.Summary
	}
	if a.URL != "" {
		evidence["url"] = a.URL
	}

	score := ""
	if a.Score > 0 {
		score = fmt.Sprintf(" (CVSS %.1f)", a.Score)
	}
	var title, severity string
	if a.Severity == advisory.SeverityUnknown {
		title = a.ID + ": vulnerability of unknown severity, counted as medium"
		severity = "no usable severity, which counts as medium"
	} else {
		title = fmt.Sprintf("%s: %s severity vulnerability%s", a.ID, effective, score)
		severity = fmt.Sprintf("severity %s%s", effective, score)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "OSV advisory %s", a.ID)
	if len(a.Aliases) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(a.Aliases, ", "))
	}
	fmt.Fprintf(&b, " affects %s with %s", s.Ref, severity)
	if a.Summary != "" {
		b.WriteString(": ")
		b.WriteString(a.Summary)
	}
	if a.URL != "" {
		b.WriteString(", see ")
		b.WriteString(a.URL)
	}
	fmt.Fprintf(&b, "; the policy reports vulnerabilities of severity %s or above (vulnerability.min_severity)", thresholdName)
	return NewFinding(c, s, title, b.String(), evidence)
}
