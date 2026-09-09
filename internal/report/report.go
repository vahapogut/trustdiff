// Package report turns the findings of a run into the documents trustdiff prints:
// the human cards for a terminal and the versioned JSON document described by
// schema/report.v1.json. SARIF and markdown writers join in milestone M2.
//
// Build assembles a Report from the per-subject results, decides each verdict and
// the exit code, and normalizes ordering so that the same run always renders the
// same bytes. The writers only render; they never change the data.
//
// The package imports internal/model and internal/version only. It must never import
// internal/cli, which is the package that calls it.
package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/version"
)

// SchemaID identifies the JSON report format. It changes only with a breaking change
// to the document shape; fields are added within a version, never renamed or removed.
const SchemaID = "trustdiff.report/1"

// Verdicts a subject can carry. The first three mirror the highest finding level;
// "ok" means every check ran and found nothing; "skipped" means nothing could be
// evaluated, which is reported rather than mistaken for a pass.
const (
	VerdictBlock   = "block"
	VerdictWarn    = "warn"
	VerdictInfo    = "info"
	VerdictOK      = "ok"
	VerdictSkipped = "skipped"
)

// Report is the complete result of one run, in the shape of schema/report.v1.json.
// Construct it with Build so that slices are never nil and verdicts are consistent.
type Report struct {
	// Schema is always SchemaID.
	Schema   string    `json:"schema"`
	Tool     Tool      `json:"tool"`
	Policy   Policy    `json:"policy"`
	Subjects []Subject `json:"subjects"`
	Summary  Summary   `json:"summary"`
}

// Tool is the build identity of the binary that wrote the report.
type Tool struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
}

// Policy records the settings that shaped the run, after the command line and the
// policy file were reconciled.
type Policy struct {
	// Path is the policy file that was loaded, or empty when defaults were used.
	Path string `json:"path"`
	// Cooldown is the young-version threshold in the spelling the policy accepts, for example 3d.
	Cooldown string `json:"cooldown"`
	// FailOn is the lowest level that makes the exit code 1: block, warn or never.
	FailOn string `json:"fail_on"`
}

// Subject is one evaluated package version with everything the checks said about it.
type Subject struct {
	Ref      model.PackageRef `json:"ref"`
	Location *model.Location  `json:"location,omitempty"`
	// Direct is true when the subject is a direct dependency of the project.
	Direct bool `json:"direct,omitempty"`
	// Evaluated lists the ids of the checks that ran to completion, sorted.
	Evaluated []string `json:"evaluated"`
	// Skipped lists the checks that could not run, with their reasons, sorted by check.
	Skipped []model.Skipped `json:"skipped"`
	// Findings is sorted by level, most severe first, then by id.
	Findings []model.Finding `json:"findings"`
	// Verdict is one of the Verdict constants.
	Verdict string `json:"verdict"`
}

// Summary carries the counts a script or a CI step wants without walking the subjects.
type Summary struct {
	Subjects int `json:"subjects"`
	// Findings counts findings by level name; the keys block, warn and info are always present.
	Findings map[string]int `json:"findings"`
	// Skipped is the number of skipped checks over all subjects.
	Skipped     int    `json:"skipped"`
	ExitCode    int    `json:"exit_code"`
	ExitMeaning string `json:"exit_meaning"`
}

// CurrentTool describes the running binary.
func CurrentTool() Tool {
	info := version.Get()
	return Tool{Name: "trustdiff", Version: info.Version, Commit: info.Commit, Date: info.Date, GoVersion: info.GoVersion}
}

// ParseFailOn maps the --fail-on spellings to a level for Build: "block", "warn", or
// "never", which becomes model.LevelOff and means the exit code is never 1.
func ParseFailOn(s string) (model.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "block":
		return model.LevelBlock, nil
	case "warn":
		return model.LevelWarn, nil
	case "never":
		return model.LevelOff, nil
	}
	return model.LevelOff, fmt.Errorf("unknown fail-on level %q (want block, warn or never)", s)
}

// Build assembles the report. Subjects keep the order they were given; inside each
// subject the evaluated ids are sorted, the skipped checks are sorted by check, and
// the findings are sorted by level, most severe first, then by id, keeping the input
// order for equal keys. The exit code is 1 when any finding is at or above failOn and
// 0 otherwise; failOn model.LevelOff means never. Exit code 3 is the caller's decision:
// call SetExitCode after Build. The input slices are copied, not modified.
func Build(subjects []Subject, tool Tool, policy Policy, failOn model.Level) *Report { //nolint:gocritic // Tool is five strings; the by-value signature is the package API.
	r := &Report{
		Schema:   SchemaID,
		Tool:     tool,
		Policy:   policy,
		Subjects: make([]Subject, 0, len(subjects)),
		Summary: Summary{
			Subjects: len(subjects),
			Findings: map[string]int{
				model.LevelBlock.String(): 0,
				model.LevelWarn.String():  0,
				model.LevelInfo.String():  0,
			},
		},
	}
	exit := 0
	for i := range subjects {
		s := normalizeSubject(&subjects[i])
		for j := range s.Findings {
			level := s.Findings[j].Level
			r.Summary.Findings[level.String()]++
			if failOn != model.LevelOff && level.AtLeast(failOn) {
				exit = 1
			}
		}
		r.Summary.Skipped += len(s.Skipped)
		r.Subjects = append(r.Subjects, s)
	}
	r.SetExitCode(exit)
	return r
}

// SetExitCode overrides the exit code Build derived, for the cases the findings alone
// do not decide, such as 3 when a required data source was unavailable.
func (r *Report) SetExitCode(code int) {
	r.Summary.ExitCode = code
	r.Summary.ExitMeaning = ExitMeaning(code)
}

// ExitMeaning spells out an exit code the way the README documents it.
// The codes are the ones internal/cli defines.
func ExitMeaning(code int) string {
	switch code {
	case 0:
		return "no blocking findings"
	case 1:
		return "blocking findings"
	case 2:
		return "usage or configuration error"
	case 3:
		return "a required data source was unavailable"
	}
	return "unknown exit code"
}

// normalizeSubject returns a copy with non-nil, sorted slices and the verdict set.
func normalizeSubject(in *Subject) Subject {
	out := *in
	out.Evaluated = slices.Clone(in.Evaluated)
	if out.Evaluated == nil {
		out.Evaluated = []string{}
	}
	slices.Sort(out.Evaluated)

	out.Skipped = slices.Clone(in.Skipped)
	if out.Skipped == nil {
		out.Skipped = []model.Skipped{}
	}
	slices.SortStableFunc(out.Skipped, func(a, b model.Skipped) int {
		return cmp.Compare(a.Check, b.Check)
	})

	out.Findings = slices.Clone(in.Findings)
	if out.Findings == nil {
		out.Findings = []model.Finding{}
	}
	slices.SortStableFunc(out.Findings, func(a, b model.Finding) int {
		if a.Level != b.Level {
			return cmp.Compare(b.Level, a.Level)
		}
		return cmp.Compare(a.ID, b.ID)
	})

	out.Verdict = verdict(&out)
	return out
}

// verdict is the highest finding level, or ok when checks ran and found nothing, or
// skipped when no check ran.
func verdict(s *Subject) string {
	top := model.LevelOff
	for i := range s.Findings {
		if level := s.Findings[i].Level; level > top {
			top = level
		}
	}
	switch {
	case top.AtLeast(model.LevelBlock):
		return VerdictBlock
	case top == model.LevelWarn:
		return VerdictWarn
	case top == model.LevelInfo:
		return VerdictInfo
	case len(s.Evaluated) == 0:
		return VerdictSkipped
	}
	return VerdictOK
}
