package guarddog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// The pinned JSON reporter serializes the CLI result directly. Errors may coexist
// with issues=0, including a download failure with no version/results/risks fields.
// See upstream cli.py and analyzer/analyzer.py, verified 2026-09-29.
func parseReport(ref model.PackageRef, body []byte) (Result, error) {
	result := Result{Ref: ref, Source: SourceURL, ToolVersion: SupportedVersion, Status: "unavailable"}
	fail := func(message string) (Result, error) {
		result.Message = message
		return result, errors.New(message)
	}
	var report struct {
		Package string                     `json:"package"`
		Version string                     `json:"package_version"`
		Issues  *int                       `json:"issues"`
		Errors  map[string]string          `json:"errors"`
		Results map[string]json.RawMessage `json:"results"`
		Risks   []Risk                     `json:"risks"`
		Path    string                     `json:"path"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		return fail("GuardDog returned invalid JSON or an incompatible report shape")
	}
	if report.Package != ref.Name {
		return fail("GuardDog report package does not match the requested release")
	}
	if report.Issues == nil || *report.Issues < 0 || report.Errors == nil {
		return fail("GuardDog report is missing valid issue counts or rule errors")
	}
	result.Errors = report.Errors
	if report.Version != ref.Version {
		return fail("GuardDog did not confirm the exact requested version; download or identity verification failed")
	}
	if report.Results == nil || report.Risks == nil {
		return fail("GuardDog report is missing rule results or risk records")
	}
	prefix := ""
	if (path.IsAbs(report.Path) && path.Clean(report.Path) != "/") || strings.HasPrefix(report.Path, "<guarddog-temp>/") {
		prefix = strings.TrimSuffix(report.Path, "/") + "/"
	}
	for rule, message := range report.Errors {
		report.Errors[rule] = relativePath(message, prefix)
	}
	for _, risk := range report.Risks {
		if risk.Name == "" || risk.Category == "" || risk.ThreatRule == "" ||
			(risk.Severity != "low" && risk.Severity != "medium" && risk.Severity != "high") {
			return fail("GuardDog report contains an invalid risk record")
		}
	}
	results := make(map[string]json.RawMessage)
	for name, value := range report.Results {
		value = bytes.TrimSpace(value)
		if name == "" || len(value) == 0 {
			return fail("GuardDog returned an invalid rule result")
		}
		// Metadata rules return null/string; source rules return {} or a list of
		// match objects. Reject unrelated types rather than treating them as clean.
		switch value[0] {
		case 'n':
			continue
		case '"':
			var message string
			if err := json.Unmarshal(value, &message); err != nil {
				return fail("GuardDog returned an invalid metadata result")
			}
			if message == "" {
				continue
			}
			value, _ = json.Marshal(relativePath(message, prefix))
		case '{':
			var empty map[string]json.RawMessage
			if err := json.Unmarshal(value, &empty); err != nil || len(empty) != 0 {
				return fail("GuardDog returned an incompatible source rule result")
			}
			continue
		case '[':
			var matches []map[string]json.RawMessage
			if err := json.Unmarshal(value, &matches); err != nil {
				return fail("GuardDog returned invalid source matches")
			}
			if len(matches) == 0 {
				continue
			}
			for _, match := range matches {
				if len(match) == 0 {
					return fail("GuardDog returned an empty source match")
				}
				for _, key := range []string{"location", "file_path"} {
					if raw, ok := match[key]; ok {
						var location string
						if err := json.Unmarshal(raw, &location); err != nil {
							return fail("GuardDog returned an invalid source location")
						}
						match[key], _ = json.Marshal(relativePath(location, prefix))
					}
				}
			}
			value, _ = json.Marshal(matches)
		default:
			return fail("GuardDog returned an incompatible rule result type")
		}
		results[name] = value
	}
	result.Issues = *report.Issues
	result.Results = results
	result.Risks = report.Risks
	for i := range result.Risks {
		result.Risks[i].FilePath = relativePath(result.Risks[i].FilePath, prefix)
	}
	result.Status = "completed"
	if len(report.Errors) != 0 {
		result.Status = "partial"
		return fail(fmt.Sprintf("GuardDog could not complete %d rule(s); available evidence is retained", len(report.Errors)))
	}
	return result, nil
}

func relativePath(value, prefix string) string {
	if prefix == "" {
		return value
	}
	return strings.ReplaceAll(value, prefix, "")
}
