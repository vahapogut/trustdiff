package model

import "encoding/json"

// Analysis is an attributed external scanner supplement, not a trustdiff finding
// or a malware-free assertion. Status is completed, partial or unavailable.
type Analysis struct {
	Ref         PackageRef                 `json:"ref"`
	Source      string                     `json:"source"`
	ToolVersion string                     `json:"tool_version,omitempty"`
	Status      string                     `json:"status"`
	Issues      int                        `json:"issues"`
	Results     map[string]json.RawMessage `json:"results,omitempty"`
	Risks       []AnalysisRisk             `json:"risks,omitempty"`
	Errors      map[string]string          `json:"errors,omitempty"`
	Message     string                     `json:"message,omitempty"`
}

// AnalysisRisk retains an external risk description. The scanner's rule results
// carry source snippets, so they are not duplicated in this compact summary.
type AnalysisRisk struct {
	Name              string `json:"name"`
	Category          string `json:"category"`
	Severity          string `json:"severity"`
	ThreatRule        string `json:"threat_rule"`
	ThreatDescription string `json:"threat_description"`
	FilePath          string `json:"file_path"`
}
