package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// The published schema at the repository root and the embedded copy must never drift.
func TestSchemaPublishedCopyIsIdentical(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("..", "..", "schema", "report.v1.json"))
	if err != nil {
		t.Fatalf("read published schema: %v", err)
	}
	if !bytes.Equal(published, SchemaJSON) {
		t.Fatal("schema/report.v1.json and internal/report/report.v1.json differ; copy one over the other")
	}
	if len(SchemaJSON) == 0 || !json.Valid(SchemaJSON) {
		t.Fatal("embedded schema is not valid JSON")
	}
	if bytes.Contains(SchemaJSON, []byte("\r")) {
		t.Fatal("schema must use LF line endings")
	}
}

// The schema is hand written, so the parts that mirror Go constants are checked here.
func TestSchemaMatchesConstants(t *testing.T) {
	var schema struct {
		Schema     string `json:"$schema"`
		Properties struct {
			Schema struct {
				Const string `json:"const"`
			} `json:"schema"`
		} `json:"properties"`
		Definitions struct {
			Tool struct {
				Properties struct {
					Name struct {
						Const string `json:"const"`
					} `json:"name"`
				} `json:"properties"`
			} `json:"tool"`
			Ref struct {
				Properties struct {
					Ecosystem struct {
						Enum []string `json:"enum"`
					} `json:"ecosystem"`
				} `json:"properties"`
			} `json:"ref"`
			Finding struct {
				Properties struct {
					Level struct {
						Enum []string `json:"enum"`
					} `json:"level"`
				} `json:"properties"`
			} `json:"finding"`
			Subject struct {
				Properties struct {
					Verdict struct {
						Enum []string `json:"enum"`
					} `json:"verdict"`
				} `json:"properties"`
			} `json:"subject"`
			Summary struct {
				Properties struct {
					Findings struct {
						Required []string `json:"required"`
					} `json:"findings"`
					ExitCode struct {
						Enum []int `json:"enum"`
					} `json:"exit_code"`
				} `json:"properties"`
			} `json:"summary"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(SchemaJSON, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if schema.Schema != "http://json-schema.org/draft-07/schema#" {
		t.Errorf("$schema = %q, want draft-07", schema.Schema)
	}
	if schema.Properties.Schema.Const != SchemaID {
		t.Errorf("properties.schema.const = %q, want %q", schema.Properties.Schema.Const, SchemaID)
	}
	if schema.Definitions.Tool.Properties.Name.Const != "trustdiff" {
		t.Errorf("tool.name const = %q", schema.Definitions.Tool.Properties.Name.Const)
	}

	ecosystems := make([]string, 0, len(model.Ecosystems()))
	for _, e := range model.Ecosystems() {
		ecosystems = append(ecosystems, e.String())
	}
	if got := schema.Definitions.Ref.Properties.Ecosystem.Enum; !slices.Equal(got, ecosystems) {
		t.Errorf("ref.ecosystem enum = %v, want %v", got, ecosystems)
	}
	if got, want := schema.Definitions.Finding.Properties.Level.Enum, []string{model.LevelBlock.String(), model.LevelWarn.String(), model.LevelInfo.String()}; !slices.Equal(got, want) {
		t.Errorf("finding.level enum = %v, want %v", got, want)
	}
	if got, want := schema.Definitions.Subject.Properties.Verdict.Enum, []string{VerdictBlock, VerdictWarn, VerdictInfo, VerdictOK, VerdictSkipped}; !slices.Equal(got, want) {
		t.Errorf("subject.verdict enum = %v, want %v", got, want)
	}
	if got, want := schema.Definitions.Summary.Properties.Findings.Required, []string{"block", "warn", "info"}; !slices.Equal(got, want) {
		t.Errorf("summary.findings required = %v, want %v", got, want)
	}
	if got, want := schema.Definitions.Summary.Properties.ExitCode.Enum, []int{0, 1, 3}; !slices.Equal(got, want) {
		t.Errorf("summary.exit_code enum = %v, want %v", got, want)
	}
}

// Every finding level and verdict the report can produce must be named in the schema
// summary, so a JSON consumer can rely on the keys being present.
func TestSummaryLevelKeys(t *testing.T) {
	r := Build(nil, testTool(), testPolicy(), model.LevelBlock)
	for _, level := range []model.Level{model.LevelBlock, model.LevelWarn, model.LevelInfo} {
		if _, ok := r.Summary.Findings[level.String()]; !ok {
			t.Errorf("summary.findings lacks the %s key", level)
		}
	}
}
