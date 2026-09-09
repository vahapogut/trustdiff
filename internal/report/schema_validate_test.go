package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
)

// The published schema must stay inside the keyword subset internal/jsonschema
// enforces, and every report the JSON writer produces must validate against it.
func TestReportSchemaValidatesJSONOutput(t *testing.T) {
	schema, err := jsonschema.Compile(SchemaJSON)
	if err != nil {
		t.Fatalf("compile schema/report.v1.json: %v", err)
	}
	if unsupported := schema.UnsupportedKeywords(); len(unsupported) != 0 {
		t.Fatalf("schema uses keywords the validator does not enforce: %v", unsupported)
	}

	golden, err := os.ReadFile(filepath.Join("testdata", "report.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(golden); err != nil {
		t.Errorf("testdata/report.json.golden does not match the schema:\n%v", err)
	}

	empty := Build(nil, Tool{Name: "trustdiff", Version: "dev", Commit: "none", Date: "unknown", GoVersion: "go1.26"}, Policy{FailOn: "block"}, model.LevelBlock)
	var buf bytes.Buffer
	if err := (JSON{}).Write(&buf, empty); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(buf.Bytes()); err != nil {
		t.Errorf("empty report does not match the schema:\n%v\n%s", err, buf.String())
	}

	unavailable := Build(nil, CurrentTool(), Policy{FailOn: "never"}, model.LevelOff)
	unavailable.SetExitCode(3)
	buf.Reset()
	if err := (JSON{}).Write(&buf, unavailable); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(buf.Bytes()); err != nil {
		t.Errorf("exit code 3 report does not match the schema:\n%v", err)
	}
}

func TestReportSchemaRejectsForeignFields(t *testing.T) {
	schema, err := jsonschema.Compile(SchemaJSON)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "report.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	broken := bytes.Replace(golden, []byte(`"schema": "trustdiff.report/1"`), []byte(`"schema": "trustdiff.report/2"`), 1)
	if bytes.Equal(broken, golden) {
		t.Fatal("golden file does not carry the schema id the test expects")
	}
	if err := schema.Validate(broken); err == nil {
		t.Error("schema accepted a report with a different schema id")
	}
}
