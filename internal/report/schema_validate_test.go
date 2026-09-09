package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

// A lockfile line is one based and the summary values are counts, so the schema
// bounds them: line 0 and a negative counter are rejected. SARIF puts the same lower
// bound on region.startLine, so a report that validates here converts to a SARIF log
// that validates too.
func TestReportSchemaBoundsNumbers(t *testing.T) {
	schema, err := jsonschema.Compile(SchemaJSON)
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "report.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		old     string
		new     string
		pointer string
	}{
		{name: "line zero", old: `"line": 42`, new: `"line": 0`, pointer: "/subjects/0/location/line"},
		{name: "negative subjects", old: `"subjects": 3`, new: `"subjects": -1`, pointer: "/summary/subjects"},
		{name: "negative block", old: `"block": 1`, new: `"block": -1`, pointer: "/summary/findings/block"},
		{name: "negative warn", old: `"warn": 1`, new: `"warn": -1`, pointer: "/summary/findings/warn"},
		{name: "negative info", old: `"info": 0`, new: `"info": -1`, pointer: "/summary/findings/info"},
		{name: "negative skipped", old: `"skipped": 1,`, new: `"skipped": -1,`, pointer: "/summary/skipped"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broken := bytes.Replace(golden, []byte(tt.old), []byte(tt.new), 1)
			if bytes.Equal(broken, golden) {
				t.Fatalf("golden file does not contain %s", tt.old)
			}
			err := schema.Validate(broken)
			if err == nil {
				t.Fatalf("schema accepted %s", tt.new)
			}
			if want := "#" + tt.pointer + ": minimum:"; !strings.Contains(err.Error(), want) {
				t.Fatalf("error does not name %s:\n%v", want, err)
			}
		})
	}
}
