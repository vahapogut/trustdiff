package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/jsonschema"
)

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{name: "empty file", doc: "", wantErr: "empty policy file"},
		{name: "unknown top-level key", doc: "version: 1\ncooldwon: 3d\n", wantErr: "cooldwon"},
		{name: "unknown key in check object", doc: "version: 1\nchecks:\n  vulnerability: { level: block, severity: high }\n", wantErr: `unknown key "severity"`},
		{name: "bad level", doc: "version: 1\nchecks:\n  young-version: loud\n", wantErr: "unknown level"},
		{name: "bad duration", doc: "version: 1\ncooldown: 3 days\n", wantErr: "duration"},
		{name: "zero duration", doc: "version: 1\ncooldown: 0d\n", wantErr: "must be positive"},
		{name: "version 2", doc: "version: 2\n", wantErr: "version must be 1"},
		{name: "version string", doc: "version: one\n", wantErr: "line 1"},
		{name: "unknown check", doc: "version: 1\nchecks:\n  bogus: warn\n", wantErr: `unknown check "bogus"`},
		{name: "bad severity", doc: "version: 1\nchecks:\n  vulnerability: { min_severity: extreme }\n", wantErr: "min_severity must be one of"},
		{name: "allow without reason", doc: "version: 1\nallow:\n  - check: low-usage\n    package: npm:x\n", wantErr: "reason is required"},
		{name: "allow with empty reason", doc: "version: 1\nallow:\n  - check: low-usage\n    package: npm:x\n    reason: \"\"\n", wantErr: "reason is required"},
		{name: "allow bad date", doc: "version: 1\nallow:\n  - check: low-usage\n    package: npm:x\n    reason: ok\n    expires: 01/03/2027\n", wantErr: "want a date"},
		{name: "double star glob", doc: "version: 1\ncooldown_exclude:\n  - \"npm:@myorg/**\"\n", wantErr: `"**" is not supported`},
		{name: "unknown ecosystem", doc: "version: 1\necosystems:\n  gem:\n    cooldown: 1d\n", wantErr: `unknown ecosystem "gem"`},
		{name: "unknown key in override", doc: "version: 1\necosystems:\n  npm:\n    previous_versions_window: 3\n", wantErr: "previous_versions_window"},
		{name: "bad on_data_unavailable", doc: "version: 1\non_data_unavailable: panic\n", wantErr: "on_data_unavailable must be warn or fail"},
		{name: "checks is a list", doc: "version: 1\nchecks:\n  - young-version\n", wantErr: "line 3"},
		{name: "duplicate key", doc: "version: 1\ncooldown: 3d\ncooldown: 4d\n", wantErr: "already defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.doc))
			if err == nil {
				t.Fatalf("Parse accepted:\n%s\nwant an error containing %q", tt.doc, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Parse error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseAcceptsSpellings(t *testing.T) {
	p := mustParse(t, "version: 1\ncooldown: P3D\ncooldown_exclude: [\"@myorg/*\"]\nchecks:\n  low-usage: { min_weekly_downloads: 10 }\nallow:\n  - check: vulnerability\n    package: \"pypi:requests@2.*\"\n    reason: no fix yet\n    expires: \"2030-01-01\"\n")
	if time := p.Cooldown; time != Duration(3*day) {
		t.Errorf("Cooldown = %v", time)
	}
	if got := p.Allow[0].Expires.String(); got != "2030-01-01" {
		t.Errorf("quoted expires = %q", got)
	}
	if p.Checks["low-usage"].Level != nil || *p.Checks["low-usage"].MinWeeklyDownloads != 10 {
		t.Errorf("low-usage = %+v", p.Checks["low-usage"])
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(exampleYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(p, Default()) {
		t.Fatal("Load(example) differs from Default()")
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil || !strings.Contains(err.Error(), "read policy") {
		t.Errorf("Load(missing) error = %v", err)
	}
	if err := os.WriteFile(path, []byte("version: 1\nnope: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("Load(invalid) error = %v, want it to name the file", err)
	}
}

// The published schema and the embedded one must be the same bytes, must stay inside
// the validator's keyword subset, and must agree with the typed decoder.
func TestSchemaFiles(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("..", "..", "schema", "policy.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(published, SchemaJSON) {
		t.Fatal("schema/policy.v1.json and internal/policy/policy.v1.json differ; copy one over the other")
	}
	schema, err := jsonschema.Compile(SchemaJSON)
	if err != nil {
		t.Fatal(err)
	}
	if unsupported := schema.UnsupportedKeywords(); len(unsupported) != 0 {
		t.Fatalf("schema uses keywords the validator does not enforce: %v", unsupported)
	}
	if !json.Valid(SchemaJSON) {
		t.Fatal("schema is not valid JSON")
	}
}

func TestValidateSchema(t *testing.T) {
	if err := ValidateSchema([]byte(exampleYAML)); err != nil {
		t.Fatalf("example rejected by the schema: %v", err)
	}
	if err := ValidateSchema(DefaultYAML()); err != nil {
		t.Fatalf("default.yaml rejected by the schema: %v", err)
	}
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{name: "unknown key", doc: "version: 1\ncooldwon: 3d\n", wantErr: "cooldwon"},
		{name: "bad level enum", doc: "version: 1\nchecks:\n  young-version: loud\n", wantErr: "young-version"},
		{name: "version 2", doc: "version: 2\n", wantErr: "version"},
		{name: "missing version", doc: "cooldown: 3d\n", wantErr: "version"},
		{name: "bad duration", doc: "version: 1\ncooldown: 3 days\n", wantErr: "cooldown"},
		{name: "option on wrong check", doc: "version: 1\nchecks:\n  young-version: { min_severity: high }\n", wantErr: "young-version"},
		{name: "allow without reason", doc: "version: 1\nallow:\n  - check: low-usage\n    package: npm:x\n", wantErr: "reason"},
		{name: "bad expires", doc: "version: 1\nallow:\n  - check: low-usage\n    package: npm:x\n    reason: ok\n    expires: soon\n", wantErr: "expires"},
		{name: "unknown ecosystem", doc: "version: 1\necosystems:\n  gem: {}\n", wantErr: "gem"},
		{name: "negative window", doc: "version: 1\nprevious_versions_window: -1\n", wantErr: "previous_versions_window"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSchema([]byte(tt.doc))
			if err == nil {
				t.Fatalf("schema accepted:\n%s", tt.doc)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("schema error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestNodeToValueTypes(t *testing.T) {
	var root yaml.Node
	doc := "version: 1\nprevious_versions_window: 5\ncooldown: \"3d\"\nallow:\n  - check: low-usage\n    package: npm:x\n    reason: ok\n    expires: 2027-03-01\n"
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatal(err)
	}
	v, err := nodeToValue(&root)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if _, ok := m["version"].(float64); !ok {
		t.Errorf("version decoded as %T, want float64", m["version"])
	}
	if _, ok := m["cooldown"].(string); !ok {
		t.Errorf("quoted cooldown decoded as %T, want string", m["cooldown"])
	}
	entry := m["allow"].([]any)[0].(map[string]any)
	if got, ok := entry["expires"].(string); !ok || got != "2027-03-01" {
		t.Errorf("unquoted date decoded as %T %v, want the string 2027-03-01", entry["expires"], entry["expires"])
	}
}
