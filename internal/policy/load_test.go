package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
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
		{name: "duplicate key in check object", doc: "version: 1\nchecks:\n  vulnerability: { level: block, level: warn }\n", wantErr: "already defined"},
		{name: "zero window", doc: "version: 1\nprevious_versions_window: 0\n", wantErr: "at least 1"},
		{name: "negative window", doc: "version: 1\nprevious_versions_window: -1\n", wantErr: "at least 1"},
		{name: "window not a number", doc: "version: 1\nprevious_versions_window: five\n", wantErr: "line 2"},
		{name: "window not whole", doc: "version: 1\nprevious_versions_window: 5.5\n", wantErr: "line 2: previous_versions_window: want a whole number"},
		{name: "window is a list", doc: "version: 1\nprevious_versions_window: [5]\n", wantErr: "line 2: previous_versions_window: want a whole number"},
		{name: "level wrong case", doc: "version: 1\nchecks:\n  young-version: Warn\n", wantErr: `line 3: level "Warn" must be written in lowercase as warn`},
		{name: "object level wrong case", doc: "version: 1\nchecks:\n  vulnerability: { level: BLOCK }\n", wantErr: `line 3: level: level "BLOCK" must be written in lowercase as block`},
		{name: "second document", doc: "version: 1\ncooldown: 1d\n---\nversion: 1\ncooldown: 9d\nbogus: 1\n", wantErr: "single YAML document"},
		{name: "merge of a scalar", doc: "version: 1\necosystems:\n  npm: &base\n    cooldown: 5d\n  pypi:\n    <<: 3d\n", wantErr: "merge"},
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

// Commenting out the example entries that "policy init" wrote leaves a key with a
// null value. The typed decoder reads that as "not set", and the schema must agree.
func TestParseAcceptsEmptyKeys(t *testing.T) {
	tests := []struct{ name, doc string }{
		{name: "allow", doc: "version: 1\nallow:\n  # - check: install-script-present\n  #   package: npm:esbuild\n  #   reason: reviewed\n"},
		{name: "checks", doc: "version: 1\nchecks:\n"},
		{name: "cooldown_exclude", doc: "version: 1\ncooldown_exclude:\n"},
		{name: "ecosystems", doc: "version: 1\necosystems:\n"},
		{name: "ecosystem override", doc: "version: 1\necosystems:\n  cargo:\n"},
		{name: "cooldown tilde", doc: "version: 1\ncooldown: ~\n"},
		{name: "cooldown null", doc: "version: 1\ncooldown: null\n"},
		{name: "check entry", doc: "version: 1\nchecks:\n  young-version:\n"},
	}
	var none *Policy
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustParse(t, tt.doc)
			if len(p.Allow) != 0 || len(p.CooldownExclude) != 0 {
				t.Errorf("Allow = %v, CooldownExclude = %v, want both empty", p.Allow, p.CooldownExclude)
			}
			for _, eco := range model.Ecosystems() {
				if got, want := p.Effective(eco), none.Effective(eco); !reflect.DeepEqual(got, want) {
					t.Errorf("Effective(%s) = %+v, want the built-in defaults", eco, got)
				}
			}
		})
	}
}

func TestNodeToValueDropsNullValues(t *testing.T) {
	var root yaml.Node
	doc := "version: 1\nallow:\ncooldown: ~\nchecks:\n  young-version:\n  low-usage: warn\ncooldown_exclude: [~]\n"
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatal(err)
	}
	v, err := nodeToValue(&root)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	for _, key := range []string{"allow", "cooldown"} {
		if _, ok := m[key]; ok {
			t.Errorf("null %s was kept as %v, want the key dropped", key, m[key])
		}
	}
	checks := m["checks"].(map[string]any)
	if _, ok := checks["young-version"]; ok || checks["low-usage"] != "warn" {
		t.Errorf("checks = %v, want low-usage only", checks)
	}
	// A null list item is not a key and stays, so the schema still reports it.
	if items := m["cooldown_exclude"].([]any); len(items) != 1 || items[0] != nil {
		t.Errorf("cooldown_exclude = %v, want [nil]", items)
	}
}

// mergeYAML shares one override between ecosystems with YAML merge keys. The typed
// decoder applies them (explicit keys win, then the first map of a list), and the
// schema must see the merged result rather than a "<<" property.
const mergeYAML = `version: 1
ecosystems:
  npm: &npm
    cooldown: 5d
    checks:
      low-usage: off
  cargo: &cargo
    cooldown: 9d
  pypi:
    <<: [*npm, *cargo]
  jsr:
    cooldown: 1d
    <<: *npm
  deno:
    <<: *npm
    cooldown: 2d
`

func TestParseAppliesMergeKeys(t *testing.T) {
	p := mustParse(t, mergeYAML)
	want := map[model.Ecosystem]time.Duration{model.NPM: 5 * day, model.Cargo: 9 * day, model.PyPI: 5 * day, model.JSR: day, model.Deno: 2 * day}
	for eco, cooldown := range want {
		s := p.Effective(eco)
		if s.Cooldown != cooldown {
			t.Errorf("Effective(%s).Cooldown = %v, want %v", eco, s.Cooldown, cooldown)
		}
		if lvl := s.Checks["low-usage"].Level; eco != model.Cargo && lvl != model.LevelOff {
			t.Errorf("Effective(%s) low-usage = %s, want off from the merged override", eco, lvl)
		}
	}
	if p.Effective(model.Cargo).Checks["low-usage"].Level != model.LevelInfo {
		t.Error("cargo must keep the default low-usage level: nothing was merged into it")
	}
}

func TestNodeToValueAppliesMergeKeys(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(mergeYAML), &root); err != nil {
		t.Fatal(err)
	}
	v, err := nodeToValue(&root)
	if err != nil {
		t.Fatal(err)
	}
	ecosystems := v.(map[string]any)["ecosystems"].(map[string]any)
	want := map[string]string{"npm": "5d", "cargo": "9d", "pypi": "5d", "jsr": "1d", "deno": "2d"}
	for eco, cooldown := range want {
		override := ecosystems[eco].(map[string]any)
		if _, ok := override["<<"]; ok {
			t.Errorf("%s still carries the merge key: %v", eco, override)
		}
		if override["cooldown"] != cooldown {
			t.Errorf("%s cooldown = %v, want %s", eco, override["cooldown"], cooldown)
		}
		if _, ok := override["checks"]; ok != (eco != "cargo") {
			t.Errorf("%s checks present = %v", eco, ok)
		}
	}

	for _, bad := range []string{
		"a: &x 3d\nb:\n  <<: *x\n",
		"b:\n  <<: 3d\n",
		"b:\n  <<:\n",
		"a: &x 3d\nb:\n  <<: [*x]\n",
	} {
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(bad), &root); err != nil {
			t.Fatal(err)
		}
		if _, err := nodeToValue(&root); err == nil || !strings.Contains(err.Error(), "merge") {
			t.Errorf("nodeToValue(%q) error = %v, want a merge error", bad, err)
		}
	}

	// A quoted "<<" is an ordinary key, for the typed decoder and for the schema.
	if err := ValidateSchema([]byte("version: 1\n\"<<\": {}\n")); err == nil || !strings.Contains(err.Error(), "<<") {
		t.Errorf("ValidateSchema(quoted <<) = %v, want an unknown property error", err)
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
		{name: "zero window", doc: "version: 1\nprevious_versions_window: 0\n", wantErr: "previous_versions_window"},
		{name: "iso duration without a body", doc: "version: 1\ncooldown: P\n", wantErr: "cooldown"},
		{name: "iso duration with an empty time part", doc: "version: 1\ncooldown: PT\n", wantErr: "cooldown"},
		{name: "iso duration with a dangling T", doc: "version: 1\ncooldown: P1DT\n", wantErr: "cooldown"},
		{name: "override iso duration without a body", doc: "version: 1\necosystems:\n  cargo:\n    cooldown: P\n", wantErr: "cooldown"},
		{name: "expires impossible date", doc: "version: 1\nallow:\n  - check: low-usage\n    package: npm:x\n    reason: ok\n    expires: 2027-13-40\n", wantErr: "expires"},
		{name: "expires impossible day", doc: "version: 1\nallow:\n  - check: low-usage\n    package: npm:x\n    reason: ok\n    expires: 2027-02-30\n", wantErr: "expires"},
		{name: "blank reason", doc: "version: 1\nallow:\n  - check: low-usage\n    package: npm:x\n    reason: \"   \"\n", wantErr: "reason"},
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

// The schema's duration pattern must accept every spelling ParseDuration accepts and
// reject the ISO forms it rejects, so an editor and the binary agree on the file.
func TestSchemaDurationAgreesWithParser(t *testing.T) {
	accepted := []string{"12h", "90m", "1h30m", "45s", "1.5h", "3d", "1w", "1w3d", "3d12h", "0.5d", "P3D", "PT12H", "P1W", "P1DT12H", "PT90M", "PT1H30M", "PT0.5H", "PT30S", "P2DT3H4M5S", "PT1H5S"}
	for _, in := range accepted {
		if _, err := ParseDuration(in); err != nil {
			t.Fatalf("ParseDuration(%q): %v", in, err)
		}
		if err := ValidateSchema([]byte("version: 1\ncooldown: " + in + "\n")); err != nil {
			t.Errorf("the schema rejects %q, which ParseDuration accepts: %v", in, err)
		}
	}
	rejected := []string{"P", "PT", "P1DT", "P1M", "P1Y", "P3D12h", "P1WT1H", "PT1S1H", "P1.5.5D", "3", "3D", "1ms", "3 d", "-3d", "p3d"}
	for _, in := range rejected {
		if _, err := ParseDuration(in); err == nil {
			t.Fatalf("ParseDuration(%q) accepted", in)
		}
		if err := ValidateSchema([]byte("version: 1\ncooldown: \"" + in + "\"\n")); err == nil {
			t.Errorf("the schema accepts %q, which ParseDuration rejects", in)
		}
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
