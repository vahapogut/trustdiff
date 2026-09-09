package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
)

// sarifSchema compiles the vendored SARIF 2.1.0 schema once for the whole package.
var sarifSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sarif-schema-2.1.0.json"))
	if err != nil {
		return nil, err
	}
	return jsonschema.Compile(raw)
})

func compiledSARIFSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schema, err := sarifSchema()
	if err != nil {
		t.Fatalf("compile testdata/sarif-schema-2.1.0.json: %v", err)
	}
	return schema
}

// renderSARIF writes r and fails the test when the log does not match the schema.
func renderSARIF(t *testing.T, r *Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := (SARIF{}).Write(&buf, r); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := normalizeNewlines(buf.Bytes())
	if err := compiledSARIFSchema(t).Validate(out); err != nil {
		t.Fatalf("output does not match SARIF 2.1.0:\n%v\n%s", err, out)
	}
	return out
}

func decodeSARIF(t *testing.T, b []byte) sarifLog {
	t.Helper()
	var log sarifLog
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return log
}

func TestSARIFGolden(t *testing.T) {
	got := assertGolden(t, "report.sarif.golden", SARIF{})
	if err := compiledSARIFSchema(t).Validate(got); err != nil {
		t.Fatalf("testdata/report.sarif.golden does not match SARIF 2.1.0:\n%v", err)
	}
}

// The schema is only worth validating against if it would notice the shape drifting,
// so every field the writer decides is broken on purpose and the exact pointer and
// keyword of the complaint are asserted.
func TestSARIFSchemaCatchesDrift(t *testing.T) {
	schema := compiledSARIFSchema(t)
	golden := string(renderSARIF(t, fixtureReport()))

	tests := []struct {
		name    string
		old     string
		new     string
		pointer string
		keyword string
	}{
		{
			name: "format version", old: `"version": "2.1.0"`, new: `"version": "2.2.0"`,
			pointer: "/version", keyword: "enum",
		},
		{
			name: "result level", old: `"level": "error"`, new: `"level": "fatal"`,
			pointer: "/runs/0/results/0/level", keyword: "enum",
		},
		{
			name: "line before the first", old: `"startLine": 42`, new: `"startLine": 0`,
			pointer: "/runs/0/results/0/locations/0/physicalLocation/region/startLine", keyword: "minimum",
		},
		{
			name: "rule index below no index", old: `"ruleIndex": 2`, new: `"ruleIndex": -2`,
			pointer: "/runs/0/results/0/ruleIndex", keyword: "minimum",
		},
		{
			name: "field SARIF does not define", old: `"ruleId": "TD002",`, new: `"ruleId": "TD002",` + "\n" + `      "verdict": "block",`,
			pointer: "/runs/0/results/0/verdict", keyword: "additionalProperties",
		},
		{
			name: "result without a message", old: `"message": {`, new: `"messages": {`,
			pointer: "/runs/0/results/0", keyword: "required",
		},
		{
			name: "help uri that is not a uri", old: `"helpUri": "https://github.com/vahapogut/trustdiff/blob/main/docs/checks.md#td000-expired-allow"`,
			new:     `"helpUri": "docs/checks.md#td000-expired-allow"`,
			pointer: "/runs/0/tool/driver/rules/0/helpUri", keyword: "format",
		},
		{
			name: "rule without an id", old: `"id": "TD000",`, new: `"ids": "TD000",`,
			pointer: "/runs/0/tool/driver/rules/0", keyword: "required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broken := strings.Replace(golden, tt.old, tt.new, 1)
			if broken == golden {
				t.Fatalf("the log does not contain %s", tt.old)
			}
			err := schema.Validate([]byte(broken))
			if err == nil {
				t.Fatalf("schema accepted %s", tt.new)
			}
			if want := "#" + tt.pointer + ": " + tt.keyword + ":"; !strings.Contains(err.Error(), want) {
				t.Fatalf("error does not name %s:\n%v", want, err)
			}
		})
	}
}

func TestSARIFRun(t *testing.T) {
	log := decodeSARIF(t, renderSARIF(t, fixtureReport()))

	if log.Version != "2.1.0" || log.Schema != sarifSchemaURI {
		t.Errorf("version = %q, $schema = %q", log.Version, log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want one run", len(log.Runs))
	}
	driver := log.Runs[0].Tool.Driver
	if driver.Name != "trustdiff" || driver.Version != "v0.0.1" || driver.InformationURI != toolInformationURI {
		t.Errorf("driver = %+v", driver)
	}

	results := log.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("results = %d, want the two findings of the fixture", len(results))
	}
	// The report sorts findings by level, most severe first, and the writer keeps
	// that order, so the block finding is the first annotation.
	if results[0].RuleID != "TD002" || results[1].RuleID != "TD001" {
		t.Errorf("result order = %q, %q", results[0].RuleID, results[1].RuleID)
	}
	if results[0].Level != "error" || results[1].Level != "warning" {
		t.Errorf("levels = %q, %q", results[0].Level, results[1].Level)
	}
	for _, r := range results {
		if got := driver.Rules[r.RuleIndex].ID; got != r.RuleID {
			t.Errorf("result %s has ruleIndex %d, which is rule %s", r.RuleID, r.RuleIndex, got)
		}
		if len(r.Locations) != 1 {
			t.Fatalf("result %s has %d locations, want the lockfile", r.RuleID, len(r.Locations))
		}
		physical := r.Locations[0].PhysicalLocation
		if physical.ArtifactLocation.URI != "package-lock.json" || physical.Region == nil || physical.Region.StartLine != 42 {
			t.Errorf("result %s location = %+v", r.RuleID, physical)
		}
		if r.Properties["ref"] != "npm:example-lib@4.19.3" {
			t.Errorf("result %s properties = %v, want the package ref", r.RuleID, r.Properties)
		}
		if _, ok := r.Properties["evidence"]; !ok {
			t.Errorf("result %s carries no evidence", r.RuleID)
		}
	}

	first := results[0]
	if want := "Publisher of 4.19.3 is not among the previous publishers\n\nprevious 5 versions"; !strings.HasPrefix(first.Message.Text, want) {
		t.Errorf("message = %q, want the title then the explanation", first.Message.Text)
	}
	if len(first.PartialFingerprints) != 1 || len(first.PartialFingerprints[fingerprintKey]) != 32 {
		t.Errorf("partialFingerprints = %v", first.PartialFingerprints)
	}
	if first.PartialFingerprints[fingerprintKey] == results[1].PartialFingerprints[fingerprintKey] {
		t.Error("two findings of one subject share a fingerprint")
	}
}

// The rule list describes every check, not only the ones that fired, so that a
// service can show what the tool looks for before it has ever failed a run.
func TestSARIFRules(t *testing.T) {
	log := decodeSARIF(t, renderSARIF(t, fixtureReport()))
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != len(checkRules) {
		t.Fatalf("rules = %d, want one per check (%d)", len(rules), len(checkRules))
	}
	seen := make(map[string]bool, len(rules))
	for i, rule := range rules {
		if seen[rule.ID] {
			t.Errorf("rule %s appears twice", rule.ID)
		}
		seen[rule.ID] = true
		if i > 0 && rules[i-1].ID >= rule.ID {
			t.Errorf("rules are not in id order: %s before %s", rules[i-1].ID, rule.ID)
		}
		if rule.Name == "" || rule.ShortDescription.Text == "" || rule.FullDescription.Text == "" {
			t.Errorf("rule %s = %+v, every field is part of the contract", rule.ID, rule)
		}
		if want := checksDocURI + "#" + strings.ToLower(rule.ID) + "-" + rule.Name; rule.HelpURI != want {
			t.Errorf("rule %s helpUri = %q, want %q", rule.ID, rule.HelpURI, want)
		}
	}
	if !seen["TD001"] || !seen["TD013"] {
		t.Error("the rule list is missing a check")
	}
}

// A finding whose check this package has no entry for still gets a rule, so that no
// result points at a rule the log does not carry.
func TestSARIFRuleForUnknownCheck(t *testing.T) {
	ref := model.MustParseRef("npm:example-lib@1.0.0")
	r := Build([]Subject{{
		Ref:       ref,
		Evaluated: []string{"TD099"},
		Findings: []model.Finding{{
			ID: "TD099", Name: "future-check", Level: model.LevelInfo, Ref: ref,
			Title: "Something a later release looks for", Explanation: "no rule for it is compiled in",
		}},
	}}, testTool(), testPolicy(), model.LevelBlock)

	log := decodeSARIF(t, renderSARIF(t, r))
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != len(checkRules)+1 {
		t.Fatalf("rules = %d, want the table plus the unknown check", len(rules))
	}
	added := rules[len(rules)-1]
	if added.ID != "TD099" || added.Name != "future-check" {
		t.Errorf("added rule = %+v", added)
	}
	if want := checksDocURI + "#td099-future-check"; added.HelpURI != want {
		t.Errorf("helpUri = %q, want %q", added.HelpURI, want)
	}
	result := log.Runs[0].Results[0]
	if result.RuleIndex != len(rules)-1 || result.Level != "note" {
		t.Errorf("result = %+v", result)
	}
	if len(result.Locations) != 0 {
		t.Errorf("a subject named on the command line has no file to annotate: %+v", result.Locations)
	}
	if _, ok := result.Properties["evidence"]; ok {
		t.Error("a finding without evidence must not carry an empty evidence object")
	}
}

// A lockfile parser that could not place an entry reports line 0, and SARIF regions
// start at 1, so the region is left out rather than written as an invalid one.
func TestSARIFLocationWithoutLine(t *testing.T) {
	ref := model.MustParseRef("pypi:example-tool@2.0.0")
	loc := &model.Location{Path: "sub dir/uv.lock"}
	r := Build([]Subject{{
		Ref: ref, Location: loc, Evaluated: []string{"TD014"},
		Findings: []model.Finding{{
			ID: "TD014", Name: "integrity-missing", Level: model.LevelWarn, Ref: ref,
			Title: "Entry has no hash", Explanation: "the entry carries no integrity field", Location: loc,
		}},
	}}, testTool(), testPolicy(), model.LevelBlock)

	log := decodeSARIF(t, renderSARIF(t, r))
	physical := log.Runs[0].Results[0].Locations[0].PhysicalLocation
	if physical.Region != nil {
		t.Errorf("region = %+v, want none for line 0", physical.Region)
	}
	if physical.ArtifactLocation.URI != "sub%20dir/uv.lock" {
		t.Errorf("uri = %q, want the path escaped as a URI reference", physical.ArtifactLocation.URI)
	}
}

func TestSARIFEmptyReport(t *testing.T) {
	out := renderSARIF(t, Build(nil, testTool(), testPolicy(), model.LevelBlock))
	if !bytes.Contains(out, []byte(`"results": []`)) {
		t.Errorf("a run that found nothing must carry an empty results array, not none:\n%s", out)
	}
	if !bytes.HasSuffix(out, []byte("}\n")) {
		t.Error("output must end with a closing brace and one newline")
	}
}

func TestSARIFLevel(t *testing.T) {
	tests := []struct {
		level model.Level
		want  string
	}{
		{level: model.LevelBlock, want: "error"},
		{level: model.LevelWarn, want: "warning"},
		{level: model.LevelInfo, want: "note"},
		{level: model.LevelOff, want: "none"},
		{level: model.Level(42), want: "none"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := sarifLevel(tt.level); got != tt.want {
				t.Errorf("sarifLevel(%v) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestArtifactURI(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "plain", path: "package-lock.json", want: "package-lock.json"},
		{name: "windows separators", path: `packages\api\pnpm-lock.yaml`, want: "packages/api/pnpm-lock.yaml"},
		{name: "space", path: "my project/uv.lock", want: "my%20project/uv.lock"},
		{name: "number sign", path: "a#b/Cargo.lock", want: "a%23b/Cargo.lock"},
		{name: "already relative", path: "./Cargo.lock", want: "./Cargo.lock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := artifactURI(tt.path); got != tt.want {
				t.Errorf("artifactURI(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// The fingerprint is what keeps a second run from adding a second annotation for a
// finding that is already there, so it must not move with the line number and must
// separate two findings that differ in check, package or title.
func TestFingerprint(t *testing.T) {
	base := model.Finding{
		ID: "TD001", Name: "young-version", Ref: model.MustParseRef("npm:example-lib@4.19.3"),
		Title: "Version is 6 hours old", Location: &model.Location{Path: "package-lock.json", Line: 42},
	}
	want := fingerprint(&base)

	moved := base
	moved.Location = &model.Location{Path: "package-lock.json", Line: 4711}
	moved.Explanation = "reworded by a later release"
	if got := fingerprint(&moved); got != want {
		t.Errorf("fingerprint moved with the line and the explanation: %q, want %q", got, want)
	}

	for _, changed := range []func(f *model.Finding){
		func(f *model.Finding) { f.ID = "TD002" },
		func(f *model.Finding) { f.Ref.Version = "4.19.4" },
		func(f *model.Finding) { f.Ref.Name = "example-other" },
		func(f *model.Finding) { f.Title = "Version is 7 hours old" },
	} {
		other := base
		changed(&other)
		if got := fingerprint(&other); got == want {
			t.Errorf("%+v has the fingerprint of %+v", other, base)
		}
	}
}

// Every rule points at a section of docs/checks.md, and the anchor a markdown
// renderer derives from a heading is the heading in lower case with the space turned
// into a dash. Comparing the table with the document keeps the two from drifting: a
// check documented but not described here would ship a log without its rule, and a
// rule here that the document lost would link into nothing.
func TestCheckRulesMatchDocs(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "checks.md"))
	if err != nil {
		t.Fatalf("read docs/checks.md: %v", err)
	}
	heading := regexp.MustCompile(`(?m)^## (TD[0-9]{3}) ([a-z0-9-]+)$`)
	documented := heading.FindAllStringSubmatch(string(doc), -1)
	if len(documented) == 0 {
		t.Fatal("docs/checks.md has no check sections; the pattern or the document changed")
	}
	if len(documented) != len(checkRules) {
		t.Fatalf("docs/checks.md documents %d checks, checkRules has %d", len(documented), len(checkRules))
	}
	for i, section := range documented {
		rule := checkRules[i]
		if rule.ID != section[1] || rule.Name != section[2] {
			t.Errorf("checkRules[%d] = %s %s, docs/checks.md has %s %s", i, rule.ID, rule.Name, section[1], section[2])
			continue
		}
		if want := checksDocURI + "#" + strings.ToLower(section[1]) + "-" + section[2]; helpURI(rule.ID, rule.Name) != want {
			t.Errorf("helpUri of %s = %q, want %q", rule.ID, helpURI(rule.ID, rule.Name), want)
		}
	}
}
