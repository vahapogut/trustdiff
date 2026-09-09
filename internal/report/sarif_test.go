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

// fingerprintFixture is one finding on one lockfile line, as a subject holds it.
func fingerprintFixture() (model.Finding, Subject) {
	loc := &model.Location{Path: "package-lock.json", Line: 42}
	ref := model.MustParseRef("npm:example-lib@4.19.3")
	f := model.Finding{
		ID: "TD001", Name: "young-version", Ref: ref, Location: loc,
		Title:       "Published 2d2h47m15s ago, inside the 3d cooldown",
		Explanation: "4.19.3 was published 2d2h47m15s before this run",
	}
	return f, Subject{Ref: ref, Location: loc, Evaluated: []string{"TD001"}, Findings: []model.Finding{f}}
}

// The fingerprint is what a code scanning service recognizes a finding by, so a
// re-run of an unchanged pull request has to produce the same one: several checks
// build their title from the run's clock, and a fingerprint that follows it closes
// the alert and opens a new one every time the gate runs.
func TestFingerprintSurvivesARerun(t *testing.T) {
	base, subject := fingerprintFixture()
	want := fingerprint(&base, &subject)

	// The same finding an hour later: the age in the title and the explanation has
	// moved on, and an edit above the entry has moved its line.
	later := base
	later.Title = "Published 2d3h47m15s ago, inside the 3d cooldown"
	later.Explanation = "4.19.3 was published 2d3h47m15s before this run"
	later.Location = &model.Location{Path: "package-lock.json", Line: 4711}
	if got := fingerprint(&later, &subject); got != want {
		t.Errorf("fingerprint = %q after an hour, want %q: the clock and the line are not identity", got, want)
	}
}

// It must separate anything that is not the same finding: another check, another
// package version, another lockfile, and another of the several findings one check
// can report for one package.
func TestFingerprintSeparatesFindings(t *testing.T) {
	base, subject := fingerprintFixture()
	base.Evidence = map[string]any{"signal": "missing-hash"}
	want := fingerprint(&base, &subject)

	tests := []struct {
		name    string
		changed func(f *model.Finding, s *Subject)
	}{
		{name: "another check", changed: func(f *model.Finding, _ *Subject) { f.ID = "TD002" }},
		{name: "another version", changed: func(f *model.Finding, _ *Subject) { f.Ref.Version = "4.19.4" }},
		{name: "another package", changed: func(f *model.Finding, _ *Subject) { f.Ref.Name = "example-other" }},
		{
			name: "another lockfile",
			changed: func(f *model.Finding, _ *Subject) {
				f.Location = &model.Location{Path: "apps/api/package-lock.json", Line: 42}
			},
		},
		{
			name: "the lockfile the subject came from",
			changed: func(f *model.Finding, s *Subject) {
				f.Location = nil
				s.Location = &model.Location{Path: "apps/api/package-lock.json", Line: 42}
			},
		},
		{
			name:    "another signal of the same check",
			changed: func(f *model.Finding, _ *Subject) { f.Evidence = map[string]any{"signal": "plain-http"} },
		},
		{
			name: "another advisory of the same check",
			changed: func(f *model.Finding, _ *Subject) {
				f.Evidence = map[string]any{"advisory_id": "GHSA-1111-2222-3333"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other, otherSubject := base, subject
			tt.changed(&other, &otherSubject)
			if got := fingerprint(&other, &otherSubject); got == want {
				t.Errorf("%+v has the fingerprint of %+v", other, base)
			}
		})
	}
}

// Two byte-identical lockfiles in one repository pin the same version on the same
// line, and a service that saw one fingerprint twice would keep one annotation and
// drop the other, so the results of one run are all distinct even when the findings
// carry nothing to tell them apart.
func TestSARIFFingerprintsAreDistinctWithinARun(t *testing.T) {
	ref := model.MustParseRef("npm:example-lib@4.19.3")
	finding := func(path string) model.Finding {
		return model.Finding{
			ID: "TD013", Name: "exotic-source", Level: model.LevelBlock, Ref: ref,
			Title: "resolved from a git repository instead of the npm registry", Explanation: "pins no commit sha",
			Location: &model.Location{Path: path, Line: 14},
		}
	}
	subject := func(path string) Subject {
		return Subject{
			Ref: ref, Location: &model.Location{Path: path, Line: 14}, Evaluated: []string{"TD013"},
			Findings: []model.Finding{finding(path)},
		}
	}
	web, api := subject("apps/web/package-lock.json"), subject("apps/api/package-lock.json")
	// A third subject repeats the first exactly, which is what a check reporting two
	// findings with nothing between them would look like.
	log := decodeSARIF(t, renderSARIF(t, Build([]Subject{web, api, web}, testTool(), testPolicy(), model.LevelBlock)))

	results := log.Runs[0].Results
	if len(results) != 3 {
		t.Fatalf("results = %d, want one per finding", len(results))
	}
	seen := make(map[string]int, len(results))
	for _, r := range results {
		seen[r.PartialFingerprints[fingerprintKey]]++
	}
	if len(seen) != len(results) {
		t.Errorf("%d results carry %d fingerprints: %v", len(results), len(seen), seen)
	}
}

// Every rule points at a section of docs/checks.md, and the anchor a markdown
// renderer derives from a heading is the heading in lower case with the space turned
// into a dash. Comparing the table with the document keeps the two from drifting: a
// check documented but not described here would ship a log without its rule, and a
// rule here that the document lost would link into nothing.
//
// The short description is compared as text as well. An alert whose rule denies the
// case the finding reports, while its helpUri points at the document that describes
// it, is worse than no rule at all, so every Short has to be a sentence of that
// check's section, or the opening clause of one.
func TestCheckRulesMatchDocs(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "checks.md"))
	if err != nil {
		t.Fatalf("read docs/checks.md: %v", err)
	}
	text := string(normalizeNewlines(doc))
	heading := regexp.MustCompile(`(?m)^## (TD[0-9]{3}) ([a-z0-9-]+)$`)
	documented := heading.FindAllStringSubmatchIndex(text, -1)
	if len(documented) == 0 {
		t.Fatal("docs/checks.md has no check sections; the pattern or the document changed")
	}
	if len(documented) != len(checkRules) {
		t.Fatalf("docs/checks.md documents %d checks, checkRules has %d", len(documented), len(checkRules))
	}
	for i, match := range documented {
		rule := checkRules[i]
		id, name := text[match[2]:match[3]], text[match[4]:match[5]]
		if rule.ID != id || rule.Name != name {
			t.Errorf("checkRules[%d] = %s %s, docs/checks.md has %s %s", i, rule.ID, rule.Name, id, name)
			continue
		}
		if want := checksDocURI + "#" + strings.ToLower(id) + "-" + name; helpURI(rule.ID, rule.Name) != want {
			t.Errorf("helpUri of %s = %q, want %q", rule.ID, helpURI(rule.ID, rule.Name), want)
		}
		end := len(text)
		if i+1 < len(documented) {
			end = documented[i+1][0]
		}
		if section := docSectionText(text[match[0]:end]); !strings.Contains(section, docSentence(rule.Short)) {
			t.Errorf("shortDescription of %s is not a sentence of its section of docs/checks.md:\n%s", rule.ID, rule.Short)
		}
	}
}

// docSectionText renders a section of docs/checks.md as the plain prose the rule is
// compared with: the backticks a document puts around a setting or a value are not
// part of the sentence, and a sentence that wraps over two lines is still one.
func docSectionText(section string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(section, "`", "")), " ")
}

// docSentence is the part of a short description that has to appear in the document:
// the sentence without its final period, so that a rule may stop at a clause where
// the document carries on into detail a one-line description does not need.
func docSentence(short string) string {
	return strings.TrimSuffix(short, ".")
}
