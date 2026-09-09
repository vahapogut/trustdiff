package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/doctor"
	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
)

// doctorSchemaPath is the published schema the json rendering is validated against.
// The report keeps an embedded copy beside its writer; the doctor schema is read from
// the repository here, so that this package holds one copy of it and not two.
var doctorSchemaPath = filepath.Join("..", "..", "schema", "doctor.v1.json")

// fixtureRule builds the rule a fixture result points at. The rules are written here
// rather than taken from the registry so that a golden file changes when this package
// changes and not when somebody raises the level of a real rule.
func fixtureRule(id, name string, manager doctor.ManagerID, level model.Level) *doctor.Rule {
	return &doctor.Rule{
		ID:       id,
		Name:     name,
		Manager:  manager,
		Summary:  "one line about " + name,
		Level:    level,
		Docs:     "https://example.test/docs/" + name,
		Verified: "2026-09-09",
		Fixable:  true,
	}
}

// fixtureScorecard is the scorecard every doctor golden renders. It is built by hand
// rather than by doctor.Evaluate, which would need a repository on disk: what these
// renderings have to get right is every status, a value in the wrong unit, a file that
// could not be read, a setting --fix wrote, a manager outside the repository root and
// a note, and a fixture says all of that in one place. The values are invented; no
// real repository is described.
func fixtureScorecard() *doctor.Scorecard {
	npm := &doctor.Manager{
		ID:            doctor.NPM,
		Root:          ".",
		Version:       "11.16.0",
		VersionSource: "the packageManager field",
		Evidence:      []string{"package-lock.json", "the packageManager field of package.json"},
		Files:         []string{".npmrc", "package.json"},
	}
	pnpm := &doctor.Manager{
		ID:            doctor.PNPM,
		Root:          "apps/web",
		Version:       "10.16.1",
		VersionSource: "apps/web/pnpm-lock.yaml",
		Evidence:      []string{"apps/web/pnpm-lock.yaml"},
		Files:         []string{"apps/web/pnpm-workspace.yaml"},
	}
	return &doctor.Scorecard{
		Root:     ".",
		Managers: []*doctor.Manager{npm, pnpm},
		Results: []doctor.Result{
			{
				// A rule with no value to check: its detail is the whole row, and its
				// status is the one the schema and the counts most easily forget.
				Rule:    fixtureRule("DR031", "bun-security-scanner", doctor.NPM, model.LevelInfo),
				Manager: npm,
				Status:  doctor.StatusAdvice,
				Detail:  "which scanner to trust is a decision for the project, so this is reported and never written",
				File:    ".npmrc",
				Level:   model.LevelInfo,
			},
			{
				Rule:    fixtureRule("DR001", "npm-min-release-age", doctor.NPM, model.LevelWarn),
				Manager: npm,
				Status:  doctor.StatusWrong,
				Detail:  "1 is 1 day, and the policy asks for 3 days (3 here)",
				File:    ".npmrc",
				Line:    3,
				Current: "1",
				Want:    "3, which is 3 days in days",
				Level:   model.LevelWarn,
			},
			{
				Rule:    fixtureRule("DR002", "npm-strict-allow-scripts", doctor.NPM, model.LevelWarn),
				Manager: npm,
				Status:  doctor.StatusSet,
				Detail:  "the previous file is kept as .npmrc.trustdiff-backup-20260909T120000Z",
				File:    ".npmrc",
				Line:    6,
				Want:    "true",
				Level:   model.LevelWarn,
				Fixed:   true,
				Edit:    "--- .npmrc\n+++ .npmrc\n@@ -3,3 +3,4 @@\n min-release-age=1\n allow-remote=false\n+strict-allow-scripts=true\n",
			},
			{
				Rule:    fixtureRule("DR003", "npm-allow-git", doctor.NPM, model.LevelInfo),
				Manager: npm,
				Status:  doctor.StatusMissing,
				File:    ".npmrc",
				Want:    "false",
				Level:   model.LevelInfo,
			},
			{
				Rule:    fixtureRule("DR004", "npm-allow-remote", doctor.NPM, model.LevelInfo),
				Manager: npm,
				Status:  doctor.StatusSet,
				File:    ".npmrc",
				Line:    4,
				Current: "false",
				Want:    "false",
				Level:   model.LevelInfo,
			},
			{
				Rule:    fixtureRule("DR010", "pnpm-minimum-release-age", doctor.PNPM, model.LevelBlock),
				Manager: pnpm,
				Status:  doctor.StatusWrong,
				Detail:  "7 is 7 minutes, and the policy asks for 3 days (4320 here). 7 is 7 days in days, the unit npm and Poetry count in",
				File:    "apps/web/pnpm-workspace.yaml",
				Line:    4,
				Current: "7",
				Want:    "4320, which is 3 days in minutes",
				Level:   model.LevelBlock,
			},
			{
				Rule:    fixtureRule("DR011", "pnpm-strict-dep-builds", doctor.PNPM, model.LevelWarn),
				Manager: pnpm,
				Status:  doctor.StatusUnreadable,
				Detail:  "could not be read: the value of strictDepBuilds is a YAML alias, which this reader will not interpret",
				File:    "apps/web/pnpm-workspace.yaml",
				Line:    9,
				Level:   model.LevelWarn,
			},
			{
				Rule:    fixtureRule("DR015", "pnpm-trust-policy", doctor.PNPM, model.LevelWarn),
				Manager: pnpm,
				Status:  doctor.StatusNotApplicable,
				Detail:  "pnpm 10.16.1 is older than 11.0.0, which added this setting",
				Level:   model.LevelWarn,
			},
		},
		Notes:   []string{"apps/web/pnpm-workspace.yaml: the value of strictDepBuilds is a YAML alias, which this reader will not interpret"},
		Changed: []string{".npmrc"},
		Backups: map[string]string{".npmrc": ".npmrc.trustdiff-backup-20260909T120000Z"},
	}
}

// fixtureDoctorDocument is the fixture scorecard as the document the writers render.
func fixtureDoctorDocument() *Doctor {
	return BuildDoctor(fixtureScorecard(), testTool(), testPolicy(), model.LevelBlock)
}

// assertDoctorGolden renders the fixture scorecard with w and compares the bytes with
// the golden file of that name under testdata, after normalizing CRLF so that a file
// written on Windows and one written on Linux compare equal. It returns what was
// rendered, for a test that has more to say about it than that it did not change.
// Regenerate the golden files with: go test ./internal/report/ -update
func assertDoctorGolden(t *testing.T, name string, w DoctorWriter) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := w.WriteDoctor(&buf, fixtureDoctorDocument()); err != nil {
		t.Fatalf("WriteDoctor: %v", err)
	}
	got := normalizeNewlines(buf.Bytes())
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if want = normalizeNewlines(want); !bytes.Equal(got, want) {
		t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
	return got
}

func TestDoctorGolden(t *testing.T) {
	tests := []struct {
		name   string
		golden string
		writer DoctorWriter
	}{
		{name: "human", golden: "doctor.human.golden", writer: Human{Color: false, Width: 80}},
		{name: "json", golden: "doctor.json.golden", writer: JSON{}},
		{name: "markdown", golden: "doctor.markdown.golden", writer: Markdown{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertDoctorGolden(t, tt.golden, tt.writer)
		})
	}
}

// Color may add escape sequences and must not move anything, which is the same
// promise the report's human writer makes.
func TestDoctorHumanColorLayoutMatchesPlain(t *testing.T) {
	var plain, color bytes.Buffer
	if err := (Human{Color: false, Width: 80}).WriteDoctor(&plain, fixtureDoctorDocument()); err != nil {
		t.Fatalf("WriteDoctor: %v", err)
	}
	if err := (Human{Color: true, Width: 80}).WriteDoctor(&color, fixtureDoctorDocument()); err != nil {
		t.Fatalf("WriteDoctor: %v", err)
	}
	if !strings.Contains(color.String(), "\x1b[") {
		t.Fatal("color output carries no escape sequences")
	}
	if stripped := ansiEscape.ReplaceAllString(color.String(), ""); stripped != plain.String() {
		t.Fatalf("layout differs once escape codes are removed\n--- color stripped ---\n%s\n--- plain ---\n%s", stripped, plain.String())
	}
}

// The human rendering has to put a manager's problems above what it already does
// right, name where the version came from and print the diff of a setting that was
// written, because those are the three things somebody runs doctor for.
func TestDoctorHumanBlocks(t *testing.T) {
	var buf bytes.Buffer
	if err := (Human{Width: 80}).WriteDoctor(&buf, fixtureDoctorDocument()); err != nil {
		t.Fatalf("WriteDoctor: %v", err)
	}
	out := string(normalizeNewlines(buf.Bytes()))
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")

	if want := "apps/web/pnpm-workspace.yaml: the value of strictDepBuilds is a YAML alias, which this reader will not interpret"; lines[0] != want {
		t.Errorf("first line = %q, want the note %q", lines[0], want)
	}
	if want := "2 set, 2 wrong, 1 missing, 1 unreadable, 1 advice, 1 not applicable. Exit code 1 (problems at or above the threshold)."; lines[len(lines)-1] != want {
		t.Errorf("last line = %q, want %q", lines[len(lines)-1], want)
	}
	for _, want := range []string{
		"npm 11.16.0  (version from the packageManager field)",
		"pnpm 10.16.1  (version from apps/web/pnpm-lock.yaml, apps/web)",
		"+strict-allow-scripts=true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not carry %q:\n%s", want, out)
		}
	}

	// Inside the npm block the wrong rule comes before the missing one and both come
	// before the two that are already set.
	order := []string{"DR001", "DR003", "DR002", "DR004", "DR010", "DR011", "DR015"}
	var got []string
	for _, line := range lines {
		for _, id := range order {
			if strings.Contains(line, id+" ") {
				got = append(got, id)
			}
		}
	}
	if !slices.Equal(got, order) {
		t.Errorf("rules appear as %v, want %v:\n%s", got, order, out)
	}

	// A detail sentence too long for the terminal is wrapped under its line, the way
	// a finding's explanation is. The notes and the summary line are not wrapped,
	// which is how the report writes them too.
	for i, line := range lines {
		if strings.HasPrefix(line, indent(humanIndentExplanation)) && len([]rune(line)) > 80 {
			t.Errorf("line %d is %d columns wide: %q", i+1, len([]rune(line)), line)
		}
	}
	if !strings.Contains(out, "      7 is 7 minutes, and the policy asks for 3 days (4320 here). 7 is 7 days in\n      days, the unit npm and Poetry count in\n") {
		t.Errorf("the long detail was not wrapped under its line:\n%s", out)
	}
}

// The markdown comment is a table a reviewer reads without opening a log, so the
// heading carries the counts, the rows are the rules with the problems first, and the
// last line says whether the gate failed.
// A comment that carried the table and dropped the note saying half the repository
// was unreadable would read as an all clear.
func TestDoctorMarkdownCarriesTheNotes(t *testing.T) {
	card := fixtureScorecard()
	card.Notes = []string{"apps/web/pnpm-workspace.yaml: could not be read"}
	d := BuildDoctor(card, testTool(), testPolicy(), model.LevelBlock)
	var buf bytes.Buffer
	if err := (Markdown{}).WriteDoctor(&buf, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "could not be read") {
		t.Errorf("the comment drops the note:\n%s", buf.String())
	}
}

func TestDoctorMarkdownComment(t *testing.T) {
	var buf bytes.Buffer
	if err := (Markdown{}).WriteDoctor(&buf, fixtureDoctorDocument()); err != nil {
		t.Fatalf("WriteDoctor: %v", err)
	}
	out := string(normalizeNewlines(buf.Bytes()))
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if want := "## trustdiff doctor: 2 set, 2 wrong, 1 missing, 1 unreadable, 1 advice, 1 not applicable"; lines[0] != want {
		t.Errorf("heading = %q, want %q", lines[0], want)
	}
	if want := "Exit code 1 (problems at or above the threshold)."; lines[len(lines)-1] != want {
		t.Errorf("last line = %q, want %q", lines[len(lines)-1], want)
	}
	rows := tableRows(t, out)
	want := [][]string{
		{"Manager", "Rule", "Status", "Setting", "Location"},
		{"---", "---", "---", "---", "---"},
		{"npm 11.16.0", "DR001 npm-min-release-age", "wrong", "1, want 3, which is 3 days in days", ".npmrc:3"},
		{"pnpm 10.16.1 (apps/web)", "DR010 pnpm-minimum-release-age", "wrong", "7, want 4320, which is 3 days in minutes", "apps/web/pnpm-workspace.yaml:4"},
		{"npm 11.16.0", "DR003 npm-allow-git", "missing", "want false", ".npmrc"},
		{"pnpm 10.16.1 (apps/web)", "DR011 pnpm-strict-dep-builds", "unreadable", "", "apps/web/pnpm-workspace.yaml:9"},
		{"npm 11.16.0", "DR002 npm-strict-allow-scripts", "set", "true", ".npmrc:6"},
		{"npm 11.16.0", "DR004 npm-allow-remote", "set", "false", ".npmrc:4"},
		{"npm 11.16.0", "DR031 bun-security-scanner", "advice", "", ".npmrc"},
		{"pnpm 10.16.1 (apps/web)", "DR015 pnpm-trust-policy", "not applicable", "", ""},
	}
	if len(rows) != len(want) {
		t.Fatalf("table has %d rows, want %d:\n%s", len(rows), len(want), out)
	}
	for i, row := range rows {
		if len(row) != 5 {
			t.Fatalf("row %d has %d cells: %q", i, len(row), row)
		}
		for j := range row {
			if row[j] != want[i][j] {
				t.Errorf("row %d cell %d = %q, want %q", i, j, row[j], want[i][j])
			}
		}
	}
}

// Every cell of the doctor table comes out of a configuration file a pull request may
// have written, so nothing in one may end the cell, break the row or render as
// markup. The values here are the ones a hostile file would carry.
func TestDoctorMarkdownEscapesCells(t *testing.T) {
	m := &doctor.Manager{ID: doctor.NPM, Root: "packages/[click](https://example.test)", Version: "1.0.0|2.0.0"}
	card := &doctor.Scorecard{
		Root:     ".",
		Managers: []*doctor.Manager{m},
		Results: []doctor.Result{{
			Rule:    fixtureRule("DR001", "npm-min-release-age", doctor.NPM, model.LevelWarn),
			Manager: m,
			Status:  doctor.StatusWrong,
			File:    ".npmrc\n| evil | row |",
			Line:    3,
			Current: "<img src=x> | **bold**",
			Want:    "3 `code`",
			Level:   model.LevelWarn,
		}},
	}
	var buf bytes.Buffer
	if err := (Markdown{}).WriteDoctor(&buf, BuildDoctor(card, testTool(), testPolicy(), model.LevelWarn)); err != nil {
		t.Fatalf("WriteDoctor: %v", err)
	}
	out := string(normalizeNewlines(buf.Bytes()))
	rows := tableRows(t, out)
	if len(rows) != 3 {
		t.Fatalf("table has %d rows, want a header, a rule and one result:\n%s", len(rows), out)
	}
	for i, row := range rows {
		if len(row) != 5 {
			t.Fatalf("row %d has %d cells, so a value ended a cell: %q", i, len(row), row)
		}
	}
	for _, escaped := range []string{`\<img src=x\>`, `\*\*bold\*\*`, "\\`code\\`", `\[click\]`} {
		if !strings.Contains(out, escaped) {
			t.Errorf("%q is not in the comment, so a value was not escaped:\n%s", escaped, out)
		}
	}
	// Not one of the characters that starts markup may stand on its own.
	for _, c := range []string{"<", ">", "*", "`", "[", "]"} {
		if strings.Count(out, c) != strings.Count(out, `\`+c) {
			t.Errorf("a bare %q survived the escaping:\n%s", c, out)
		}
	}
	if strings.Count(out, "\n| ") != 3 {
		t.Errorf("a newline inside a value started a row:\n%s", out)
	}
}

// The exit code is the one thing a CI step reads, so it follows the level of the
// problems and nothing else.
func TestDoctorExitCode(t *testing.T) {
	tests := []struct {
		name   string
		failOn model.Level
		want   int
	}{
		{name: "block fails on the block rule", failOn: model.LevelBlock, want: 1},
		{name: "warn fails too", failOn: model.LevelWarn, want: 1},
		{name: "never fails on nothing", failOn: model.LevelOff, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := BuildDoctor(fixtureScorecard(), testTool(), testPolicy(), tt.failOn)
			if d.Summary.ExitCode != tt.want {
				t.Errorf("exit code = %d, want %d", d.Summary.ExitCode, tt.want)
			}
			if got, want := d.Summary.ExitMeaning, DoctorExitMeaning(tt.want); got != want {
				t.Errorf("exit meaning = %q, want %q", got, want)
			}
		})
	}

	// A scorecard whose only problems are below the threshold passes.
	card := fixtureScorecard()
	for i := range card.Results {
		card.Results[i].Level = model.LevelInfo
	}
	if d := BuildDoctor(card, testTool(), testPolicy(), model.LevelBlock); d.Summary.ExitCode != 0 {
		t.Errorf("exit code = %d for problems below the threshold, want 0", d.Summary.ExitCode)
	}

	// Exit code 3 is the caller's, as it is for the report.
	d := BuildDoctor(nil, testTool(), testPolicy(), model.LevelBlock)
	d.SetExitCode(3)
	if d.Summary.ExitMeaning != "a file could not be read" {
		t.Errorf("exit meaning = %q", d.Summary.ExitMeaning)
	}
}

// A run that found nothing still writes a document, with every slice present and the
// counts at zero, so a script never has to tell an empty run from a broken one.
func TestDoctorEmptyScorecard(t *testing.T) {
	for _, card := range []*doctor.Scorecard{nil, {}, {Root: "."}} {
		d := BuildDoctor(card, testTool(), testPolicy(), model.LevelBlock)
		if d.Root != "." {
			t.Errorf("root = %q, want the dot", d.Root)
		}
		if d.Managers == nil || d.Results == nil || d.Notes == nil {
			t.Error("an empty scorecard left a slice nil, which json writes as null")
		}
		if len(d.Summary.Statuses) != len(doctorSummaryOrder) {
			t.Errorf("statuses = %v, want every status the package defines", d.Summary.Statuses)
		}
		if d.Summary.ExitCode != 0 {
			t.Errorf("exit code = %d, want 0", d.Summary.ExitCode)
		}
		var buf bytes.Buffer
		if err := (JSON{}).WriteDoctor(&buf, d); err != nil {
			t.Fatalf("WriteDoctor: %v", err)
		}
		for _, want := range []string{`"managers": []`, `"results": []`, `"notes": []`} {
			if !strings.Contains(buf.String(), want) {
				t.Errorf("empty document does not carry %s:\n%s", want, buf.String())
			}
		}
	}
}

// A result whose manager is not one detection returned must still be rendered: losing
// a rule from a scorecard is worse than an odd looking block.
func TestDoctorKeepsResultsOfUnlistedManagers(t *testing.T) {
	stray := &doctor.Manager{ID: doctor.Cargo, Root: "crates/core", Version: "1.90.0"}
	card := &doctor.Scorecard{
		Root: ".",
		Results: []doctor.Result{{
			Rule:    fixtureRule("DR080", "cargo-cooldown", doctor.Cargo, model.LevelInfo),
			Manager: stray,
			Status:  doctor.StatusNotApplicable,
			Detail:  "cargo has no setting for this yet",
			Level:   model.LevelInfo,
		}},
	}
	d := BuildDoctor(card, testTool(), testPolicy(), model.LevelBlock)
	if len(d.Managers) != 1 || d.Managers[0].Root != "crates/core" {
		t.Fatalf("managers = %+v, want the one the result named", d.Managers)
	}
	var buf bytes.Buffer
	if err := (Human{Width: 80}).WriteDoctor(&buf, d); err != nil {
		t.Fatalf("WriteDoctor: %v", err)
	}
	if !strings.Contains(buf.String(), "DR080 cargo-cooldown") {
		t.Errorf("the rule was dropped:\n%s", buf.String())
	}
}

func TestNewDoctor(t *testing.T) {
	for _, format := range []string{"human", "json", "markdown"} {
		w, err := NewDoctor(format, Options{})
		if err != nil || w == nil {
			t.Errorf("NewDoctor(%q) = %v, %v", format, w, err)
		}
	}
	for _, format := range []string{"", "sarif", "yaml"} {
		if _, err := NewDoctor(format, Options{}); err == nil {
			t.Errorf("NewDoctor(%q) accepted a format it has no writer for", format)
		}
	}
}

// doctorSchema is the published schema, compiled once for the tests below.
func doctorSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(doctorSchemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", doctorSchemaPath, err)
	}
	if bytes.Contains(raw, []byte("\r")) {
		t.Error("schema must use LF line endings")
	}
	schema, err := jsonschema.Compile(raw)
	if err != nil {
		t.Fatalf("compile %s: %v", doctorSchemaPath, err)
	}
	if unsupported := schema.UnsupportedKeywords(); len(unsupported) != 0 {
		t.Fatalf("schema uses keywords the validator does not enforce: %v", unsupported)
	}
	return schema
}

// The published schema must stay inside the keyword subset internal/jsonschema
// enforces, and every document the JSON writer produces must validate against it.
func TestDoctorSchemaValidatesJSONOutput(t *testing.T) {
	schema := doctorSchema(t)

	golden, err := os.ReadFile(filepath.Join("testdata", "doctor.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(normalizeNewlines(golden)); err != nil {
		t.Errorf("testdata/doctor.json.golden does not match the schema:\n%v", err)
	}

	empty := BuildDoctor(nil, testTool(), testPolicy(), model.LevelBlock)
	var buf bytes.Buffer
	if err := (JSON{}).WriteDoctor(&buf, empty); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(buf.Bytes()); err != nil {
		t.Errorf("a scorecard with no results does not match the schema:\n%v\n%s", err, buf.String())
	}

	unavailable := BuildDoctor(fixtureScorecard(), CurrentTool(), Policy{FailOn: "never"}, model.LevelOff)
	unavailable.SetExitCode(3)
	buf.Reset()
	if err := (JSON{}).WriteDoctor(&buf, unavailable); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(buf.Bytes()); err != nil {
		t.Errorf("the exit code 3 document does not match the schema:\n%v", err)
	}
}

func TestDoctorSchemaRejectsForeignFields(t *testing.T) {
	schema := doctorSchema(t)
	golden, err := os.ReadFile(filepath.Join("testdata", "doctor.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	golden = normalizeNewlines(golden)
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{name: "another schema id", old: `"schema": "trustdiff.doctor/1"`, new: `"schema": "trustdiff.doctor/2"`},
		{name: "a status nobody defined", old: `"status": "wrong"`, new: `"status": "probably fine"`},
		{name: "a line before the first", old: `"line": 3`, new: `"line": 0`},
		{name: "a field the schema does not name", old: `"root": ".",`, new: `"root": ".", "extra": 1,`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broken := bytes.Replace(golden, []byte(tt.old), []byte(tt.new), 1)
			if bytes.Equal(broken, golden) {
				t.Fatalf("golden file does not contain %s", tt.old)
			}
			if err := schema.Validate(broken); err == nil {
				t.Errorf("schema accepted %s", tt.new)
			}
		})
	}
}

// doctorSchemaDoc is the part of the hand written schema the tests compare with the
// Go constants it mirrors.
type doctorSchemaDoc struct {
	Schema     string   `json:"$schema"`
	ID         string   `json:"$id"`
	Required   []string `json:"required"`
	Properties struct {
		Schema struct {
			Const string `json:"const"`
		} `json:"schema"`
	} `json:"properties"`
	Definitions struct {
		ManagerID struct {
			Enum []string `json:"enum"`
		} `json:"manager_id"`
		Manager struct {
			Required []string `json:"required"`
		} `json:"manager"`
		Result struct {
			Required   []string `json:"required"`
			Properties struct {
				Status struct {
					Enum []string `json:"enum"`
				} `json:"status"`
				Level struct {
					Enum []string `json:"enum"`
				} `json:"level"`
			} `json:"properties"`
		} `json:"result"`
		Summary struct {
			Required   []string `json:"required"`
			Properties struct {
				Statuses struct {
					Required []string `json:"required"`
				} `json:"statuses"`
				ExitCode struct {
					Enum []int `json:"enum"`
				} `json:"exit_code"`
			} `json:"properties"`
		} `json:"summary"`
	} `json:"definitions"`
}

func readDoctorSchemaDoc(t *testing.T) doctorSchemaDoc {
	t.Helper()
	raw, err := os.ReadFile(doctorSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc doctorSchemaDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	return doc
}

// The schema is hand written, so the parts that mirror Go constants are checked here.
func TestDoctorSchemaMatchesConstants(t *testing.T) {
	doc := readDoctorSchemaDoc(t)
	if doc.Schema != "http://json-schema.org/draft-07/schema#" {
		t.Errorf("$schema = %q, want draft-07", doc.Schema)
	}
	if want := "https://raw.githubusercontent.com/vahapogut/trustdiff/main/schema/doctor.v1.json"; doc.ID != want {
		t.Errorf("$id = %q, want %q", doc.ID, want)
	}
	if doc.Properties.Schema.Const != DoctorSchemaID {
		t.Errorf("properties.schema.const = %q, want %q", doc.Properties.Schema.Const, DoctorSchemaID)
	}

	statuses := []string{
		string(doctor.StatusSet),
		string(doctor.StatusWrong),
		string(doctor.StatusMissing),
		string(doctor.StatusUnreadable),
		string(doctor.StatusAdvice),
		string(doctor.StatusNotApplicable),
	}
	if got := doc.Definitions.Result.Properties.Status.Enum; !slices.Equal(got, statuses) {
		t.Errorf("result.status enum = %v, want %v", got, statuses)
	}
	if got := doc.Definitions.Summary.Properties.Statuses.Required; !slices.Equal(got, statuses) {
		t.Errorf("summary.statuses required = %v, want %v", got, statuses)
	}
	if got, want := doc.Definitions.Result.Properties.Level.Enum, []string{model.LevelBlock.String(), model.LevelWarn.String(), model.LevelInfo.String()}; !slices.Equal(got, want) {
		t.Errorf("result.level enum = %v, want %v", got, want)
	}
	if got, want := doc.Definitions.Summary.Properties.ExitCode.Enum, []int{0, 1, 3}; !slices.Equal(got, want) {
		t.Errorf("summary.exit_code enum = %v, want %v", got, want)
	}

	managers := []doctor.ManagerID{
		doctor.NPM, doctor.PNPM, doctor.Yarn, doctor.Bun, doctor.Deno, doctor.UV,
		doctor.Pip, doctor.Poetry, doctor.Cargo, doctor.Dependabot, doctor.Renovate, doctor.Actions,
	}
	want := make([]string, 0, len(managers))
	for _, id := range managers {
		want = append(want, string(id))
	}
	if got := doc.Definitions.ManagerID.Enum; !slices.Equal(got, want) {
		t.Errorf("manager_id enum = %v, want %v", got, want)
	}
}

// Every field the schema requires has to be written by the writer, and no value may
// be written as an empty string: the document says a thing is absent by leaving the
// key out, which is the rule report.v1 follows.
func TestDoctorJSONWritesEveryRequiredField(t *testing.T) {
	doc := readDoctorSchemaDoc(t)
	golden, err := os.ReadFile(filepath.Join("testdata", "doctor.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(normalizeNewlines(golden), &out); err != nil {
		t.Fatalf("decode golden: %v", err)
	}

	requireKeys(t, "the document", out, doc.Required)
	requireKeys(t, "summary", out["summary"].(map[string]any), doc.Definitions.Summary.Required)
	managers, _ := out["managers"].([]any)
	if len(managers) != 2 {
		t.Fatalf("the fixture must render two managers, got %d", len(managers))
	}
	for i, m := range managers {
		requireKeys(t, "manager "+string(rune('0'+i)), m.(map[string]any), doc.Definitions.Manager.Required)
	}
	results, _ := out["results"].([]any)
	if len(results) != 8 {
		t.Fatalf("the fixture must render eight results, got %d", len(results))
	}
	for i, res := range results {
		requireKeys(t, "result "+string(rune('0'+i)), res.(map[string]any), doc.Definitions.Result.Required)
	}
	// The fixture has to reach every optional field too, or the schema documents
	// something nothing writes.
	optional := []string{"version", "version_source", "evidence", "files", "file", "line", "current", "want", "detail", "fixed", "docs", "verified"}
	written := writtenKeys(out)
	for _, key := range optional {
		if !written[key] {
			t.Errorf("no entry of the fixture writes the %q field", key)
		}
	}
	assertNoEmptyStrings(t, "", out)
}

func requireKeys(t *testing.T, where string, obj map[string]any, keys []string) {
	t.Helper()
	if len(keys) == 0 {
		t.Fatalf("the schema requires nothing of %s, which cannot be right", where)
	}
	for _, key := range keys {
		if _, ok := obj[key]; !ok {
			t.Errorf("%s does not carry the required field %q", where, key)
		}
	}
}

// writtenKeys is every key the document uses, at any depth.
func writtenKeys(value any) map[string]bool {
	out := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch typed := v.(type) {
		case map[string]any:
			for key, child := range typed {
				out[key] = true
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return out
}

// assertNoEmptyStrings fails for a value written as "", which the document must say
// by omitting the key instead. The policy path is the one exception: it is a field of
// the shape shared with report.v1, where an empty path means the built-in defaults.
func assertNoEmptyStrings(t *testing.T, pointer string, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			assertNoEmptyStrings(t, pointer+"/"+key, child)
		}
	case []any:
		for i, child := range typed {
			assertNoEmptyStrings(t, pointer+"/"+string(rune('0'+i)), child)
		}
	case string:
		if typed == "" && pointer != "/policy/path" {
			t.Errorf("%s is written as an empty string, which must be an absent key instead", pointer)
		}
	}
}
