package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// renderMarkdown writes r and returns the comment with LF line endings.
func renderMarkdown(t *testing.T, r *Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := (Markdown{}).Write(&buf, r); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return string(normalizeNewlines(buf.Bytes()))
}

// splitRow splits a table row into its cells at the pipes that separate them,
// ignoring the escaped ones, which is what a markdown renderer does.
func splitRow(row string) []string {
	var cells []string
	var cell strings.Builder
	escaped := false
	for _, r := range strings.TrimSpace(row) {
		switch {
		case escaped:
			cell.WriteRune(r)
			escaped = false
		case r == '\\':
			cell.WriteRune(r)
			escaped = true
		case r == '|':
			cells = append(cells, strings.TrimSpace(cell.String()))
			cell.Reset()
		default:
			cell.WriteRune(r)
		}
	}
	cells = append(cells, strings.TrimSpace(cell.String()))
	// A row starts and ends with a pipe, so the first and the last cell are empty.
	return cells[1 : len(cells)-1]
}

func tableRows(t *testing.T, out string) [][]string {
	t.Helper()
	var rows [][]string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "|") {
			rows = append(rows, splitRow(line))
		}
	}
	return rows
}

func TestMarkdownGolden(t *testing.T) {
	assertGolden(t, "report.markdown.golden", Markdown{})
}

func TestMarkdownComment(t *testing.T) {
	out := renderMarkdown(t, fixtureReport())

	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if want := "## trustdiff: 3 subjects, 1 block, 1 warn, 0 info, 1 skipped check"; lines[0] != want {
		t.Errorf("heading = %q, want %q", lines[0], want)
	}
	if want := "Exit code 1 (blocking findings)."; lines[len(lines)-1] != want {
		t.Errorf("last line = %q, want %q", lines[len(lines)-1], want)
	}
	if strings.Contains(out, "<") {
		t.Errorf("the comment must be markdown, with no HTML in it:\n%s", out)
	}

	rows := tableRows(t, out)
	if len(rows) != 4 {
		t.Fatalf("table has %d rows, want a header, a rule and the two findings:\n%s", len(rows), out)
	}
	want := [][]string{
		{"Package", "Level", "Check", "Finding", "Location"},
		{"---", "---", "---", "---", "---"},
		{"npm:example-lib@4.19.3", "block", "TD002 publisher-changed", "Publisher of 4.19.3 is not among the previous publishers", "package-lock.json:42"},
		{"npm:example-lib@4.19.3", "warn", "TD001 young-version", "Version is 6 hours old", "package-lock.json:42"},
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

	// The subject whose only check could not run says so; the clean one says nothing,
	// because a table of findings plus a line per silence is a comment nobody reads.
	skipped := "pypi:example-tool@2.0.0: no findings, 1 skipped check (TD001: pypi.org unavailable in offline mode and no cached response)."
	if !strings.Contains(out, "\n"+skipped+"\n") {
		t.Errorf("comment does not carry the skipped check line %q:\n%s", skipped, out)
	}
	if strings.Contains(out, "cargo:example-crate") {
		t.Errorf("a subject with no findings and nothing skipped needs no line of its own:\n%s", out)
	}
}

// A finding is text a package author can influence, so nothing in it may break the
// table apart or end the row.
func TestMarkdownEscapesCells(t *testing.T) {
	ref := model.MustParseRef("npm:example-lib@1.0.0")
	loc := &model.Location{Path: "packages/a|b/package-lock.json", Line: 7}
	r := Build([]Subject{{
		Ref: ref, Location: loc, Evaluated: []string{"TD007"},
		Findings: []model.Finding{{
			ID: "TD007", Name: "new-dependency-introduced", Level: model.LevelWarn, Ref: ref,
			Title:       "Adds | a dependency\nwith a break and a backslash \\| in it",
			Explanation: "the title is what a table cell has to survive",
			Location:    loc,
		}},
	}}, testTool(), testPolicy(), model.LevelBlock)

	out := renderMarkdown(t, r)
	rows := tableRows(t, out)
	if len(rows) != 3 {
		t.Fatalf("table has %d rows, want a header, a rule and one finding:\n%s", len(rows), out)
	}
	row := rows[2]
	if len(row) != 5 {
		t.Fatalf("row has %d cells, want 5: %q", len(row), row)
	}
	if want := `Adds \| a dependency with a break and a backslash \\\| in it`; row[3] != want {
		t.Errorf("finding cell = %q, want %q", row[3], want)
	}
	if want := `packages/a\|b/package-lock.json:7`; row[4] != want {
		t.Errorf("location cell = %q, want %q", row[4], want)
	}
	if strings.Count(out, "\n|") != 3 {
		t.Errorf("a newline in a finding started a new row:\n%s", out)
	}
}

func TestMarkdownWithoutFindings(t *testing.T) {
	r := Build([]Subject{
		{
			Ref:     model.MustParseRef("pypi:example-tool@2.0.0"),
			Skipped: []model.Skipped{{Check: "TD001", Reason: "pypi.org unavailable"}, {Check: "TD012", Reason: "deps.dev unavailable"}},
		},
		{Ref: model.MustParseRef("cargo:example-crate@1.0.0"), Evaluated: []string{"TD001"}},
	}, testTool(), testPolicy(), model.LevelBlock)

	out := renderMarkdown(t, r)
	want := `## trustdiff: 2 subjects, 0 block, 0 warn, 0 info, 2 skipped checks

No findings.

pypi:example-tool@2.0.0: no findings, 2 skipped checks (TD001: pypi.org unavailable; TD012: deps.dev unavailable).

Exit code 0 (no blocking findings).
`
	if out != want {
		t.Errorf("comment =\n%s\nwant\n%s", out, want)
	}
}

func TestMarkdownEmptyReport(t *testing.T) {
	out := renderMarkdown(t, Build(nil, testTool(), testPolicy(), model.LevelBlock))
	want := `## trustdiff: 0 subjects, 0 block, 0 warn, 0 info, 0 skipped checks

No findings.

Exit code 0 (no blocking findings).
`
	if out != want {
		t.Errorf("comment =\n%s\nwant\n%s", out, want)
	}
}

// A finding with no lockfile behind it leaves the location cell empty rather than
// inventing a file.
func TestMarkdownWithoutLocation(t *testing.T) {
	ref := model.MustParseRef("npm:example-lib@1.0.0")
	r := Build([]Subject{{
		Ref: ref, Evaluated: []string{"TD012"},
		Findings: []model.Finding{{
			ID: "TD012", Name: "low-usage", Level: model.LevelInfo, Ref: ref,
			Title: "12 weekly downloads", Explanation: "below the threshold of 500",
		}},
	}}, testTool(), testPolicy(), model.LevelBlock)

	rows := tableRows(t, renderMarkdown(t, r))
	if got := rows[2][4]; got != "" {
		t.Errorf("location cell = %q, want it empty", got)
	}
}

func TestEscapeCell(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "Version is 6 hours old", want: "Version is 6 hours old"},
		{name: "pipe", in: "a|b", want: `a\|b`},
		{name: "backslash", in: `a\b`, want: `a\\b`},
		{name: "backslash before pipe", in: `a\|b`, want: `a\\\|b`},
		{name: "line feed", in: "a\nb", want: "a b"},
		{name: "carriage return line feed", in: "a\r\nb", want: "a b"},
		{name: "carriage return", in: "a\rb", want: "a b"},
		{name: "trimmed", in: "  a  ", want: "a"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeCell(tt.in); got != tt.want {
				t.Errorf("escapeCell(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
