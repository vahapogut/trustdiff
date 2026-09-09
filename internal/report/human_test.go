package report

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

func TestWrap(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		width int
		want  []string
	}{
		{name: "empty", in: "", width: 20, want: nil},
		{name: "whitespace only", in: "  \n\t ", width: 20, want: nil},
		{name: "fits", in: "short text", width: 20, want: []string{"short text"}},
		{name: "exact boundary stays on one line", in: "aaaa bbbbb", width: 10, want: []string{"aaaa bbbbb"}},
		{name: "one over the boundary wraps", in: "aaaa bbbbbb", width: 10, want: []string{"aaaa", "bbbbbb"}},
		{name: "greedy fill", in: "one two three four five six", width: 13, want: []string{"one two three", "four five six"}},
		{name: "long word stands alone", in: "abcdefgh ij", width: 5, want: []string{"abcdefgh", "ij"}},
		{name: "long word in the middle", in: "a abcdefgh b", width: 5, want: []string{"a", "abcdefgh", "b"}},
		{name: "runs of whitespace collapse", in: "a  b\nc\t d", width: 80, want: []string{"a b c d"}},
		{name: "counts runes not bytes", in: "ééé ééé", width: 7, want: []string{"ééé ééé"}},
		{name: "counts runes not bytes when wrapping", in: "ééé ééé", width: 6, want: []string{"ééé", "ééé"}},
		{name: "zero width means no wrapping", in: "one two three", width: 0, want: []string{"one two three"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrap(tt.in, tt.width)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("wrap(%q, %d) = %q, want %q", tt.in, tt.width, got, tt.want)
			}
		})
	}
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestHumanColorLayoutMatchesPlain(t *testing.T) {
	var plain, color bytes.Buffer
	if err := (Human{Color: false, Width: 80}).Write(&plain, fixtureReport()); err != nil {
		t.Fatalf("Write plain: %v", err)
	}
	if err := (Human{Color: true, Width: 80}).Write(&color, fixtureReport()); err != nil {
		t.Fatalf("Write color: %v", err)
	}
	if !strings.Contains(color.String(), "\x1b[") {
		t.Fatal("color output carries no escape sequence")
	}
	if strings.Contains(plain.String(), "\x1b[") {
		t.Fatal("plain output carries an escape sequence")
	}
	stripped := ansiEscape.ReplaceAllString(color.String(), "")
	if stripped != plain.String() {
		t.Fatalf("layout differs once escape codes are removed\n--- color stripped ---\n%s\n--- plain ---\n%s", stripped, plain.String())
	}
}

func TestSummaryLine(t *testing.T) {
	tests := []struct {
		name string
		in   Summary
		want string
	}{
		{
			name: "plural everything",
			in:   Summary{Subjects: 3, Findings: map[string]int{"block": 1, "warn": 2, "info": 0}, Skipped: 1, ExitCode: 1, ExitMeaning: "blocking findings"},
			want: "3 subjects, 1 block, 2 warn, 0 info, 1 skipped check. Exit code 1 (blocking findings).",
		},
		{
			name: "singular subject and plural skipped",
			in:   Summary{Subjects: 1, Findings: map[string]int{"block": 0, "warn": 0, "info": 0}, Skipped: 2, ExitCode: 0, ExitMeaning: "no blocking findings"},
			want: "1 subject, 0 block, 0 warn, 0 info, 2 skipped checks. Exit code 0 (no blocking findings).",
		},
		{
			name: "empty",
			in:   Summary{Findings: map[string]int{}, ExitCode: 0, ExitMeaning: "no blocking findings"},
			want: "0 subjects, 0 block, 0 warn, 0 info, 0 skipped checks. Exit code 0 (no blocking findings).",
		},
		{
			name: "unavailable",
			in:   Summary{Subjects: 2, Findings: map[string]int{"block": 0, "warn": 0, "info": 0}, Skipped: 4, ExitCode: 3, ExitMeaning: "a required data source was unavailable"},
			want: "2 subjects, 0 block, 0 warn, 0 info, 4 skipped checks. Exit code 3 (a required data source was unavailable).",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summaryLine(tt.in); got != tt.want {
				t.Fatalf("summaryLine = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHumanWidth(t *testing.T) {
	ref := model.MustParseRef("npm:example-lib@1.0.0")
	explanation := strings.Repeat("word ", 30) + "end"
	subject := Subject{
		Ref:       ref,
		Evaluated: []string{"TD001"},
		Findings:  []model.Finding{{ID: "TD001", Name: "young-version", Level: model.LevelWarn, Ref: ref, Title: "t", Explanation: explanation}},
	}
	report := Build([]Subject{subject}, testTool(), testPolicy(), model.LevelBlock)

	tests := []struct {
		name     string
		width    int
		maxWidth int
	}{
		{name: "narrow", width: 40, maxWidth: 40},
		{name: "default when zero", width: 0, maxWidth: 80},
		{name: "tiny width keeps a readable minimum", width: 8, maxWidth: humanIndentExplanation + humanMinTextWidth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := (Human{Width: tt.width}).Write(&buf, report); err != nil {
				t.Fatalf("Write: %v", err)
			}
			lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
			explanationLines := 0
			for _, line := range lines {
				if !strings.HasPrefix(line, strings.Repeat(" ", humanIndentExplanation)+"word") && !strings.HasPrefix(line, strings.Repeat(" ", humanIndentExplanation)+"end") {
					continue
				}
				explanationLines++
				if n := len([]rune(line)); n > tt.maxWidth {
					t.Errorf("explanation line is %d wide, limit %d: %q", n, tt.maxWidth, line)
				}
			}
			if explanationLines < 2 {
				t.Errorf("explanation was not wrapped:\n%s", buf.String())
			}
			if !strings.Contains(buf.String(), "end") {
				t.Errorf("explanation text was lost:\n%s", buf.String())
			}
		})
	}
}

func TestHumanCardsAndSummary(t *testing.T) {
	var buf bytes.Buffer
	if err := (Human{Width: 80}).Write(&buf, fixtureReport()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	wantLines := []string{
		"npm:example-lib@4.19.3  BLOCK  (package-lock.json:42, direct)",
		"    TD002 publisher-changed: Publisher of 4.19.3 is not among the previous publishers",
		"    TD001 young-version: Version is 6 hours old",
		"pypi:example-tool@2.0.0  SKIPPED",
		"  skipped TD001: pypi.org unavailable in offline mode and no cached response",
		"cargo:example-crate@1.0.0  OK",
		"3 subjects, 1 block, 1 warn, 0 info, 1 skipped check. Exit code 1 (blocking findings).",
	}
	last := -1
	for _, want := range wantLines {
		idx := strings.Index(out, want+"\n")
		if idx < 0 {
			t.Errorf("missing line %q in:\n%s", want, out)
			continue
		}
		if idx < last {
			t.Errorf("line %q appears out of order", want)
		}
		last = idx
	}
	if strings.Index(out, "  block\n") > strings.Index(out, "  warn\n") {
		t.Errorf("block group must come before warn group:\n%s", out)
	}
	if !strings.HasSuffix(out, ".\n") {
		t.Errorf("output must end with the summary line and one newline:\n%q", out)
	}
}
