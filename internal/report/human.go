package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Layout of a card. The explanation indent plus the minimum text width is the
// narrowest line the writer produces whatever Width says.
const (
	humanDefaultWidth      = 80
	humanIndentGroup       = 2
	humanIndentFinding     = 4
	humanIndentExplanation = 6
	humanMinTextWidth      = 20
)

// ANSI SGR parameters. They are only ever emitted when Human.Color is true.
const (
	ansiReset      = "\x1b[0m"
	ansiBold       = "1"
	ansiDim        = "2"
	ansiRed        = "31"
	ansiGreen      = "32"
	ansiYellow     = "33"
	ansiCyan       = "36"
	ansiBoldRed    = "1;31"
	ansiBoldGreen  = "1;32"
	ansiBoldYellow = "1;33"
	ansiBoldCyan   = "1;36"
	ansiBoldDim    = "1;2"
)

// Human writes one card per subject followed by a summary line:
//
//	npm:example-lib@4.19.3  BLOCK  (package-lock.json:42, direct)
//	  block
//	    TD002 publisher-changed: Publisher of 4.19.3 is not among the previous publishers
//	      previous 5 versions were published by alice; 4.19.3 was published by
//	      bob-ci
//	  skipped TD012: downloads API unavailable in offline mode
//
//	1 subject, 1 block, 0 warn, 0 info, 1 skipped check. Exit code 1 (blocking findings).
//
// Findings are grouped under their level in the order Build sorted them. Explanations
// wrap at Width columns. Color adds ANSI escape sequences around single words and
// never changes the layout, so the output with and without color differs only in the
// escape codes.
type Human struct {
	Color bool
	// Width is the terminal width in columns; zero or less means 80.
	Width int
}

// Write renders r to w in one call.
func (h Human) Write(w io.Writer, r *Report) error {
	var b strings.Builder
	for i := range r.Subjects {
		h.writeCard(&b, &r.Subjects[i])
		b.WriteString("\n")
	}
	b.WriteString(summaryCounts(r.Summary))
	b.WriteString(" ")
	b.WriteString(h.paint(exitColor(r.Summary.ExitCode), summaryExit(r.Summary)))
	b.WriteString("\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write human report: %w", err)
	}
	return nil
}

func (h Human) writeCard(b *strings.Builder, s *Subject) {
	b.WriteString(h.paint(ansiBold, s.Ref.String()))
	b.WriteString("  ")
	b.WriteString(h.paint(verdictColor(s.Verdict), strings.ToUpper(s.Verdict)))
	if origin := subjectOrigin(s); origin != "" {
		b.WriteString("  (")
		b.WriteString(origin)
		b.WriteString(")")
	}
	b.WriteString("\n")

	// Findings arrive sorted by level, so a level heading is written whenever the
	// level changes. Every level present is shown, whatever it is.
	for i := range s.Findings {
		f := &s.Findings[i]
		if i == 0 || f.Level != s.Findings[i-1].Level {
			b.WriteString(indent(humanIndentGroup))
			b.WriteString(h.paint(levelColor(f.Level), f.Level.String()))
			b.WriteString("\n")
		}
		h.writeFinding(b, f)
	}

	for _, sk := range s.Skipped {
		b.WriteString(indent(humanIndentGroup))
		b.WriteString(h.paint(ansiDim, "skipped"))
		b.WriteString(" ")
		b.WriteString(sk.Check)
		b.WriteString(": ")
		b.WriteString(sk.Reason)
		b.WriteString("\n")
	}
}

func (h Human) writeFinding(b *strings.Builder, f *model.Finding) {
	b.WriteString(indent(humanIndentFinding))
	b.WriteString(h.paint(ansiBold, f.ID))
	b.WriteString(" ")
	b.WriteString(f.Name)
	b.WriteString(": ")
	b.WriteString(f.Title)
	b.WriteString("\n")
	for _, line := range wrap(f.Explanation, h.textWidth()) {
		b.WriteString(indent(humanIndentExplanation))
		b.WriteString(line)
		b.WriteString("\n")
	}
}

// textWidth is the room left for an explanation line after its indent.
func (h Human) textWidth() int {
	width := h.Width
	if width <= 0 {
		width = humanDefaultWidth
	}
	return max(width-humanIndentExplanation, humanMinTextWidth)
}

// paint wraps s in the SGR sequence for code when color is on. An empty code means
// no styling for this element.
func (h Human) paint(code, s string) string {
	if !h.Color || code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + ansiReset
}

func indent(n int) string { return strings.Repeat(" ", n) }

// subjectOrigin describes where the subject came from: the lockfile line and whether
// it is a direct dependency. Empty for a subject given on the command line.
func subjectOrigin(s *Subject) string {
	var parts []string
	if s.Location != nil && s.Location.Path != "" {
		loc := s.Location.Path
		if s.Location.Line > 0 {
			loc += ":" + strconv.Itoa(s.Location.Line)
		}
		parts = append(parts, loc)
	}
	if s.Direct {
		parts = append(parts, "direct")
	}
	return strings.Join(parts, ", ")
}

func verdictColor(verdict string) string {
	switch verdict {
	case VerdictBlock:
		return ansiBoldRed
	case VerdictWarn:
		return ansiBoldYellow
	case VerdictInfo:
		return ansiBoldCyan
	case VerdictOK:
		return ansiBoldGreen
	case VerdictSkipped:
		return ansiBoldDim
	}
	return ansiBold
}

func levelColor(level model.Level) string {
	switch level {
	case model.LevelBlock:
		return ansiRed
	case model.LevelWarn:
		return ansiYellow
	case model.LevelInfo:
		return ansiCyan
	case model.LevelOff:
		return ansiDim
	}
	return ""
}

func exitColor(code int) string {
	switch code {
	case 0:
		return ansiGreen
	case 1:
		return ansiRed
	case 3:
		return ansiYellow
	}
	return ""
}

// summaryLine is the closing line of the human report without color.
func summaryLine(s Summary) string {
	return summaryCounts(s) + " " + summaryExit(s)
}

func summaryCounts(s Summary) string {
	return fmt.Sprintf("%s, %d block, %d warn, %d info, %s.",
		plural(s.Subjects, "subject", "subjects"),
		s.Findings[model.LevelBlock.String()],
		s.Findings[model.LevelWarn.String()],
		s.Findings[model.LevelInfo.String()],
		plural(s.Skipped, "skipped check", "skipped checks"))
}

func summaryExit(s Summary) string {
	return fmt.Sprintf("Exit code %d (%s).", s.ExitCode, s.ExitMeaning)
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + pluralForm
}

// wrap breaks text into lines of at most width runes, filling each line greedily on
// whitespace. Runs of whitespace, including newlines, collapse to one space. A word
// longer than width stands alone on its own line rather than being cut. A width of
// zero or less disables wrapping. The result is nil for text without words.
func wrap(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	lineLen := utf8.RuneCountInString(line)
	for _, word := range words[1:] {
		n := utf8.RuneCountInString(word)
		if width > 0 && lineLen+1+n > width {
			lines = append(lines, line)
			line, lineLen = word, n
			continue
		}
		line += " " + word
		lineLen += 1 + n
	}
	return append(lines, line)
}
