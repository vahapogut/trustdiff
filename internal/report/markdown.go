package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Markdown writes the report as a comment for a pull request:
//
//	## trustdiff: 3 subjects, 1 block, 1 warn, 0 info, 1 skipped check
//
//	| Package | Level | Check | Finding | Location |
//	| --- | --- | --- | --- | --- |
//	| npm:example-lib@4.19.3 | block | TD002 publisher-changed | ... | package-lock.json:42 |
//
//	pypi:example-tool@2.0.0: no findings, 1 skipped check (TD001: pypi.org unavailable).
//
//	Exit code 1 (blocking findings).
//
// One row per finding, in the order the report holds them, which is subject by
// subject and inside a subject by level, most severe first. A subject with findings
// says everything it has to say in its rows; a subject with none but with checks that
// could not run gets a line of its own, because a check that did not run is not a
// pass. The closing line is the exit code and what it means, so that the comment says
// whether the gate failed without anyone opening the log.
//
// The table is the whole report a reviewer sees, and everything in it comes from a
// lockfile a pull request may have written, so every value is escaped: a pipe or a
// backslash cannot break the columns, a newline cannot break the row, and none of the
// punctuation that starts markdown or HTML can turn a package name into a link, an
// image or a details block that hides the rest of the row. What the comment renders
// is therefore the text the lockfile holds, character for character, and there is no
// HTML anywhere, which also keeps it readable as text in a diff and in an email
// notification. The full explanation of a finding stays in the json and sarif
// formats; a table cell holds the title.
type Markdown struct{}

// Write renders r to w in one call.
func (Markdown) Write(w io.Writer, r *Report) error {
	var b strings.Builder
	b.WriteString("## ")
	b.WriteString(markdownHeading(r))
	b.WriteString("\n\n")
	writeMarkdownTable(&b, r)
	writeMarkdownSkipped(&b, r)
	b.WriteString(summaryExit(r.Summary))
	b.WriteString("\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write markdown report: %w", err)
	}
	return nil
}

// markdownHeading names the tool and carries the counts, without the trailing period
// the same sentence has in the human report: a heading does not end in one.
func markdownHeading(r *Report) string {
	return "trustdiff: " + strings.TrimSuffix(summaryCounts(r.Summary), ".")
}

// writeMarkdownTable writes the finding table, or one line when the run found
// nothing, followed by a blank line.
func writeMarkdownTable(b *strings.Builder, r *Report) {
	rows := 0
	for i := range r.Subjects {
		rows += len(r.Subjects[i].Findings)
	}
	if rows == 0 {
		b.WriteString("No findings.\n\n")
		return
	}
	b.WriteString("| Package | Level | Check | Finding | Location |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for i := range r.Subjects {
		s := &r.Subjects[i]
		for j := range s.Findings {
			f := &s.Findings[j]
			writeMarkdownRow(b,
				f.Ref.String(),
				f.Level.String(),
				strings.TrimSpace(f.ID+" "+f.Name),
				f.Title,
				markdownLocation(findingLocation(f, s)))
		}
	}
	b.WriteString("\n")
}

func writeMarkdownRow(b *strings.Builder, cells ...string) {
	b.WriteString("|")
	for _, cell := range cells {
		b.WriteString(" ")
		b.WriteString(escapeCell(cell))
		b.WriteString(" |")
	}
	b.WriteString("\n")
}

// writeMarkdownSkipped writes one line per subject that has no findings but has
// checks that could not run, each followed by a blank line. The package ref and the
// reason are escaped like a table cell: they come from the same lockfile and the same
// registry, and a line outside the table renders markup just as readily as one in it.
func writeMarkdownSkipped(b *strings.Builder, r *Report) {
	for i := range r.Subjects {
		s := &r.Subjects[i]
		if len(s.Findings) != 0 || len(s.Skipped) == 0 {
			continue
		}
		reasons := make([]string, 0, len(s.Skipped))
		for _, sk := range s.Skipped {
			reasons = append(reasons, escapeCell(sk.Check)+": "+escapeCell(sk.Reason))
		}
		fmt.Fprintf(b, "%s: no findings, %s (%s).\n\n",
			escapeCell(s.Ref.String()),
			plural(len(s.Skipped), "skipped check", "skipped checks"),
			strings.Join(reasons, "; "))
	}
}

// markdownLocation is the lockfile path and, when the parser recorded one, the line.
// It is empty for a subject named on the command line.
func markdownLocation(loc *model.Location) string {
	if loc == nil || loc.Path == "" {
		return ""
	}
	if loc.Line > 0 {
		return loc.Path + ":" + strconv.Itoa(loc.Line)
	}
	return loc.Path
}

// markdownSpecial is the punctuation escapeCell puts a backslash in front of. Each
// character can start inline markup or raw HTML: a backtick opens code, an asterisk
// or an underscore emphasis, a bracket a link or, after an exclamation mark, an
// image, a tilde a strikethrough, an ampersand a character reference, an angle
// bracket an HTML tag or an autolink, and a pipe ends the cell. The exclamation mark
// needs no escape of its own once the bracket carries one. GFM accepts a backslash
// before any ASCII punctuation, so escaping a character that did not need it changes
// nothing a reader sees.
const markdownSpecial = "`*_[]<>&~|"

// escapeCell makes a string safe to put between two pipes, whoever wrote it: a
// lockfile in a pull request from a fork decides the package names and versions this
// comment prints, and a name spelled "[trustdiff passed](https://example.test)" or a
// version carrying an HTML tag would otherwise render as the tool's own words. Every
// character of markdownSpecial is escaped, the backslash included so that the escape
// cannot be swallowed by a backslash already in the text, and every kind of line
// break becomes a space, because a table row is one line and nothing may end it.
func escapeCell(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		// Only ASCII is escaped, and every byte of a multi-byte rune is above ASCII,
		// so walking the bytes cannot split one.
		if c := s[i]; c == '\\' || strings.IndexByte(markdownSpecial, c) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return oneLine(b.String())
}

// oneLine collapses CR, LF and CRLF into single spaces and trims the ends.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}
