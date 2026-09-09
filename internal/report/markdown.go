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
// The table is the whole report a reviewer sees, so cells are escaped: a pipe or a
// backslash in a finding cannot break the columns, and a newline cannot break the
// row. There is no HTML anywhere, which keeps the comment readable as text in a diff
// and in an email notification. The full explanation of a finding stays in the json
// and sarif formats; a table cell holds the title.
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
// checks that could not run, each followed by a blank line.
func writeMarkdownSkipped(b *strings.Builder, r *Report) {
	for i := range r.Subjects {
		s := &r.Subjects[i]
		if len(s.Findings) != 0 || len(s.Skipped) == 0 {
			continue
		}
		reasons := make([]string, 0, len(s.Skipped))
		for _, sk := range s.Skipped {
			reasons = append(reasons, oneLine(sk.Check)+": "+oneLine(sk.Reason))
		}
		fmt.Fprintf(b, "%s: no findings, %s (%s).\n\n",
			oneLine(s.Ref.String()),
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

// escapeCell makes a string safe to put between two pipes. A backslash is doubled
// first so that the backslash escaping the pipe cannot be swallowed by a backslash
// already in the text, and every kind of line break becomes a space, because a table
// row is one line and nothing a check writes may end it.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return oneLine(s)
}

// oneLine collapses CR, LF and CRLF into single spaces and trims the ends.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}
