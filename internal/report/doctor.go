package report

// The doctor scorecard is rendered here rather than in internal/doctor for the same
// reason the report is rendered here: the package that finds things and the package
// that prints them are separate, so a new format changes one file and no judgment.
// This is the only file of the package that imports internal/doctor, which is why
// the package comment in report.go names internal/model and internal/version as the
// packages the rest of it depends on.

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/vahapogut/trustdiff/internal/doctor"
	"github.com/vahapogut/trustdiff/internal/model"
)

// DoctorSchemaID identifies the JSON doctor document. The scorecard is its own
// document rather than a subject inside a report because a configuration file is not
// a package in a registry and a doctor rule is not a check that read one, which
// ADR 0003 records. It changes only with a breaking change to the document shape;
// fields are added within a version, never renamed or removed.
const DoctorSchemaID = "trustdiff.doctor/1"

// doctorStatusWidth is the width of the status column of the human rendering. It is
// the length of the longest status, "not applicable", so that every rule line starts
// its id in the same column and a reader can run an eye down the statuses.
const doctorStatusWidth = 14

// doctorSummaryOrder is the order the summary line and the statuses object name the
// statuses in: what is right first, then the three problems, then what does not
// apply. It is not the order the results are sorted in, which puts the problems
// first because those are what somebody opened the scorecard for.
var doctorSummaryOrder = []doctor.Status{
	doctor.StatusSet,
	doctor.StatusWrong,
	doctor.StatusMissing,
	doctor.StatusUnreadable,
	doctor.StatusAdvice,
	doctor.StatusNotApplicable,
}

// Doctor is the complete result of one doctor run, in the shape of
// schema/doctor.v1.json. Construct it with BuildDoctor so that the slices are never
// nil, the results are sorted and the summary agrees with what the results say.
type Doctor struct {
	// Schema is always DoctorSchemaID.
	Schema string `json:"schema"`
	// Tool is the build identity of the binary that wrote the document, in the shape
	// the report document uses, so a script that reads one reads the other.
	Tool Tool `json:"tool"`
	// Policy is the settings the run worked under, in the report document's shape.
	Policy Policy `json:"policy"`
	// Root is the directory that was scanned, as it was given.
	Root string `json:"root"`
	// Managers are the package managers found, in the order detection returned them.
	Managers []DoctorManager `json:"managers"`
	// Results are every rule evaluated against every manager, problems first.
	Results []DoctorResult `json:"results"`
	// Notes are the things the run could not read, one line each.
	Notes []string `json:"notes"`
	// Summary carries the counts and the exit code, so a CI step needs nothing else.
	Summary DoctorSummary `json:"summary"`
}

// DoctorManager is one package manager found in the repository. The same id appears
// more than once in a monorepo, once per directory, which is why the root is part of
// the entry rather than something a reader has to infer from a file path.
type DoctorManager struct {
	// ID is which manager it is, spelled the way a policy file spells it.
	ID string `json:"id"`
	// Version is the version the repository pins or the machine has, omitted when
	// nothing said so. The rules that need one then report not applicable.
	Version string `json:"version,omitempty"`
	// VersionSource says where Version came from, in the words the scorecard prints,
	// and is omitted when no version was found.
	VersionSource string `json:"version_source,omitempty"`
	// Root is the directory this manager manages, relative to the scan root, "." for
	// the repository itself.
	Root string `json:"root"`
	// Evidence is what made this manager count as present, one line each, omitted
	// when detection recorded none.
	Evidence []string `json:"evidence,omitempty"`
	// Files are the configuration files found for it, omitted when none exists.
	Files []string `json:"files,omitempty"`
}

// DoctorResult is one rule evaluated against one manager. It carries the values as
// well as the sentence, because a pull request comment wants the value and a person
// reading a terminal wants the sentence.
type DoctorResult struct {
	// Rule is the stable rule id, for example DR001.
	Rule string `json:"rule"`
	// Name is the rule's policy name, which is how a policy file turns it off.
	Name string `json:"name"`
	// Manager is the id of the manager the rule was evaluated for.
	Manager string `json:"manager"`
	// Status is what the rule concluded.
	Status string `json:"status"`
	// Level is the level after the policy was applied.
	Level model.Level `json:"level"`
	// File is the file that was read, relative to the scan root, omitted when none of
	// the rule's files exists and none may be created.
	File string `json:"file,omitempty"`
	// Line is the 1-based line of the value, omitted when there is none to point at.
	Line int `json:"line,omitempty"`
	// Current is the value as the file writes it, omitted when the key is absent.
	Current string `json:"current,omitempty"`
	// Want is what the rule asks for, as it would be written, omitted for a rule that
	// has no value to write.
	Want string `json:"want,omitempty"`
	// Detail is the sentence after the status, omitted when the status says
	// everything there is to say.
	Detail string `json:"detail,omitempty"`
	// Fixed is true when --fix wrote this setting in this run, which is why a status
	// of set can describe a file that was wrong when the run started.
	Fixed bool `json:"fixed,omitempty"`
	// Docs is the page the rule was verified against, omitted when it cites none.
	Docs string `json:"docs,omitempty"`
	// Verified is the date that page was last read, omitted when the rule has none.
	Verified string `json:"verified,omitempty"`
	// Edit is the unified diff --fix wrote. The human rendering prints it under the
	// line and the document formats leave it out: a diff is something to read, not a
	// field to consume, and the file itself already holds the result.
	Edit string `json:"-"`
	// manager is the index into Doctor.Managers of the manager this result belongs
	// to, so the human rendering can group by manager without matching on names.
	manager int
}

// DoctorSummary carries the counts and the exit code, in the shape the report
// document's summary uses for the two fields that mean the same thing.
type DoctorSummary struct {
	// Managers is the number of entries in Managers.
	Managers int `json:"managers"`
	// Results is the number of entries in Results.
	Results int `json:"results"`
	// Statuses counts the results by status. Every key is present even when its
	// count is zero, and the keys are the status values themselves, so a reader can
	// count with the status field of a result.
	Statuses map[string]int `json:"statuses"`
	// ExitCode is the process exit code.
	ExitCode int `json:"exit_code"`
	// ExitMeaning is that code spelled out.
	ExitMeaning string `json:"exit_meaning"`
}

// BuildDoctor assembles the document from a scorecard, which may be nil for a run
// that found nothing to look at. Managers keep the order detection returned them.
// The results are sorted so that the problems come first, wrong before missing
// before unreadable, and what is already set and what does not apply come last,
// keeping the scorecard's own order, by manager and then by rule id, inside each
// group. The exit code is 1 when a problem is at or above failOn and 0 otherwise;
// failOn model.LevelOff means never. Exit code 3 is the caller's decision: call
// SetExitCode after BuildDoctor, the way the report does.
//
// A result whose manager is not one of the scorecard's own gets an entry of its own,
// so that no rule the scorecard evaluated is dropped from a rendering.
func BuildDoctor(card *doctor.Scorecard, tool Tool, policy Policy, failOn model.Level) *Doctor { //nolint:gocritic // Tool is five strings; the by-value signature is the package API, as it is for Build.
	if card == nil {
		card = &doctor.Scorecard{}
	}
	d := &Doctor{
		Schema:   DoctorSchemaID,
		Tool:     tool,
		Policy:   policy,
		Root:     doctorRoot(card.Root),
		Managers: make([]DoctorManager, 0, len(card.Managers)),
		Results:  make([]DoctorResult, 0, len(card.Results)),
		Notes:    slices.Clone(card.Notes),
		Summary:  DoctorSummary{Statuses: doctorStatusCounts()},
	}
	if d.Notes == nil {
		d.Notes = []string{}
	}
	index := make(map[*doctor.Manager]int, len(card.Managers))
	for _, m := range card.Managers {
		index[m] = len(d.Managers)
		d.Managers = append(d.Managers, doctorManager(m))
	}
	for i := range card.Results {
		res := &card.Results[i]
		out := doctorResult(res)
		if m := res.Manager; m != nil {
			at, ok := index[m]
			if !ok {
				at = len(d.Managers)
				index[m] = at
				d.Managers = append(d.Managers, doctorManager(m))
			}
			out.manager = at
		}
		d.Results = append(d.Results, out)
	}
	slices.SortStableFunc(d.Results, func(a, b DoctorResult) int {
		return doctorStatusRank(a.Status) - doctorStatusRank(b.Status)
	})

	d.Summary.Managers = len(d.Managers)
	d.Summary.Results = len(d.Results)
	exit := 0
	for i := range d.Results {
		res := &d.Results[i]
		// A status this package does not define is left out of the counts rather
		// than adding a key the schema does not name. The result still carries it,
		// where validation reports it.
		if _, ok := d.Summary.Statuses[res.Status]; ok {
			d.Summary.Statuses[res.Status]++
		}
		if failOn != model.LevelOff && doctor.Status(res.Status).Problem() &&
			res.Level != model.LevelOff && res.Level.AtLeast(failOn) {
			exit = 1
		}
	}
	d.SetExitCode(exit)
	return d
}

// SetExitCode overrides the exit code BuildDoctor derived, for the case the results
// alone do not decide: 3 when a file could not be read and the policy says fail.
func (d *Doctor) SetExitCode(code int) {
	d.Summary.ExitCode = code
	d.Summary.ExitMeaning = DoctorExitMeaning(code)
}

// DoctorExitMeaning spells out a doctor exit code the way schema/doctor.v1.json
// documents it. The codes are the ones internal/cli defines and they mirror the
// report's: 0 and 1 are the same question asked of a scorecard rather than of a set
// of findings, and 3 is again the run saying it could not read what it was asked to.
func DoctorExitMeaning(code int) string {
	switch code {
	case 0:
		return "no problems at or above the threshold"
	case 1:
		return "problems at or above the threshold"
	case 2:
		return "usage or configuration error"
	case 3:
		return "a file could not be read"
	}
	return "unknown exit code"
}

// DoctorWriter renders a doctor document. Implementations write the whole document
// in one call and never write anything else to w, because w is usually stdout.
type DoctorWriter interface {
	WriteDoctor(w io.Writer, d *Doctor) error
}

// NewDoctor returns the doctor writer for a --format value: "human" for a terminal,
// "json" for the document schema/doctor.v1.json describes, and "markdown" for a pull
// request comment. Any other name, "sarif" and the empty one included, reports
// ErrUnsupportedFormat and names what it was given: a scorecard is a set of
// configuration files rather than a set of code locations, so there is nothing for a
// code scanning service to annotate.
//
// Only the human writer reads opts, as with New.
func NewDoctor(format string, opts Options) (DoctorWriter, error) {
	switch format {
	case "human":
		return Human(opts), nil
	case "json":
		return JSON{}, nil
	case "markdown":
		return Markdown{}, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
}

// WriteDoctor renders d to w as the document schema/doctor.v1.json describes, with
// the two-space indentation, the struct field order and the unescaped HTML the
// report document is written with.
func (JSON) WriteDoctor(w io.Writer, d *Doctor) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		return fmt.Errorf("encode json doctor document: %w", err)
	}
	return nil
}

// WriteDoctor renders d to w as one block per package manager followed by a summary
// line:
//
//	npm 11.16.0  (version from the packageManager field)
//	  wrong           DR001 npm-min-release-age  .npmrc:3
//	      "1" is 1 day, and the policy asks for 3 days (3 here)
//	  set             DR002 npm-strict-allow-scripts  .npmrc:5  fixed
//	      --- .npmrc
//	      +++ .npmrc
//
//	2 set, 2 wrong, 1 missing, 1 unreadable, 1 not applicable. Exit code 1 (problems at or above the threshold).
//
// The rules of a manager are sorted so the problems are at the top of its block. The
// detail sentence is wrapped under the line the way a finding's explanation is, and
// the diff of a setting --fix wrote is printed under it unchanged, because a diff
// that has been reflowed is not one anybody can read. Notes go above everything, the
// way the other commands print them. Color follows the level of the rule and never
// changes the layout, so the output with and without color differs only in the escape
// codes.
func (h Human) WriteDoctor(w io.Writer, d *Doctor) error {
	var b strings.Builder
	for _, note := range d.Notes {
		b.WriteString(note)
		b.WriteString("\n")
	}
	if len(d.Notes) != 0 {
		b.WriteString("\n")
	}
	for i := range d.Managers {
		h.writeDoctorManager(&b, d, i)
		b.WriteString("\n")
	}
	b.WriteString(doctorSummaryCounts(d.Summary))
	b.WriteString(" ")
	b.WriteString(h.paint(exitColor(d.Summary.ExitCode), doctorSummaryExit(d.Summary)))
	b.WriteString("\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write human doctor scorecard: %w", err)
	}
	return nil
}

// writeDoctorManager writes one manager's header and its rules.
func (h Human) writeDoctorManager(b *strings.Builder, d *Doctor, index int) {
	m := &d.Managers[index]
	if !doctorHasResults(d, index) {
		// A manager whose every rule the policy turned off is a header with nothing
		// under it, which reads as a manager that was somehow not evaluated.
		return
	}
	b.WriteString(h.paint(ansiBold, doctorManagerTitle(m)))
	if origin := doctorManagerOrigin(m); origin != "" {
		b.WriteString("  (")
		b.WriteString(origin)
		b.WriteString(")")
	}
	b.WriteString("\n")
	for i := range d.Results {
		if d.Results[i].manager == index {
			h.writeDoctorResult(b, &d.Results[i])
		}
	}
}

// writeDoctorResult writes one rule: the status, the id, the name, where the value
// is, whether it was written, and then the sentence and the diff under it.
func (h Human) writeDoctorResult(b *strings.Builder, res *DoctorResult) {
	b.WriteString(indent(humanIndentGroup))
	b.WriteString(h.paint(doctorStatusColor(res), res.Status))
	// The padding is written outside the escape sequence so that a colored run and a
	// plain one are the same width.
	b.WriteString(indent(max(doctorStatusWidth-len(res.Status), 0) + humanIndentGroup))
	b.WriteString(h.paint(ansiBold, res.Rule))
	b.WriteString(" ")
	b.WriteString(res.Name)
	if loc := doctorLocation(res); loc != "" {
		b.WriteString("  ")
		b.WriteString(loc)
	}
	if res.Fixed {
		b.WriteString("  ")
		b.WriteString(h.paint(ansiGreen, "fixed"))
	}
	b.WriteString("\n")
	for _, line := range wrap(doctorDetail(res), h.textWidth()) {
		b.WriteString(indent(humanIndentExplanation))
		b.WriteString(line)
		b.WriteString("\n")
	}
	if res.Edit == "" {
		return
	}
	for _, line := range strings.Split(strings.TrimRight(res.Edit, "\n"), "\n") {
		b.WriteString(indent(humanIndentExplanation))
		b.WriteString(line)
		b.WriteString("\n")
	}
}

// WriteDoctor renders d to w as a comment for a pull request:
//
//	## trustdiff doctor: 2 set, 2 wrong, 1 missing, 1 unreadable, 1 not applicable
//
//	| Manager | Rule | Status | Setting | Location |
//	| --- | --- | --- | --- | --- |
//	| npm 11.16.0 | DR001 npm-min-release-age | wrong | 1, want 3 | .npmrc:3 |
//
//	Exit code 1 (problems at or above the threshold).
//
// One row per rule, problems first, so the top of the table is what a reviewer has to
// act on. Every cell goes through the same escaping the report's table uses, and here
// it matters more rather than less: a manager name, a setting and a path all come out
// of files the pull request itself may have written, and the values are somebody's
// own text, not a version string. The sentence a rule holds does not fit a table cell
// and stays in the human and json formats.
func (Markdown) WriteDoctor(w io.Writer, d *Doctor) error {
	var b strings.Builder
	b.WriteString("## ")
	b.WriteString(doctorMarkdownHeading(d))
	b.WriteString("\n\n")
	writeDoctorMarkdownTable(&b, d)
	writeDoctorMarkdownNotes(&b, d)
	b.WriteString(doctorSummaryExit(d.Summary))
	b.WriteString("\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write markdown doctor scorecard: %w", err)
	}
	return nil
}

// writeDoctorMarkdownNotes writes what the run could not read, one line each,
// followed by a blank line. A comment that carried the table and dropped the note
// saying half the repository was unreadable would be a comment that reads as an
// all clear.
//
// The lines are escaped like a table cell, because they name paths a pull request
// chose.
func writeDoctorMarkdownNotes(b *strings.Builder, d *Doctor) {
	if len(d.Notes) == 0 {
		return
	}
	for _, note := range d.Notes {
		b.WriteString(escapeCell(note))
		b.WriteString("\n\n")
	}
}

// doctorMarkdownHeading names the command and carries the counts, without the
// trailing period the same sentence has in the human rendering: a heading does not
// end in one.
func doctorMarkdownHeading(d *Doctor) string {
	return "trustdiff doctor: " + strings.TrimSuffix(doctorSummaryCounts(d.Summary), ".")
}

// writeDoctorMarkdownTable writes the rule table, or one line when the run evaluated
// nothing, followed by a blank line.
func writeDoctorMarkdownTable(b *strings.Builder, d *Doctor) {
	if len(d.Results) == 0 {
		b.WriteString("No rules evaluated.\n\n")
		return
	}
	b.WriteString("| Manager | Rule | Status | Setting | Location |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for i := range d.Results {
		res := &d.Results[i]
		writeMarkdownRow(b,
			doctorManagerCell(d, res),
			strings.TrimSpace(res.Rule+" "+res.Name),
			res.Status,
			doctorSetting(res),
			doctorLocation(res))
	}
	b.WriteString("\n")
}

// doctorManagerCell names the manager of a row: what the human header says, plus the
// directory when the manager is not the repository root, because two rows of the same
// manager in a monorepo are otherwise indistinguishable.
func doctorManagerCell(d *Doctor, res *DoctorResult) string {
	if res.manager < 0 || res.manager >= len(d.Managers) {
		return res.Manager
	}
	m := &d.Managers[res.manager]
	title := doctorManagerTitle(m)
	if m.Root != "." {
		title += " (" + m.Root + ")"
	}
	return title
}

// doctorSetting is the Setting column: what the file says now and, when that is not
// what the rule asks for, what it should say instead.
func doctorSetting(res *DoctorResult) string {
	switch {
	case res.Fixed && res.Want != "":
		// The run wrote this setting, so what the file says now is what the rule
		// asked for. The value it replaced is in the diff the terminal printed,
		// which is not something to put in a pull request comment.
		return res.Want
	case res.Current != "" && res.Want != "" && res.Status != string(doctor.StatusSet):
		return res.Current + ", want " + res.Want
	case res.Current != "":
		return res.Current
	case res.Want != "" && doctor.Status(res.Status).Problem():
		return "want " + res.Want
	}
	return ""
}

// doctorManager copies one manager into the document, normalizing the root so that
// every entry names a directory and nothing has to guess what an empty one meant.
func doctorManager(m *doctor.Manager) DoctorManager {
	return DoctorManager{
		ID:            string(m.ID),
		Version:       m.Version,
		VersionSource: m.VersionSource,
		Root:          doctorRoot(m.Root),
		Evidence:      slices.Clone(m.Evidence),
		Files:         slices.Clone(m.Files),
	}
}

// doctorResult copies one result into the document. The manager index is filled in by
// the caller, which is the only one that knows the order the managers ended up in.
func doctorResult(res *doctor.Result) DoctorResult {
	out := DoctorResult{
		Manager: managerID(res.Manager),
		Status:  string(res.Status),
		Level:   res.Level,
		File:    res.File,
		Line:    res.Line,
		Current: res.Current,
		Want:    res.Want,
		Detail:  res.Detail,
		Fixed:   res.Fixed,
		Edit:    res.Edit,
		manager: -1,
	}
	if r := res.Rule; r != nil {
		out.Rule, out.Name, out.Docs, out.Verified = r.ID, r.Name, r.Docs, r.Verified
	}
	return out
}

// managerID is the id of a manager a result names, empty for the result of a
// scorecard that was assembled without one.
func managerID(m *doctor.Manager) string {
	if m == nil {
		return ""
	}
	return string(m.ID)
}

// doctorRoot is a directory as the document reports it: the dot for the repository
// itself, whether the scorecard said "." or said nothing.
func doctorRoot(dir string) string {
	if dir == "" {
		return "."
	}
	return dir
}

// doctorStatusCounts is the statuses object with every key present at zero, so that a
// reader never has to tell a missing key from a count of none.
func doctorStatusCounts() map[string]int {
	out := make(map[string]int, len(doctorSummaryOrder))
	for _, status := range doctorSummaryOrder {
		out[string(status)] = 0
	}
	return out
}

// doctorStatusRank orders the statuses for the renderings: the three problems first,
// worst first, then what is already set, then what does not apply. A status this
// package does not know sorts last, where it cannot hide a problem.
func doctorStatusRank(status string) int {
	switch doctor.Status(status) {
	case doctor.StatusWrong:
		return 0
	case doctor.StatusMissing:
		return 1
	case doctor.StatusUnreadable:
		return 2
	case doctor.StatusSet:
		return 3
	case doctor.StatusAdvice:
		return 4
	case doctor.StatusNotApplicable:
		return 5
	}
	return 6
}

// doctorStatusColor is the color of a status word. A problem takes the color of its
// level, which is the one the report already paints findings with, so that a block
// rule reads as red wherever it appears; what is set is green and what does not apply
// is dim, because neither is something to look at.
func doctorStatusColor(res *DoctorResult) string {
	switch doctor.Status(res.Status) {
	case doctor.StatusSet:
		return ansiGreen
	case doctor.StatusAdvice, doctor.StatusNotApplicable:
		return ansiDim
	}
	return levelColor(res.Level)
}

// doctorManagerTitle names a manager and its version, which is the version every rule
// of the block was judged against.
func doctorManagerTitle(m *DoctorManager) string {
	if m.Version == "" {
		return m.ID
	}
	return m.ID + " " + m.Version
}

// doctorManagerOrigin describes where the version came from and, when the manager is
// not the repository root, which directory it manages. A version nobody could
// determine is said so rather than left out, because it is the reason every rule with
// a Since is reported as not applicable.
func doctorManagerOrigin(m *DoctorManager) string {
	var parts []string
	switch {
	case m.Version == "" && doctor.ManagerID(m.ID).Versioned():
		// Only for a manager that has a version to pin. Dependabot, Renovate and
		// the workflow files are read by a service rather than by something the
		// repository installs, so "version not detected" would be reporting the
		// absence of something that does not exist.
		parts = append(parts, "version not detected")
	case m.VersionSource != "":
		parts = append(parts, "version from "+m.VersionSource)
	}
	if m.Root != "." {
		parts = append(parts, m.Root)
	}
	return strings.Join(parts, ", ")
}

// doctorLocation is the file and, when the reader could point at one, the line, in
// the spelling the report's own location column uses.
func doctorLocation(res *DoctorResult) string {
	if res.File == "" {
		return ""
	}
	return markdownLocation(&model.Location{Path: res.File, Line: res.Line})
}

// doctorDetail is the sentence under a rule line. A rule that judged a value has one
// already; a setting that is simply absent has none, and there the useful sentence is
// what to write instead.
func doctorDetail(res *DoctorResult) string {
	if res.Detail != "" {
		return res.Detail
	}
	if res.Want != "" && doctor.Status(res.Status).Problem() {
		return "want " + res.Want
	}
	return ""
}

// doctorSummaryCounts is the counts sentence of the summary line, in the order
// doctorSummaryOrder names.
func doctorSummaryCounts(s DoctorSummary) string {
	parts := make([]string, 0, len(doctorSummaryOrder))
	for _, status := range doctorSummaryOrder {
		parts = append(parts, fmt.Sprintf("%d %s", s.Statuses[string(status)], status))
	}
	return strings.Join(parts, ", ") + "."
}

// doctorSummaryExit is the exit code sentence, written by the report's own summary so
// that the two commands say it in one voice.
func doctorSummaryExit(s DoctorSummary) string {
	return summaryExit(Summary{ExitCode: s.ExitCode, ExitMeaning: s.ExitMeaning})
}

// doctorHasResults reports whether any result belongs to a manager.
func doctorHasResults(d *Doctor, index int) bool {
	for i := range d.Results {
		if d.Results[i].manager == index {
			return true
		}
	}
	return false
}
