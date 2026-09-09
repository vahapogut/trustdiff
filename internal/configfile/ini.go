package configfile

import (
	"fmt"
	"strconv"
	"strings"
)

// Each format's file registers its codec here rather than from one list, so a
// format is added by adding a file and nothing else has to be edited.
func init() { Register(iniCodec{}) }

// iniCodec reads the "key = value" files npm and pip are configured through. The
// two are the same shape with one difference that matters here: a pip.conf groups
// its keys under [global] and [install] headers and an .npmrc has none at all, so
// a one segment Key is a key of the file itself and a two segment Key is a
// section and a key inside it.
//
// The comment rule is npm's own: a line whose first non blank character is ";" or
// "#" is a comment, and nothing else is. npm's reader does not strip a "#" that
// follows a value, and neither does this one, because a hash in a registry path
// would otherwise be read as the start of a comment and half of somebody's URL
// would disappear on the next write.
type iniCodec struct{}

// Format is the format this codec handles.
func (iniCodec) Format() Format { return FormatINI }

// iniEntry is one assignment the scanner placed, with enough of the line kept to
// rewrite only the value and leave the key's own spacing alone.
type iniEntry struct {
	// section is the [header] the entry sits under, empty at the top of the file.
	section string
	// name is the key with npm's "[]" list marker taken off.
	name string
	// list is true when the line spelled the key "name[]", which is how npm writes
	// one item of an array.
	list bool
	// line is the 1-based line the assignment is on, and endLine the last line its
	// value occupies, which is the same line unless indented lines under it carry
	// more of the value.
	line, endLine int
	// more are the continuation lines under the assignment, trimmed, in file order.
	more []string
	// sep is everything between the end of the key and the start of the value,
	// " = " or "=", so a line inserted beside this one is spelled the same way.
	sep string
	// valueAt is the byte offset in the line where the value starts.
	valueAt int
	// raw is the value as written, quotes and all.
	raw string
}

// iniHeader is one [section] line, kept so an insertion knows where a section
// begins and where the one after it takes over.
type iniHeader struct {
	name string
	line int
}

// iniFound is what the scanner concluded about one key: the value a reader of the
// file sees, and the entries that spell it, which Set needs to know which lines it
// may replace.
type iniFound struct {
	value   Value
	entries []iniEntry
}

// Get locates a key. A key with more than two segments is an error rather than a
// miss, because an ini file has no third level and a rule that asks for one is
// wrong about the file, not about the project.
func (iniCodec) Get(doc *Doc, key Key) (Value, error) {
	found, err := iniFind(doc, key)
	if err != nil {
		return Value{}, err
	}
	return found.value, nil
}

// Set replaces the value where it sits, or adds the key to the section it belongs
// to.
func (iniCodec) Set(doc *Doc, key Key, want Literal) (Edit, bool, error) {
	found, err := iniFind(doc, key)
	if err != nil {
		return Edit{}, false, err
	}
	if v := &found.value; v.Found() {
		if holds(v, want) {
			return Edit{}, false, nil
		}
		if !v.Editable {
			return Edit{}, false, NotEditable(key, v.Line, v.Reason)
		}
		return iniReplace(doc, key, &found, want), true, nil
	}
	return iniInsert(doc, key, want), true, nil
}

// iniPlace splits a key into the section it names and the key inside it.
func iniPlace(key Key) (section, name string, ok bool) {
	switch len(key) {
	case 1:
		return "", key[0], true
	case 2:
		return key[0], key[1], true
	default:
		return "", "", false
	}
}

// iniFind scans the whole file and builds the value of one key. The file is
// scanned rather than indexed because these files are tens of lines long and a
// second pass costs nothing next to being wrong about which line a key is on.
func iniFind(doc *Doc, key Key) (iniFound, error) {
	section, name, ok := iniPlace(key)
	if !ok {
		return iniFound{}, fmt.Errorf("%s: %s names %d levels, and an ini file has at most a section and a key inside it", doc.Path, key, len(key))
	}
	entries, _ := iniScan(doc)
	var matched []iniEntry
	for _, e := range entries {
		if e.section == section && e.name == name {
			matched = append(matched, e)
		}
	}
	return iniFound{value: iniValue(doc, key, matched), entries: iniMatched(matched)}, nil
}

// iniMatched narrows the matches to the ones an edit may touch: the "name[]" lines
// when the key was written as a list, and otherwise the last plain assignment,
// which is the one a reader of the file ends up with because a later assignment
// wins over an earlier one.
func iniMatched(matched []iniEntry) []iniEntry {
	var list []iniEntry
	for _, e := range matched {
		if e.list {
			list = append(list, e)
		}
	}
	if len(list) > 0 {
		return list
	}
	if len(matched) == 0 {
		return nil
	}
	return matched[len(matched)-1:]
}

// iniValue builds the Value of the entries that spell one key.
func iniValue(doc *Doc, key Key, matched []iniEntry) Value {
	entries := iniMatched(matched)
	if len(entries) == 0 {
		return Value{Key: key}
	}
	if entries[0].list {
		return iniListValue(doc, key, entries)
	}
	e := entries[0]
	text, raw := iniUnquote(e.raw), e.raw
	if len(e.more) > 0 {
		// pip joins a value continued on the lines under it with newlines, so that is
		// the value a reader of the file gets and the value a rule has to be shown.
		text = strings.Join(append([]string{text}, e.more...), "\n")
		raw = strings.Join(append([]string{e.raw}, e.more...), "\n")
	}
	v := Value{Key: key, Text: text, Raw: raw, Line: e.line, EndLine: e.endLine, Editable: true}
	v.Kind = iniKind(v.Text, e.raw)
	iniRefuseEnv(&v, doc, raw)
	return v
}

// iniListValue builds the Value of a "name[]" list. The lines have to be
// consecutive for an edit to be planned, because replacing a range that has
// somebody else's key in the middle of it would delete that key.
func iniListValue(doc *Doc, key Key, entries []iniEntry) Value {
	items := make([]string, 0, len(entries))
	raws := make([]string, 0, len(entries))
	for _, e := range entries {
		items = append(items, iniUnquote(e.raw))
		raws = append(raws, e.raw)
	}
	first, last := entries[0], entries[len(entries)-1]
	v := Value{
		Key: key, Kind: KindList, Items: items,
		// A list has no single run of bytes in the file, so Raw is the items as the
		// file wrote them, in file order, which is what a message has to show.
		Raw:  strings.Join(raws, ", "),
		Line: first.line, EndLine: last.endLine, Editable: true,
	}
	if last.line-first.line != len(entries)-1 {
		v.Editable = false
		v.Reason = fmt.Sprintf("the %s[] entries are spread over lines %d to %d with other lines between them", first.name, first.line, last.line)
		return v
	}
	for _, e := range entries {
		iniRefuseEnv(&v, doc, e.raw)
	}
	return v
}

// iniRefuseEnv marks a value that interpolates an environment variable. npm
// replaces ${TOKEN} in an .npmrc when it reads the file, so the text on disk is
// deliberately not the value: writing the resolved value back would bake a secret
// into the repository, and writing anything else would drop the interpolation the
// person asked for.
func iniRefuseEnv(v *Value, doc *Doc, raw string) {
	start := strings.Index(raw, "${")
	if start < 0 {
		return
	}
	name := raw[start:]
	if end := strings.IndexByte(name, '}'); end >= 0 {
		name = name[:end+1]
	}
	v.Editable = false
	v.Reason = fmt.Sprintf("the value interpolates the environment variable %s, which a rewrite would drop: change it by hand in %s", name, doc.Path)
}

// iniKind reads the shape of an unquoted value. A value the file quoted is a
// string whatever it spells, because somebody quoting "true" meant the word.
func iniKind(text, raw string) Kind {
	if iniQuoted(raw) {
		return KindString
	}
	switch text {
	case "true", "false":
		return KindBool
	}
	if _, err := strconv.ParseInt(text, 10, 64); err == nil {
		return KindInt
	}
	return KindString
}

// iniQuoted reports whether the value on the line was written in quotes.
func iniQuoted(raw string) bool {
	return len(raw) >= 2 && (raw[0] == '"' || raw[0] == '\'') && raw[len(raw)-1] == raw[0]
}

// iniUnquote takes the quotes off a quoted value. Escapes are left as they are:
// npm's own reader only unquotes, and inventing an escape rule here would change
// values that no reader of the file ever changed.
func iniUnquote(raw string) string {
	if iniQuoted(raw) {
		return raw[1 : len(raw)-1]
	}
	return raw
}

// iniScan walks the file once and returns every assignment and every section
// header, in file order.
func iniScan(doc *Doc) ([]iniEntry, []iniHeader) {
	var (
		entries []iniEntry
		headers []iniHeader
		section string
	)
	for n := 1; n <= doc.NumLines(); n++ {
		line := doc.Line(n)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if last := len(entries) - 1; last >= 0 && iniContinues(doc, &entries[last], line, n) {
			// The line carries more of the value above it. It is not a key of its own,
			// whatever a query string in a url on it looks like, and it is not a line an
			// edit to that key may leave behind.
			entries[last].more = append(entries[last].more, trimmed)
			entries[last].endLine = n
			continue
		}
		if name, ok := iniSectionName(trimmed); ok {
			section = name
			headers = append(headers, iniHeader{name: name, line: n})
			continue
		}
		if e, ok := iniAssignment(line, n); ok {
			e.section = section
			entries = append(entries, e)
		}
	}
	return entries, headers
}

// iniContinues reports whether a line holds more of the value the assignment above
// it started. The rule is the one Python's configparser reads a pip.conf with: a
// line indented past the key it follows belongs to that key's value, which is how
// a pip.conf lists a second index url.
//
// It is asked only of an assignment inside a section, because pip.conf is the file
// here that has them. npm's own reader knows no continuations at all, so an
// indented line of an .npmrc is a key npm reads and a key this codec has to leave
// readable.
func iniContinues(doc *Doc, prev *iniEntry, line string, n int) bool {
	if prev.section == "" || prev.endLine != n-1 {
		return false
	}
	indent := Indent(line)
	return indent != "" && len(indent) > len(Indent(doc.Line(prev.line)))
}

// iniSectionName reads a "[name]" header off an already trimmed line.
func iniSectionName(trimmed string) (string, bool) {
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return "", false
	}
	return strings.TrimSpace(trimmed[1 : len(trimmed)-1]), true
}

// iniAssignment reads one "key = value" line. A line without an "=" is skipped
// rather than read as npm's bare "key" shorthand for true, because a file this
// tool cannot spell back the same way is a file it should not edit.
func iniAssignment(line string, n int) (iniEntry, bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return iniEntry{}, false
	}
	head := line[:eq]
	name := strings.TrimSpace(head)
	if name == "" {
		return iniEntry{}, false
	}
	e := iniEntry{line: n, endLine: n}
	if strings.HasSuffix(name, "[]") {
		e.list = true
		name = strings.TrimSuffix(name, "[]")
	}
	e.name = name
	valueAt := eq + 1
	for valueAt < len(line) && (line[valueAt] == ' ' || line[valueAt] == '\t') {
		valueAt++
	}
	e.valueAt = valueAt
	e.sep = line[len(strings.TrimRight(head, " \t")):valueAt]
	e.raw = strings.TrimRight(line[valueAt:], " \t")
	return e, true
}

// iniReplace plans the edit that puts a new value where the old one is.
func iniReplace(doc *Doc, key Key, found *iniFound, want Literal) Edit {
	first := found.entries[0]
	last := found.entries[len(found.entries)-1]
	line := doc.Line(first.line)
	indent := Indent(line)
	var lines []string
	switch {
	case want.Kind == KindList:
		lines = iniListLines(indent, first.name, first.sep, want.Items)
	case len(found.entries) == 1 && !first.list:
		// Only the bytes after the separator change, so the key, its indentation and
		// the spaces the person put around the "=" all stay exactly as they were. The
		// lines a continued value runs on go with it, because a line left behind would
		// still be read as part of the value that is no longer there.
		lines = []string{line[:first.valueAt] + iniSpell(want)}
	default:
		lines = []string{indent + first.name + first.sep + iniSpell(want)}
	}
	return Edit{Start: first.line, End: last.endLine, Lines: lines, Description: describe(key, want, false)}
}

// iniInsert plans the edit that adds a key the file does not state. A key with no
// section goes above the first header, because a key written after one would
// belong to that section instead of to the file.
func iniInsert(doc *Doc, key Key, want Literal) Edit {
	section, name, _ := iniPlace(key)
	entries, headers := iniScan(doc)
	indent, sep := iniStyle(doc, entries, section)
	lines := iniLines(indent, name, sep, want)

	at, header := iniInsertAt(doc, entries, headers, section)
	if header {
		// The section is not in the file, so it is written at the end with a blank
		// line above it, which is how every one of these files separates two blocks.
		head := []string{"[" + section + "]"}
		if doc.NumLines() > 0 && strings.TrimSpace(doc.Line(doc.NumLines())) != "" {
			head = append([]string{""}, head...)
		}
		lines = append(head, lines...)
	}
	return Edit{Start: at, End: at - 1, Lines: lines, Description: describe(key, want, true)}
}

// iniLines spells a literal as the lines that state it, which is one line for a
// scalar and one "name[]=" line per item for a list.
func iniLines(indent, name, sep string, want Literal) []string {
	if want.Kind == KindList {
		return iniListLines(indent, name, sep, want.Items)
	}
	return []string{indent + name + sep + iniSpell(want)}
}

// iniListLines writes npm's repeated "name[]=" spelling of a list.
func iniListLines(indent, name, sep string, items []string) []string {
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, indent+name+"[]"+sep+iniSpell(String(item)))
	}
	return lines
}

// iniStyle picks the separator and the indentation an inserted line should use:
// the one the section it joins already uses, or the one the rest of the file uses,
// so a pip.conf that writes "key = value" keeps its spaces and an .npmrc that
// writes "key=value" keeps none.
func iniStyle(doc *Doc, entries []iniEntry, section string) (indent, sep string) {
	for _, e := range entries {
		if e.section == section {
			return Indent(doc.Line(e.line)), e.sep
		}
	}
	if len(entries) > 0 {
		return Indent(doc.Line(entries[0].line)), entries[0].sep
	}
	return "", "="
}

// iniInsertAt returns the 1-based line an inserted key goes before, and whether
// its section header has to be written first.
func iniInsertAt(doc *Doc, entries []iniEntry, headers []iniHeader, section string) (at int, header bool) {
	end := doc.NumLines() + 1
	if section == "" {
		// A key with no section joins the ones already above the first header, and
		// when there are none it goes above the comments that introduce that header,
		// because those comments belong to the section and not to this key.
		for i := len(entries) - 1; i >= 0; i-- {
			if entries[i].section == "" {
				return entries[i].line + 1, false
			}
		}
		if len(headers) == 0 {
			return end, false
		}
		at = headers[0].line
		for at > 1 && iniIntroduces(doc.Line(at-1)) {
			at--
		}
		return at, false
	}
	for i, h := range headers {
		if h.name != section {
			continue
		}
		last := doc.NumLines()
		if i+1 < len(headers) {
			last = headers[i+1].line - 1
		}
		// A blank line at the end of a section separates it from the next one, so
		// the key goes above it and the file keeps its shape.
		for last > h.line && strings.TrimSpace(doc.Line(last)) == "" {
			last--
		}
		return last + 1, false
	}
	return end, true
}

// iniIntroduces reports whether a line is a comment or a blank line, the two kinds
// of line that sit between one block of a file and the next.
func iniIntroduces(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#")
}

// iniSpell writes a scalar the way an ini file spells it, which is without quotes:
// every example in npm's and pip's own documentation is unquoted, and a quoted
// value would read differently to the tools that already read the file. A value
// whose edges a reader would trim away is the one case that has to be quoted.
func iniSpell(want Literal) string {
	switch want.Kind {
	case KindBool:
		return strconv.FormatBool(want.Bool)
	case KindInt:
		return want.Text
	default:
		s := want.Text
		if s == "" || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\r\n") {
			return strconv.Quote(s)
		}
		return s
	}
}

// holds reports whether the value a file already states is exactly what a rule
// wants, by meaning rather than by spelling: a list is the same list when its
// items are in the same order, and a number is the same number however it is
// written. It is the question every codec's Set asks before it plans anything,
// because a fixer that rewrites a file which is already correct is a fixer nobody
// can run twice. It lives beside the first codec rather than in a file of its own
// because one file per format is this package's whole layout.
func holds(v *Value, want Literal) bool {
	switch want.Kind {
	case KindBool:
		got, err := strconv.ParseBool(v.Text)
		return v.Kind == KindBool && err == nil && got == want.Bool
	case KindInt:
		if v.Kind != KindInt {
			return false
		}
		got, err := strconv.ParseInt(strings.ReplaceAll(v.Text, "_", ""), 10, 64)
		if err != nil {
			return false
		}
		wanted, err := strconv.ParseInt(want.Text, 10, 64)
		return err == nil && got == wanted
	case KindString:
		return v.Kind == KindString && v.Text == want.Text
	case KindList:
		if v.Kind != KindList || len(v.Items) != len(want.Items) {
			return false
		}
		for i := range v.Items {
			if v.Items[i] != want.Items[i] {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// describe is the sentence a preview prints beside an edit. It names the key the
// way the format's own documentation spells it and the value the way the file will
// read afterwards, because a preview a reader cannot check against the file is not
// a preview.
func describe(key Key, want Literal, adding bool) string {
	text := want.Text
	switch want.Kind {
	case KindBool:
		text = strconv.FormatBool(want.Bool)
	case KindList:
		text = "[" + strings.Join(want.Items, ", ") + "]"
	}
	if adding {
		return "add " + key.String() + ", set to " + text
	}
	return "set " + key.String() + " to " + text
}
