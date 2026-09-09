package configfile

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

func init() { Register(tomlCodec{}) }

// tomlCodec reads bunfig.toml, pyproject.toml, uv.toml, poetry.toml and
// .cargo/config.toml.
//
// The work is split in two because neither half can do it alone. The decoder
// answers what the file defines and what each key holds, which is the only way to
// be right about a format that spells the same table three ways, but it reports no
// positions at all, so it cannot say which line to edit. The scanner in this file
// answers where, by walking the text and keeping the table it is inside, and it
// says nothing about types. A key is found when both halves agree.
//
// The three spellings the scanner has to fold together are the reason it exists:
// {"install", "minimumReleaseAge"} is "[install]" and then the key on a later
// line, "install.minimumReleaseAge = ..." at the top of the file, and
// "install = { minimumReleaseAge = ... }" on one line. All three define the same
// key and a rule should not have to know which one a project chose.
type tomlCodec struct{}

// Format is the format this codec handles.
func (tomlCodec) Format() Format { return FormatTOML }

// tomlAssign is one "key = value" the scanner placed, with the byte range of the
// value so an edit can replace it without touching the key or a trailing comment.
type tomlAssign struct {
	// path is the full key, the enclosing table's own path included.
	path []string
	// keyEnd and start are the offsets the key ends at and the value begins at, so
	// the text between them is the "=" and the spaces the file put around it.
	keyEnd, start int
	// end is the offset just past the value.
	end int
	// root is true when the assignment is above every table header, which is the
	// only place a key with no table of its own can be written.
	root bool
	// why names the construct that stops an edit, empty when the value may be
	// replaced.
	why string
}

// tomlHeader is one "[table]" line. last is the file's last line that belongs to
// the table, which is where a key added to it goes.
type tomlHeader struct {
	path  []string
	line  int
	last  int
	array bool
}

// tomlFound is the answer to one lookup: the value the decoder read, the place the
// scanner put it, and the scanned text, so Set does not walk the file twice.
type tomlFound struct {
	value Value
	at    tomlAssign
	src   *tomlSourceText
	// placed is false when the decoder defines the key and the scanner could not
	// find the line it is written on, which is a file this codec must not edit.
	placed bool
}

// Get locates a key. A file the decoder rejects is an error rather than a miss,
// because a project whose bunfig.toml does not parse has a problem worth naming.
func (tomlCodec) Get(doc *Doc, key Key) (Value, error) {
	found, err := tomlLookup(doc, key)
	if err != nil {
		return Value{}, err
	}
	return found.value, nil
}

// Set replaces the value where it sits, or adds the key to its table.
func (tomlCodec) Set(doc *Doc, key Key, want Literal) (Edit, bool, error) {
	found, err := tomlLookup(doc, key)
	if err != nil {
		return Edit{}, false, err
	}
	v := &found.value
	if !v.Found() {
		return tomlInsert(doc, found.src, key, want)
	}
	if holds(v, want) {
		return Edit{}, false, nil
	}
	if !found.placed {
		return Edit{}, false, fmt.Errorf("%s: %s: %w: the file defines it in a shape this reader cannot point at a line for", doc.Path, key, ErrNotEditable)
	}
	if !v.Editable {
		return Edit{}, false, NotEditable(key, v.Line, v.Reason)
	}
	line := doc.Line(v.Line)
	from, to := found.src.column(found.at.start), found.src.column(found.at.end)
	// Only the bytes of the value are replaced, so a trailing comment on the same
	// line, and the spaces somebody aligned the "=" with, both survive.
	return Edit{
		Start: v.Line, End: v.Line,
		Lines:       []string{line[:from] + tomlSpell(want) + line[to:]},
		Description: describe(key, want, false),
	}, true, nil
}

// tomlSourceText is the file as one string with the assignments and headers the
// scanner placed, and the line index that turns an offset back into a line.
type tomlSourceText struct {
	text    string
	starts  []int
	assigns []tomlAssign
	headers []tomlHeader
}

// line returns the 1-based line an offset falls on.
func (s *tomlSourceText) line(off int) int {
	return sort.Search(len(s.starts), func(k int) bool { return s.starts[k] > off })
}

// column returns the byte offset within its own line, which is where an edit cuts
// the line to put a new value in.
func (s *tomlSourceText) column(off int) int {
	n := s.line(off)
	if n < 1 {
		return 0
	}
	return off - s.starts[n-1]
}

// tomlSource joins the document's lines and scans them. The join is on "\n"
// whatever the file's own endings are, so an offset in this text is a column in
// the document's line and a carriage return never shifts anything.
func tomlSource(doc *Doc) *tomlSourceText {
	text := strings.Join(doc.Lines(), "\n")
	s := &tomlSourceText{text: text, starts: make([]int, 1, strings.Count(text, "\n")+1)}
	for i := range len(text) {
		if text[i] == '\n' {
			s.starts = append(s.starts, i+1)
		}
	}
	sc := &tomlScan{src: s}
	sc.run()
	// Every table owns the lines from its header down to the header after it, which
	// is where a key added to that table has to go.
	for i := range s.headers {
		s.headers[i].last = doc.NumLines()
		if i+1 < len(s.headers) {
			s.headers[i].last = s.headers[i+1].line - 1
		}
	}
	return s
}

// find returns the assignment that states a key, if the scanner placed one.
func (s *tomlSourceText) find(key Key) (tomlAssign, bool) {
	for _, a := range s.assigns {
		if Key(a.path).Equal(key) {
			return a, true
		}
	}
	return tomlAssign{}, false
}

// tomlLookup asks the decoder what the file defines and the scanner where it is.
func tomlLookup(doc *Doc, key Key) (tomlFound, error) {
	if len(key) == 0 {
		return tomlFound{}, fmt.Errorf("%s: a toml key names no levels, so there is nothing to look up", doc.Path)
	}
	src := tomlSource(doc)
	var top map[string]any
	md, err := toml.Decode(src.text, &top)
	if err != nil {
		return tomlFound{}, fmt.Errorf("%s: %w", doc.Path, err)
	}
	// The metadata is what says the file states the key. The decoded map is only
	// asked what it holds, because a key set to a value that happens to be a Go zero
	// value is still a key the file states.
	if !md.IsDefined(key...) {
		return tomlFound{value: Value{Key: key}, src: src}, nil
	}
	v := Value{Key: key, Kind: KindOther}
	if got, ok := tomlWalk(top, key); ok {
		v = tomlValue(key, got)
	}
	at, placed := src.find(key)
	if !placed {
		v.Editable = false
		v.Reason = "the file defines it in a shape this reader cannot point at a line for, an array of tables most likely"
		return tomlFound{value: v, src: src}, nil
	}
	v.Raw = src.text[at.start:at.end]
	v.Line, v.EndLine = src.line(at.start), src.line(max(at.start, at.end-1))
	v.Editable = at.why == ""
	if !v.Editable {
		v.Reason = at.why + ", which cannot be rewritten one line at a time: change it by hand in " + doc.Path
	}
	return tomlFound{value: v, at: at, src: src, placed: true}, nil
}

// tomlWalk follows a key through the decoded document. A key whose parent is not a
// table is not defined, whatever the parent holds.
func tomlWalk(top map[string]any, key Key) (any, bool) {
	var cur any = top
	for _, part := range key {
		table, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = table[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// tomlValue turns a decoded Go value into the shape a rule reads. A number that is
// not an integer, a date and anything else the decoder produced are KindOther: a
// rule can print them and will not compare them.
func tomlValue(key Key, got any) Value {
	v := Value{Key: key, Kind: KindOther}
	switch x := got.(type) {
	case bool:
		v.Kind, v.Text = KindBool, strconv.FormatBool(x)
	case int64:
		v.Kind, v.Text = KindInt, strconv.FormatInt(x, 10)
	case string:
		v.Kind, v.Text = KindString, x
	case map[string]any:
		v.Kind = KindMap
	case []any:
		items, ok := tomlItems(x)
		if !ok {
			return v
		}
		v.Kind, v.Items = KindList, items
	default:
		v.Text = fmt.Sprint(got)
	}
	return v
}

// tomlItems reads an array of scalars. An array holding a table or another array
// is not a list a rule can compare, so it stays KindOther.
func tomlItems(arr []any) ([]string, bool) {
	items := make([]string, 0, len(arr))
	for _, el := range arr {
		switch x := el.(type) {
		case string:
			items = append(items, x)
		case int64:
			items = append(items, strconv.FormatInt(x, 10))
		case bool:
			items = append(items, strconv.FormatBool(x))
		default:
			return nil, false
		}
	}
	return items, true
}

// tomlInsert plans the edit that adds a key the file does not state.
func tomlInsert(doc *Doc, src *tomlSourceText, key Key, want Literal) (Edit, bool, error) {
	name := key[len(key)-1]
	table := key[:len(key)-1]
	indent, sep := tomlStyle(doc, src, table)
	line := indent + tomlName(name) + sep + tomlSpell(want)

	if len(table) == 0 {
		// A key with no table joins the ones already above the first header, because a
		// key written after a header would belong to that table instead of to the
		// file. With none to join it goes above the comments that introduce the first
		// header, which belong to that table and not to this key.
		at := doc.NumLines() + 1
		if last, ok := src.lastRoot(); ok {
			at = src.line(last.start) + 1
		} else if len(src.headers) > 0 {
			at = src.headers[0].line
			for at > 1 && tomlIntroduces(doc.Line(at-1)) {
				at--
			}
		}
		return Edit{Start: at, End: at - 1, Lines: []string{line}, Description: describe(key, want, true)}, true, nil
	}
	if h, ok := src.header(table); ok {
		last := h.last
		for last > h.line && strings.TrimSpace(doc.Line(last)) == "" {
			last--
		}
		return Edit{Start: last + 1, End: last, Lines: []string{line}, Description: describe(key, want, true)}, true, nil
	}
	if a, ok := src.within(table); ok {
		// The table is defined without a header of its own, inline or through a dotted
		// key. Writing "[install]" underneath would define it twice and the file would
		// stop parsing, so the codec says so instead of breaking it.
		return Edit{}, false, fmt.Errorf("%s: %s: %w: %s is written inline at line %d, so add %s to it by hand",
			doc.Path, key, ErrNotEditable, table, src.line(a.start), name)
	}
	// The table is not in the file at all, so it is written at the end with a blank
	// line above it, which is how every one of these files separates two tables.
	lines := []string{"[" + tomlPath(table) + "]", line}
	if doc.NumLines() > 0 && strings.TrimSpace(doc.Line(doc.NumLines())) != "" {
		lines = append([]string{""}, lines...)
	}
	at := doc.NumLines() + 1
	return Edit{Start: at, End: at - 1, Lines: lines, Description: describe(key, want, true)}, true, nil
}

// header returns the "[table]" line of a path. An array of tables is not one: its
// keys belong to an element, not to the path itself.
func (s *tomlSourceText) header(table Key) (tomlHeader, bool) {
	for _, h := range s.headers {
		if !h.array && Key(h.path).Equal(table) {
			return h, true
		}
	}
	return tomlHeader{}, false
}

// lastRoot returns the last assignment written above every table header, which is
// where another key of the file itself belongs.
func (s *tomlSourceText) lastRoot() (tomlAssign, bool) {
	for i := len(s.assigns) - 1; i >= 0; i-- {
		if s.assigns[i].root {
			return s.assigns[i], true
		}
	}
	return tomlAssign{}, false
}

// within returns an assignment that defines something under a table path, which is
// how a table that has no header of its own still exists.
func (s *tomlSourceText) within(table Key) (tomlAssign, bool) {
	for _, a := range s.assigns {
		if len(a.path) > len(table) && Key(a.path[:len(table)]).Equal(table) {
			return a, true
		}
		if Key(a.path).Equal(table) {
			return a, true
		}
	}
	return tomlAssign{}, false
}

// tomlStyle picks the indentation and the "=" spacing an inserted line should use:
// the table's own, or the file's, or the " = " every toml formatter writes.
func tomlStyle(doc *Doc, src *tomlSourceText, table Key) (indent, sep string) {
	pick := func(a tomlAssign) (string, string) {
		return Indent(doc.Line(src.line(a.keyEnd))), src.text[a.keyEnd:a.start]
	}
	for _, a := range src.assigns {
		if len(a.path) == len(table)+1 && Key(a.path[:len(table)]).Equal(table) {
			return pick(a)
		}
	}
	if len(src.assigns) > 0 {
		return pick(src.assigns[0])
	}
	return "", " = "
}

// tomlIntroduces reports whether a line is blank or a comment, the two kinds of
// line that sit between one block of a file and the next.
func tomlIntroduces(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

// tomlPath spells a table path the way a header does.
func tomlPath(table Key) string {
	parts := make([]string, 0, len(table))
	for _, part := range table {
		parts = append(parts, tomlName(part))
	}
	return strings.Join(parts, ".")
}

// tomlName spells one key. A name that is not bare has to be quoted, which is what
// a key like "tool.uv" written as one segment needs.
func tomlName(name string) string {
	if name == "" {
		return `""`
	}
	for i := range len(name) {
		if !tomlBare(name[i]) {
			return strconv.Quote(name)
		}
	}
	return name
}

// tomlSpell writes a literal the way toml spells it.
func tomlSpell(want Literal) string {
	switch want.Kind {
	case KindBool:
		return strconv.FormatBool(want.Bool)
	case KindInt:
		return want.Text
	case KindList:
		parts := make([]string, 0, len(want.Items))
		for _, item := range want.Items {
			parts = append(parts, strconv.Quote(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		// Go's quoting and toml's basic strings agree on every escape these files
		// hold, and both leave a printable non-ASCII rune as itself.
		return strconv.Quote(want.Text)
	}
}

// tomlBare reports whether a byte may appear in an unquoted key.
func tomlBare(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// tomlScan walks the text once and records every assignment and every table
// header. It is not a parser: the decoder has already said the file is valid toml,
// so this only has to keep its place, which means knowing where a string, an array,
// an inline table and a comment end.
type tomlScan struct {
	src   *tomlSourceText
	i     int
	table []string
	// keyEnd is where the key keyPath last read ended, before the spaces after it.
	// The text from there to the value is the "=" and the spacing the file chose,
	// which an inserted line copies so it lines up with its the lines around it.
	keyEnd int
}

// run walks the whole file.
func (s *tomlScan) run() {
	for {
		s.trivia()
		if s.i >= len(s.src.text) {
			return
		}
		if s.src.text[s.i] == '[' {
			s.header()
			continue
		}
		keyAt := s.i
		parts, ok := s.keyPath()
		if !ok {
			s.toEOL()
			continue
		}
		keyEnd := s.keyEnd
		s.spaces()
		if s.i >= len(s.src.text) || s.src.text[s.i] != '=' {
			// Not an assignment after all, so the line is stepped over rather than
			// guessed at.
			s.i = keyAt
			s.toEOL()
			continue
		}
		s.i++
		s.spaces()
		s.assign(append(append([]string{}, s.table...), parts...), keyEnd, "")
	}
}

// header reads a "[table]" or "[[array]]" line and makes it the current table.
func (s *tomlScan) header() {
	array := strings.HasPrefix(s.src.text[s.i:], "[[")
	s.i++
	if array {
		s.i++
	}
	s.spaces()
	parts, ok := s.keyPath()
	if !ok {
		s.toEOL()
		return
	}
	s.table = parts
	s.src.headers = append(s.src.headers, tomlHeader{path: parts, line: s.src.line(s.i), array: array})
	s.toEOL()
}

// keyPath reads a bare, quoted or dotted key and leaves the cursor after it.
func (s *tomlScan) keyPath() ([]string, bool) {
	var parts []string
	for {
		s.spaces()
		if s.i >= len(s.src.text) {
			return nil, false
		}
		var part string
		if c := s.src.text[s.i]; c == '"' || c == '\'' {
			text, ok := s.quoted()
			if !ok {
				return nil, false
			}
			part = text
		} else {
			start := s.i
			for s.i < len(s.src.text) && tomlBare(s.src.text[s.i]) {
				s.i++
			}
			if s.i == start {
				return nil, false
			}
			part = s.src.text[start:s.i]
		}
		parts = append(parts, part)
		s.keyEnd = s.i
		s.spaces()
		if s.i < len(s.src.text) && s.src.text[s.i] == '.' {
			s.i++
			continue
		}
		return parts, true
	}
}

// assign records one key and its value. refuse is the reason its enclosing inline
// table already gave, so a key inside a table that spans lines inherits it.
func (s *tomlScan) assign(path []string, keyEnd int, refuse string) {
	start := s.i
	why := s.value(path, refuse)
	end := s.i
	for end > start && (s.src.text[end-1] == ' ' || s.src.text[end-1] == '\t' || s.src.text[end-1] == '\r') {
		end--
	}
	if why == "" && s.src.line(start) != s.src.line(max(start, end-1)) {
		why = "a value that spans lines"
	}
	s.src.assigns = append(s.src.assigns, tomlAssign{
		path: path, keyEnd: keyEnd, start: start, end: end, why: why, root: len(s.table) == 0,
	})
}

// value steps over one value and returns the reason it must not be rewritten,
// empty when it may be. The keys of an inline table are recorded on the way, which
// is what makes install.minimumReleaseAge findable in "install = { ... }".
func (s *tomlScan) value(path []string, refuse string) string {
	text := s.src.text
	if s.i >= len(text) {
		return "a key with no value"
	}
	switch c := text[s.i]; {
	case strings.HasPrefix(text[s.i:], `"""`), strings.HasPrefix(text[s.i:], "'''"):
		s.multiline()
		return "a multi-line string"
	case c == '"' || c == '\'':
		s.quoted()
		return refuse
	case c == '[':
		start := s.i
		s.bracketed()
		if s.src.line(start) != s.src.line(s.i-1) {
			return "an array that spans lines"
		}
		return refuse
	case c == '{':
		return s.inlineTable(path, refuse)
	default:
		// A bare value: a number, a boolean, a date. It ends where the line, a
		// comment or the array or table around it ends.
		for s.i < len(text) && strings.IndexByte("\n#,]}", text[s.i]) < 0 {
			s.i++
		}
		return refuse
	}
}

// inlineTable reads "{ key = value, ... }" and records every key inside it under
// the path of the table itself. A table whose braces are on two different lines is
// refused whole: replacing one line of it would leave the rest behind.
func (s *tomlScan) inlineTable(path []string, refuse string) string {
	text := s.src.text
	start := s.i
	mark := len(s.src.assigns)
	s.i++
	for {
		s.trivia()
		if s.i >= len(text) {
			break
		}
		if text[s.i] == '}' {
			s.i++
			break
		}
		if text[s.i] == ',' {
			s.i++
			continue
		}
		parts, ok := s.keyPath()
		if !ok {
			s.i++
			continue
		}
		keyEnd := s.keyEnd
		s.spaces()
		if s.i < len(text) && text[s.i] == '=' {
			s.i++
		}
		s.spaces()
		s.assign(append(append([]string{}, path...), parts...), keyEnd, refuse)
	}
	if s.src.line(start) == s.src.line(s.i-1) {
		return refuse
	}
	why := "an inline table that spans lines"
	// The keys read inside it are refused for the same reason, because the table
	// they sit in is what makes them unsafe to touch, not the values themselves.
	for j := mark; j < len(s.src.assigns); j++ {
		if s.src.assigns[j].why == "" {
			s.src.assigns[j].why = why
		}
	}
	return why
}

// bracketed steps over an array, and over anything nested inside it, to its
// closing bracket. The nesting counter takes braces too, because an array of
// inline tables closes them in the same run.
func (s *tomlScan) bracketed() {
	text := s.src.text
	depth := 0
	for s.i < len(text) {
		switch c := text[s.i]; {
		case c == '[', c == '{':
			depth++
			s.i++
		case c == ']', c == '}':
			depth--
			s.i++
			if depth <= 0 {
				return
			}
		case c == '#':
			s.toEOL()
		case strings.HasPrefix(text[s.i:], `"""`), strings.HasPrefix(text[s.i:], "'''"):
			s.multiline()
		case c == '"' || c == '\'':
			s.quoted()
		default:
			s.i++
		}
	}
}

// quoted reads one single-line string and returns its text without the quotes. An
// escape is left as written, because the only strings this reader compares are
// table and key names, which no file escapes.
func (s *tomlScan) quoted() (string, bool) {
	text := s.src.text
	quote := text[s.i]
	for j := s.i + 1; j < len(text); j++ {
		switch {
		case text[j] == '\n':
			s.i = j
			return "", false
		case text[j] == '\\' && quote == '"':
			j++
		case text[j] == quote:
			out := text[s.i+1 : j]
			s.i = j + 1
			return out, true
		}
	}
	s.i = len(text)
	return "", false
}

// multiline steps over a """ or ”' string.
func (s *tomlScan) multiline() {
	text := s.src.text
	quote := text[s.i : s.i+3]
	s.i += 3
	for s.i < len(text) {
		switch {
		case quote[0] == '"' && text[s.i] == '\\':
			s.i += 2
		case strings.HasPrefix(text[s.i:], quote):
			s.i += 3
			return
		default:
			s.i++
		}
	}
}

// spaces steps over spaces and tabs, which never end a line.
func (s *tomlScan) spaces() {
	for s.i < len(s.src.text) && (s.src.text[s.i] == ' ' || s.src.text[s.i] == '\t' || s.src.text[s.i] == '\r') {
		s.i++
	}
}

// trivia steps over whitespace, newlines and whole comment lines.
func (s *tomlScan) trivia() {
	for s.i < len(s.src.text) {
		switch s.src.text[s.i] {
		case ' ', '\t', '\r', '\n':
			s.i++
		case '#':
			s.toEOL()
		default:
			return
		}
	}
}

// toEOL leaves the cursor on the next newline, or at the end of the file.
func (s *tomlScan) toEOL() {
	for s.i < len(s.src.text) && s.src.text[s.i] != '\n' {
		s.i++
	}
}
