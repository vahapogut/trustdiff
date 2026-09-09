package configfile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Two codecs, one implementation. JSON with comments differs from JSON only in
// what the reader has to step over, and package.json and deno.jsonc are otherwise
// read and written the same way.
func init() {
	Register(jsonCodec{format: FormatJSON})
	Register(jsonCodec{format: FormatJSONC})
}

// jsonCodec reads package.json, renovate.json, deno.json and deno.jsonc.
//
// encoding/json says where it is through Decoder.InputOffset, which is the whole
// reason it is used here: the offset just past a key and the bytes of the value
// after it give the exact range an edit has to replace, and everything else in the
// file, the order of the keys and the indentation included, is never looked at
// again.
//
// A .jsonc holds comments and trailing commas, which the standard decoder will
// not read. Rather than a second parser, the codec decodes a copy in which every
// comment byte and every trailing comma has been replaced by a space. Nothing is
// removed, so an offset in the copy is the same offset in the real file, and the
// file on disk is what gets edited: a comment nobody asked about is never in the
// way and never moves.
type jsonCodec struct {
	format Format
}

// Format is the format this codec handles.
func (c jsonCodec) Format() Format { return c.format }

// jsonMember is one key of an object, with the range of its value.
type jsonMember struct {
	name string
	// keyEnd is the offset just past the key's closing quote, which is on the key's
	// own line because a JSON string cannot hold a raw newline.
	keyEnd int
	// valAt and valEnd bound the value.
	valAt, valEnd int
}

// jsonBox is one object: where its braces are and what it states, which is what an
// insertion needs to place a new member and give the old last one its comma.
type jsonBox struct {
	open, shut int
	members    []jsonMember
}

// member returns the last entry with a name, because a file that states a key
// twice is read by every JSON parser as the second one.
func (b jsonBox) member(name string) (jsonMember, bool) {
	for i := len(b.members) - 1; i >= 0; i-- {
		if b.members[i].name == name {
			return b.members[i], true
		}
	}
	return jsonMember{}, false
}

// jsonFound is one lookup: the value, where it is, and the deepest object the walk
// reached, which is where a missing key would be added.
type jsonFound struct {
	value Value
	at    jsonMember
	box   jsonBox
	src   *jsonSource
	// depth is how many segments of the key the file has.
	depth int
	// blocked is why the walk could go no further, empty when it only ran out of
	// keys, which is a plain miss.
	blocked string
}

// Get locates a key.
func (c jsonCodec) Get(doc *Doc, key Key) (Value, error) {
	found, err := c.lookup(doc, key)
	if err != nil {
		return Value{}, err
	}
	return found.value, nil
}

// Set replaces the value where it sits, or adds the key to the object it belongs
// to.
func (c jsonCodec) Set(doc *Doc, key Key, want Literal) (Edit, bool, error) {
	found, err := c.lookup(doc, key)
	if err != nil {
		return Edit{}, false, err
	}
	v := &found.value
	if !v.Found() {
		return jsonInsert(doc, &found, key, want)
	}
	if holds(v, want) {
		return Edit{}, false, nil
	}
	if !v.Editable {
		return Edit{}, false, NotEditable(key, v.Line, v.Reason)
	}
	src := found.src
	start, end := src.line(found.at.valAt), src.line(found.at.valEnd)
	from, to := src.column(found.at.valAt), src.column(found.at.valEnd)
	// Everything on the first line before the value and everything on the last line
	// after it stays, which for a value that ran over several lines means the lines
	// between them are the only ones that go.
	return Edit{
		Start: start, End: end,
		Lines:       []string{doc.Line(start)[:from] + jsonSpell(want) + doc.Line(end)[to:]},
		Description: describe(key, want, false),
	}, true, nil
}

// lookup parses the file and walks the key into it.
func (c jsonCodec) lookup(doc *Doc, key Key) (jsonFound, error) {
	if len(key) == 0 {
		return jsonFound{}, fmt.Errorf("%s: a json key names no levels, so there is nothing to look up", doc.Path)
	}
	src := newJSONSource(doc, c.format)
	open, ok := src.top()
	if !ok {
		return jsonFound{}, fmt.Errorf("%s: the top of the file is not an object, so it states no keys to read", doc.Path)
	}
	box, err := src.box(open)
	if err != nil {
		return jsonFound{}, fmt.Errorf("%s: %w", doc.Path, err)
	}
	found := jsonFound{value: Value{Key: key}, box: box, src: src}
	for i, part := range key {
		found.box, found.depth = box, i
		m, ok := box.member(part)
		if !ok {
			return found, nil
		}
		if i == len(key)-1 {
			found.at, found.value = m, src.value(key, m)
			found.depth = len(key)
			return found, nil
		}
		if src.scan[m.valAt] != '{' {
			// A key on the way down holds something other than an object, so the rest
			// of the path is not a path this file has.
			found.blocked = fmt.Sprintf("%s at line %d does not hold an object", key[:i+1], src.line(m.keyEnd))
			return found, nil
		}
		if box, err = src.box(m.valAt); err != nil {
			return jsonFound{}, fmt.Errorf("%s: %w", doc.Path, err)
		}
	}
	return found, nil
}

// jsonSource is the file as one string, the copy the decoder reads, and the index
// that turns an offset back into a line.
type jsonSource struct {
	// path is the file as the caller named it, for the reason a refusal prints.
	path string
	// text is the file's lines joined with "\n", which is what an edit changes.
	text string
	// scan is text with the comments and the trailing commas blanked out, which is
	// what the decoder reads. It is the same length, byte for byte, as text.
	scan string
	// trailing holds the offsets of the trailing commas that were blanked, in order.
	// A .jsonc that already ends a member with one must not be given a second.
	trailing []int
	starts   []int
}

// newJSONSource joins the document's lines and, for a .jsonc, blanks what the
// standard decoder would refuse. The join is on "\n" whatever the file's own
// endings are, so an offset in this text is a column in the document's line and a
// carriage return never shifts anything.
func newJSONSource(doc *Doc, format Format) *jsonSource {
	text := strings.Join(doc.Lines(), "\n")
	s := &jsonSource{path: doc.Path, text: text, scan: text, starts: make([]int, 1, strings.Count(text, "\n")+1)}
	for i := range len(text) {
		if text[i] == '\n' {
			s.starts = append(s.starts, i+1)
		}
	}
	if format == FormatJSONC {
		s.scan, s.trailing = jsonStrip(text)
	}
	return s
}

// line returns the 1-based line an offset falls on.
func (s *jsonSource) line(off int) int {
	return sort.Search(len(s.starts), func(k int) bool { return s.starts[k] > off })
}

// column returns the byte offset within its own line, which is where an edit cuts
// the line to put a new value in.
func (s *jsonSource) column(off int) int {
	n := s.line(off)
	if n < 1 {
		return 0
	}
	return off - s.starts[n-1]
}

// top returns the offset of the document's first byte of content, and whether it
// opens an object.
func (s *jsonSource) top() (int, bool) {
	for i := range len(s.scan) {
		if !jsonSpace(s.scan[i]) {
			return i, s.scan[i] == '{'
		}
	}
	return 0, false
}

// box reads the members of the object that starts at open. The decoder is asked
// for the value as a RawMessage rather than for its meaning, because the length of
// the raw bytes is what says where the value ends.
func (s *jsonSource) box(open int) (jsonBox, error) {
	dec := json.NewDecoder(strings.NewReader(s.scan[open:]))
	if _, err := dec.Token(); err != nil {
		return jsonBox{}, fmt.Errorf("line %d: %w", s.line(open), err)
	}
	box := jsonBox{open: open}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return jsonBox{}, fmt.Errorf("line %d: %w", s.line(open+int(dec.InputOffset())), err)
		}
		name, ok := tok.(string)
		if !ok {
			return jsonBox{}, fmt.Errorf("line %d: an object key that is not a string", s.line(open+int(dec.InputOffset())))
		}
		keyEnd := open + int(dec.InputOffset())
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return jsonBox{}, fmt.Errorf("line %d: %q: %w", s.line(keyEnd), name, err)
		}
		valAt := s.valueStart(keyEnd)
		box.members = append(box.members, jsonMember{
			name:   name,
			keyEnd: keyEnd,
			valAt:  valAt,
			valEnd: valAt + len(strings.TrimRight(string(raw), " \t\r\n")),
		})
	}
	if _, err := dec.Token(); err != nil {
		return jsonBox{}, fmt.Errorf("line %d: %w", s.line(open), err)
	}
	box.shut = open + int(dec.InputOffset()) - 1
	return box, nil
}

// valueStart is the offset of the value that follows a key, which is past the ":"
// and the spaces around it.
func (s *jsonSource) valueStart(after int) int {
	i := after
	for i < len(s.scan) && jsonSpace(s.scan[i]) {
		i++
	}
	if i < len(s.scan) && s.scan[i] == ':' {
		i++
	}
	for i < len(s.scan) && jsonSpace(s.scan[i]) {
		i++
	}
	return i
}

// value builds the Value of one member. The shape is read from the blanked copy,
// where a comment inside an array cannot be mistaken for an item, and Raw is taken
// from the real text, because a message that shows the value should show what is
// actually written there.
func (s *jsonSource) value(key Key, m jsonMember) Value {
	raw := s.scan[m.valAt:m.valEnd]
	v := Value{
		Key: key, Kind: KindOther, Raw: s.text[m.valAt:m.valEnd],
		Line: s.line(m.keyEnd), EndLine: s.line(m.valEnd), Editable: true,
	}
	if s.holdsComment(m.valAt, m.valEnd) {
		// A value is replaced by one line, and a comment written inside an array or an
		// object that runs over several of them would go with the lines it was on. The
		// comment is somebody's note about what is there, so the codec says so and
		// leaves the value alone.
		v.Editable = false
		v.Reason = "the value holds a comment, which rewriting it would delete: change it by hand in " + s.path
	}
	if raw == "" {
		return v
	}
	switch c := raw[0]; {
	case c == '"':
		var text string
		if err := json.Unmarshal([]byte(raw), &text); err == nil {
			v.Kind, v.Text = KindString, text
		}
	case c == '{':
		v.Kind = KindMap
	case c == '[':
		if items, ok := jsonItems(raw); ok {
			v.Kind, v.Items = KindList, items
		}
	case c == 't' || c == 'f':
		v.Kind, v.Text = KindBool, raw
	case c == '-' || c >= '0' && c <= '9':
		v.Text = raw
		if _, err := strconv.ParseInt(raw, 10, 64); err == nil {
			v.Kind = KindInt
		}
	}
	return v
}

// holdsComment reports whether a comment sits inside a byte range. The blanked
// copy is the answer: every byte a comment held is a space there and something
// else in the file. A trailing comma was blanked too and is not a comment, and in
// a .json nothing was blanked at all.
func (s *jsonSource) holdsComment(from, to int) bool {
	for i := from; i < to && i < len(s.scan); i++ {
		if s.scan[i] != s.text[i] && !s.blanked(i) {
			return true
		}
	}
	return false
}

// jsonItems reads an array of scalars. An array holding an object or another array
// is not a list a rule can compare.
func jsonItems(raw string) ([]string, bool) {
	var elements []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &elements); err != nil {
		return nil, false
	}
	items := make([]string, 0, len(elements))
	for _, el := range elements {
		text := string(el)
		switch {
		case strings.HasPrefix(text, `"`):
			var s string
			if err := json.Unmarshal(el, &s); err != nil {
				return nil, false
			}
			items = append(items, s)
		case text == "true", text == "false":
			items = append(items, text)
		case text != "" && (text[0] == '-' || text[0] >= '0' && text[0] <= '9'):
			items = append(items, text)
		default:
			return nil, false
		}
	}
	return items, true
}

// jsonInsert plans the edit that adds a key the file does not state: one line in
// the object it belongs to, indented the way that object indents its own keys, and
// the comma the member that used to be last now needs.
func jsonInsert(doc *Doc, found *jsonFound, key Key, want Literal) (Edit, bool, error) {
	src, box := found.src, found.box
	if found.blocked != "" {
		return Edit{}, false, NotEditable(key, src.line(box.open), found.blocked+": change it by hand in "+doc.Path)
	}
	openLine, shutLine := src.line(box.open), src.line(box.shut)
	last, has := jsonLast(box)
	after, indent := openLine, Indent(doc.Line(openLine))+strings.Repeat(" ", jsonStep(doc, src, box))
	if has {
		after = src.line(last.valEnd)
		indent = Indent(doc.Line(src.line(last.keyEnd)))
	}
	if after >= shutLine {
		// The object's last member and its closing brace share a line, so there is no
		// line to add one to. Reformatting it to make room would rewrite something
		// nobody asked to have rewritten.
		return Edit{}, false, NotEditable(key, openLine,
			"the object it belongs to is written on one line: change it by hand in "+doc.Path)
	}

	lines := jsonNest(indent, jsonStep(doc, src, box), key[found.depth:], want)
	start := after + 1
	if has && !jsonHasComma(src, last.valEnd) {
		// The member that was last needs the comma it did not need before, put right
		// after its value so a comment further along the line stays where it is.
		line := doc.Line(after)
		at := src.column(last.valEnd)
		lines = append([]string{line[:at] + "," + line[at:]}, lines...)
		return Edit{Start: after, End: after, Lines: lines, Description: describe(key, want, true)}, true, nil
	}
	return Edit{Start: start, End: start - 1, Lines: lines, Description: describe(key, want, true)}, true, nil
}

// jsonLast returns the member that comes last in the file, which is the one whose
// value ends furthest along.
func jsonLast(box jsonBox) (jsonMember, bool) {
	if len(box.members) == 0 {
		return jsonMember{}, false
	}
	last := box.members[0]
	for _, m := range box.members[1:] {
		if m.valEnd > last.valEnd {
			last = m
		}
	}
	return last, true
}

// jsonHasComma reports whether a comma already follows a value, the trailing comma
// of a .jsonc included, which the blanked copy hid from the decoder. Writing a
// second one would break the file for every reader that tolerates the first.
func jsonHasComma(src *jsonSource, from int) bool {
	for i := from; i < len(src.scan); i++ {
		if src.scan[i] == ',' || src.blanked(i) {
			return true
		}
		if !jsonSpace(src.scan[i]) {
			return false
		}
	}
	return false
}

// blanked reports whether an offset held a trailing comma that jsonStrip replaced
// by a space. A comma inside a comment was blanked too and is not one of these.
func (s *jsonSource) blanked(off int) bool {
	i := sort.SearchInts(s.trailing, off)
	return i < len(s.trailing) && s.trailing[i] == off
}

// jsonNest writes the lines that state a key, one object per segment left, which
// is what a rule that asks for a key two levels down in a file that has neither of
// them needs.
func jsonNest(indent string, step int, key Key, want Literal) []string {
	pad := strings.Repeat(" ", step)
	deep := indent + strings.Repeat(pad, len(key)-1)
	lines := make([]string, 0, 2*len(key))
	for i, part := range key[:len(key)-1] {
		lines = append(lines, indent+strings.Repeat(pad, i)+jsonQuote(part)+": {")
	}
	lines = append(lines, deep+jsonQuote(key[len(key)-1])+": "+jsonSpell(want))
	for i := len(key) - 2; i >= 0; i-- {
		lines = append(lines, indent+strings.Repeat(pad, i)+"}")
	}
	return lines
}

// jsonStep is how far one nesting level is indented in this file, measured from
// the object being written into. Two spaces is the default because it is what npm
// itself writes a package.json with.
func jsonStep(doc *Doc, src *jsonSource, box jsonBox) int {
	const fallback = 2
	if len(box.members) == 0 {
		return fallback
	}
	outer := len(Indent(doc.Line(src.line(box.open))))
	inner := len(Indent(doc.Line(src.line(box.members[0].keyEnd))))
	if inner > outer {
		return inner - outer
	}
	return fallback
}

// jsonSpell writes a literal the way json spells it. A list is written on one line
// because that is how every one of these files writes a short array of strings.
func jsonSpell(want Literal) string {
	switch want.Kind {
	case KindBool:
		return strconv.FormatBool(want.Bool)
	case KindInt:
		return want.Text
	case KindList:
		parts := make([]string, 0, len(want.Items))
		for _, item := range want.Items {
			parts = append(parts, jsonQuote(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return jsonQuote(want.Text)
	}
}

// jsonQuote writes a string as a JSON string, leaving "<", ">" and "&" as
// themselves: the encoder escapes them for HTML by default, which would turn a
// registry URL in a package.json into something nobody typed.
func jsonQuote(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return strconv.Quote(s)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// jsonSpace reports whether a byte is whitespace between two JSON tokens.
func jsonSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// jsonStrip returns a copy of a .jsonc in which every byte of every comment and
// every trailing comma has been replaced by a space, and the offsets of the
// commas it blanked. Nothing is removed and nothing is added, so every offset in
// the copy is the same offset in the file, which is what lets the decoder say
// where a value is in a file it could not have read.
func jsonStrip(text string) (string, []int) {
	out := []byte(text)
	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			out[i] = ' '
		}
	}
	for i := 0; i < len(out); {
		switch {
		case out[i] == '"':
			i += jsonStringLen(text[i:])
		case strings.HasPrefix(text[i:], "//"):
			end := strings.IndexByte(text[i:], '\n')
			if end < 0 {
				blank(i, len(out))
				i = len(out)
				continue
			}
			// The newline ends the comment rather than belonging to it, so it stays and
			// the line count of the copy is the line count of the file.
			blank(i, i+end)
			i += end
		case strings.HasPrefix(text[i:], "/*"):
			end := strings.Index(text[i+2:], "*/")
			if end < 0 {
				blank(i, len(out))
				i = len(out)
				continue
			}
			blank(i, i+2+end+2)
			i += 2 + end + 2
		default:
			i++
		}
	}
	// The commas are found on the blanked copy, so a comma written inside a comment
	// is not one of them.
	var trailing []int
	stripped := string(out)
	for i := 0; i < len(out); {
		switch out[i] {
		case '"':
			i += jsonStringLen(stripped[i:])
		case ',':
			if j := jsonNextContent(stripped, i+1); j < len(out) && (out[j] == '}' || out[j] == ']') {
				out[i] = ' '
				trailing = append(trailing, i)
			}
			i++
		default:
			i++
		}
	}
	return string(out), trailing
}

// jsonNextContent is the offset of the next byte that is not whitespace.
func jsonNextContent(text string, from int) int {
	i := from
	for i < len(text) && jsonSpace(text[i]) {
		i++
	}
	return i
}

// jsonStringLen is the length of the string that starts at s, up to and including
// its closing quote, or the rest of the text when it is not closed.
func jsonStringLen(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(s)
}
