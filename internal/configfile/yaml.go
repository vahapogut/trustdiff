package configfile

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

func init() { Register(yamlCodec{}) }

// yamlCodec reads pnpm-workspace.yaml, .yarnrc.yml and .github/dependabot.yml.
//
// The whole file is read through yaml.Node and never into a struct, because a
// struct gives back values and this package needs places: a Node carries the Line
// and the Column of every key and every value, which is what lets an edit replace
// the bytes of one value and leave the comment above it, the blank line after it
// and the order of the keys exactly as somebody wrote them.
//
// YAML says the same thing in more ways than any other format here, and several
// of them cannot be edited one line at a time. An anchor is a definition other
// keys point at, an alias is a pointer to one, a merge key pulls a whole mapping
// in from somewhere else, a flow collection can run over several lines, and a
// block scalar's value is the lines under it rather than the text beside it.
// Each of those is reported with the line it is on and left alone, because a
// setting that looks written and is not is worse than one that is plainly missing.
type yamlCodec struct{}

// Format is the format this codec handles.
func (yamlCodec) Format() Format { return FormatYAML }

// yamlFound is one lookup: the value, the mapping the walk reached, and how much
// of the key the file actually has, which is what an insertion needs to know.
type yamlFound struct {
	value Value
	// key and node are the two nodes of the pair when the file states the key.
	key, node *yaml.Node
	// stopped is the deepest mapping the walk got into, nil when the file has no
	// mapping to walk. depth is how many segments of the key it had.
	stopped *yaml.Node
	depth   int
	// step is the indentation one nesting level costs in this file.
	step int
}

// Get locates a key.
func (yamlCodec) Get(doc *Doc, key Key) (Value, error) {
	found, err := yamlLookup(doc, key)
	if err != nil {
		return Value{}, err
	}
	return found.value, nil
}

// Set replaces the value where it sits, or adds the key to the mapping it belongs
// to.
func (yamlCodec) Set(doc *Doc, key Key, want Literal) (Edit, bool, error) {
	found, err := yamlLookup(doc, key)
	if err != nil {
		return Edit{}, false, err
	}
	v := &found.value
	if !v.Found() {
		return yamlInsert(doc, &found, key, want)
	}
	if holds(v, want) {
		return Edit{}, false, nil
	}
	if !v.Editable {
		return Edit{}, false, NotEditable(key, v.Line, v.Reason)
	}
	return yamlReplace(doc, &found, key, want)
}

// yamlLookup parses the file and walks the key into it.
func yamlLookup(doc *Doc, key Key) (yamlFound, error) {
	if len(key) == 0 {
		return yamlFound{}, fmt.Errorf("%s: a yaml key names no levels, so there is nothing to look up", doc.Path)
	}
	top, err := yamlTop(doc)
	if err != nil {
		return yamlFound{}, err
	}
	found := yamlFound{value: Value{Key: key}, step: yamlStep(top)}
	if top == nil {
		return found, nil
	}
	cur, why := top, ""
	for i, part := range key {
		if cur.Kind != yaml.MappingNode {
			// The walk ran into something that holds no keys, so the rest of the path
			// is not in the file. Where it stopped is remembered only when it is a
			// mapping, because that is the only thing a key can be added to.
			return found, nil
		}
		found.stopped, found.depth = cur, i
		if merged := yamlMerge(cur); merged != "" && why == "" {
			why = merged
		}
		k, node := yamlMember(cur, part)
		if k == nil {
			return found, nil
		}
		if i < len(key)-1 {
			if refuse := yamlRefuse(doc, node); refuse != "" {
				// A mapping reached through an alias or an anchor is somebody else's
				// mapping, and writing into it would change every key that points at it.
				found.value = yamlUnreadable(doc, key, k.Line, refuse)
				return found, nil
			}
			cur = node
			continue
		}
		found.key, found.node, found.depth = k, node, len(key)
		found.value = yamlValue(doc, key, k, node, why)
		return found, nil
	}
	return found, nil
}

// yamlTop parses the document and returns its top node, nil for an empty file.
// The lines are joined with "\n" whatever the file's own endings are, so a
// carriage return never shifts a column.
func yamlTop(doc *Doc) (*yaml.Node, error) {
	var root yaml.Node
	dec := yaml.NewDecoder(strings.NewReader(strings.Join(doc.Lines(), "\n")))
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty file states nothing, which is a miss and not a failure.
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w", doc.Path, err)
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		return root.Content[0], nil
	}
	return &root, nil
}

// yamlMember returns the key node and the value node of one entry of a mapping.
func yamlMember(mapping *yaml.Node, name string) (key, value *yaml.Node) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == name {
			return mapping.Content[i], mapping.Content[i+1]
		}
	}
	return nil, nil
}

// yamlMerge names the merge key of a mapping when it has one. A mapping that
// merges another one states keys this reader cannot see the lines of, so every
// key in it is reported rather than edited: the value on the line may not be the
// value the mapping ends up with.
func yamlMerge(mapping *yaml.Node) string {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "<<" {
			return fmt.Sprintf("a merge key, << at line %d, which brings keys in from another mapping", mapping.Content[i].Line)
		}
	}
	return ""
}

// yamlRefuse names the construct that stops an edit at a node, empty when there
// is none. The name is the one the format's own documentation uses, because the
// scorecard prints it to somebody who then has to go and look at the line.
func yamlRefuse(doc *Doc, n *yaml.Node) string {
	switch {
	case n.Kind == yaml.AliasNode:
		return "an alias to the anchor &" + n.Value
	case n.Anchor != "":
		return "an anchor, &" + n.Anchor
	case n.Style&yaml.LiteralStyle != 0:
		return "a block scalar written with |"
	case n.Style&yaml.FoldedStyle != 0:
		return "a block scalar written with >"
	}
	if n.Kind == yaml.MappingNode && n.Style&yaml.FlowStyle != 0 && !yamlClosesOnItsLine(doc, n) {
		return "a flow mapping that spans lines"
	}
	if n.Kind == yaml.SequenceNode && n.Style&yaml.FlowStyle != 0 && !yamlClosesOnItsLine(doc, n) {
		return "a flow sequence that spans lines"
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return yamlRefuseScalar(doc, n)
	case yaml.SequenceNode:
		return yamlRefuseSequence(doc, n)
	default:
		return ""
	}
}

// yamlRefuseScalar names the two ways a scalar runs past the line it starts on: a
// quoted string whose closing quote is on a later line, and a plain scalar
// continued by an indented line under it. Both read as one value and neither can
// be replaced by rewriting the first line.
//
// The plain case is caught by looking for the value the parser read at the start
// of the text on the line: a plain scalar has no escapes and no quotes, so the two
// are the same bytes. When the line does not begin with the whole value, the rest
// of it is on the lines below.
func yamlRefuseScalar(doc *Doc, n *yaml.Node) string {
	if n.Tag == "!!null" && n.Value == "" {
		// A key written with nothing after its colon. There is no value on the line
		// to measure and nothing running past it either.
		return ""
	}
	line := doc.Line(n.Line)
	at := yamlColumn(line, n.Column)
	if at >= len(line) {
		return "a value this reader could not find on its own line"
	}
	rest := line[at:]
	if c := rest[0]; c == '"' || c == '\'' {
		if _, ok := yamlQuotedLen(rest); !ok {
			return "a quoted scalar that spans lines"
		}
		return ""
	}
	if !strings.HasPrefix(rest, n.Value) {
		return "a plain scalar continued on the line under it"
	}
	return ""
}

// yamlRefuseSequence names what stops a block sequence from being rewritten: an
// item that is not a plain scalar, and a comment or a blank line between two
// items, which replacing the range would delete.
func yamlRefuseSequence(doc *Doc, n *yaml.Node) string {
	if n.Style&yaml.FlowStyle != 0 {
		return ""
	}
	for _, item := range n.Content {
		if item.Kind != yaml.ScalarNode {
			return "a sequence whose items are not plain values"
		}
		if refuse := yamlRefuse(doc, item); refuse != "" {
			return refuse
		}
	}
	if yamlEnd(n)-n.Line+1 != len(n.Content) {
		return "a sequence with comments or blank lines between its items"
	}
	return ""
}

// yamlClosesOnItsLine reports whether a flow collection opens and closes on the
// line it starts on. The nodes inside it only say where they are, so a "[a, b"
// closed on the next line would otherwise look like a one line sequence.
func yamlClosesOnItsLine(doc *Doc, n *yaml.Node) bool {
	if yamlEnd(n) != n.Line {
		return false
	}
	line := doc.Line(n.Line)
	depth := 0
	for i := yamlColumn(line, n.Column); i < len(line); {
		switch line[i] {
		case '[', '{':
			depth++
			i++
		case ']', '}':
			depth--
			i++
			if depth == 0 {
				return true
			}
		case '"', '\'':
			width, ok := yamlQuotedLen(line[i:])
			if !ok {
				return false
			}
			i += width
		default:
			i++
		}
	}
	return false
}

// yamlValue builds the Value of one mapping entry.
func yamlValue(doc *Doc, key Key, k, node *yaml.Node, why string) Value {
	v := Value{Key: key, Kind: KindOther, Line: k.Line, EndLine: yamlEnd(node), Editable: true}
	if v.EndLine < v.Line {
		v.EndLine = v.Line
	}
	switch node.Kind {
	case yaml.ScalarNode:
		v.Text = node.Value
		v.Kind = yamlScalarKind(node)
	case yaml.MappingNode:
		v.Kind = KindMap
	case yaml.SequenceNode:
		if items, ok := yamlItems(node); ok {
			v.Kind, v.Items = KindList, items
		}
	case yaml.AliasNode, yaml.DocumentNode:
		v.Kind = KindOther
	}
	v.Raw = yamlRaw(doc, node, v.Line, v.EndLine)
	if refuse := yamlRefuse(doc, node); refuse != "" && why == "" {
		why = refuse
	}
	if why != "" {
		v.Editable = false
		v.Reason = why + ": change it by hand in " + doc.Path
	}
	return v
}

// yamlUnreadable is the value of a key this codec found the place of but will not
// interpret, because something on the way to it is not a plain mapping.
func yamlUnreadable(doc *Doc, key Key, line int, why string) Value {
	return Value{
		Key: key, Kind: KindOther, Line: line, EndLine: line,
		Reason: why + ": change it by hand in " + doc.Path,
	}
}

// yamlScalarKind reads the shape the parser resolved a scalar to. The tag is used
// rather than the text because a quoted "4320" is a string and the parser is the
// one that already knows.
func yamlScalarKind(node *yaml.Node) Kind {
	switch node.Tag {
	case "!!bool":
		return KindBool
	case "!!int":
		return KindInt
	case "!!str":
		return KindString
	default:
		return KindOther
	}
}

// yamlItems reads a sequence of scalars. A sequence holding a mapping or another
// sequence is not a list a rule can compare.
func yamlItems(node *yaml.Node) ([]string, bool) {
	items := make([]string, 0, len(node.Content))
	for _, el := range node.Content {
		if el.Kind != yaml.ScalarNode {
			return nil, false
		}
		items = append(items, el.Value)
	}
	return items, true
}

// yamlRaw is the text of a value as the file holds it: the bytes on the line for a
// value that fits on one, and the lines joined for one that does not.
func yamlRaw(doc *Doc, node *yaml.Node, start, end int) string {
	if node.Line < start || node.Line > doc.NumLines() {
		return ""
	}
	if node.Line == end {
		line := doc.Line(node.Line)
		at := yamlColumn(line, node.Column)
		if at > len(line) {
			return ""
		}
		return strings.TrimRight(line[at:], " \t")
	}
	parts := make([]string, 0, end-node.Line+1)
	for n := node.Line; n <= end; n++ {
		parts = append(parts, doc.Line(n))
	}
	return strings.Join(parts, "\n")
}

// yamlEnd is the last line a node covers, as far as the parser reported it.
func yamlEnd(n *yaml.Node) int {
	end := n.Line
	for _, child := range n.Content {
		if e := yamlEnd(child); e > end {
			end = e
		}
	}
	return end
}

// yamlReplace plans the edit that puts a new value where the old one is.
func yamlReplace(doc *Doc, found *yamlFound, key Key, want Literal) (Edit, bool, error) {
	node := found.node
	block := node.Kind == yaml.SequenceNode && node.Style&yaml.FlowStyle == 0
	if want.Kind == KindList && block {
		// The file already writes this key as a block sequence, so the new items are
		// written the same way, at the indentation the old ones had.
		indent := Indent(doc.Line(node.Line))
		lines := make([]string, 0, len(want.Items))
		for _, item := range want.Items {
			lines = append(lines, indent+"- "+yamlString(item))
		}
		return Edit{Start: node.Line, End: yamlEnd(node), Lines: lines, Description: describe(key, want, false)}, true, nil
	}
	if block {
		// A scalar replacing a block sequence: the sequence's lines go away and the
		// value moves up beside its key, which is the only shape a scalar has here.
		line := doc.Line(found.key.Line)
		head, ok := yamlAfterColon(line, found.key.Column)
		if !ok {
			return Edit{}, false, NotEditable(key, found.key.Line, "the key and its \":\" are not on one line: change it by hand in "+doc.Path)
		}
		return Edit{
			Start: found.key.Line, End: yamlEnd(node),
			Lines:       []string{line[:head] + " " + yamlSpell(want)},
			Description: describe(key, want, false),
		}, true, nil
	}
	slot, why := yamlSlot(doc, found)
	if why != "" {
		return Edit{}, false, NotEditable(key, found.key.Line, why+": change it by hand in "+doc.Path)
	}
	line := doc.Line(slot.line)
	return Edit{
		Start: slot.line, End: slot.line,
		Lines:       []string{line[:slot.from] + yamlSpell(want) + line[slot.to:]},
		Description: describe(key, want, false),
	}, true, nil
}

// yamlPlace is the byte range on one line that holds a value, so an edit can put a
// new one there and leave the key, the indentation and a trailing comment alone.
type yamlPlace struct {
	line     int
	from, to int
}

// yamlSlot finds the bytes of a value on its line. A key written with no value at
// all gets the empty range just after its colon, because that is where the value
// it is missing would go.
func yamlSlot(doc *Doc, found *yamlFound) (yamlPlace, string) {
	node := found.node
	if node.Kind == yaml.ScalarNode && node.Tag == "!!null" && node.Value == "" {
		line := doc.Line(found.key.Line)
		at, ok := yamlAfterColon(line, found.key.Column)
		if !ok {
			return yamlPlace{}, "a key whose \":\" this reader could not find"
		}
		return yamlPlace{line: found.key.Line, from: at, to: at}, ""
	}
	line := doc.Line(node.Line)
	at := yamlColumn(line, node.Column)
	if at >= len(line) {
		return yamlPlace{}, "a value this reader could not find on its own line"
	}
	rest := line[at:]
	switch rest[0] {
	case '"', '\'':
		width, ok := yamlQuotedLen(rest)
		if !ok {
			return yamlPlace{}, "a quoted scalar that spans lines"
		}
		return yamlPlace{line: node.Line, from: at, to: at + width}, ""
	case '[', '{':
		if !yamlClosesOnItsLine(doc, node) {
			return yamlPlace{}, "a flow collection that spans lines"
		}
		return yamlPlace{line: node.Line, from: at, to: at + yamlFlowLen(rest)}, ""
	default:
		// A plain scalar is exactly the bytes the parser read, so the value the parser
		// gave back measures it. Everything after those bytes on the line, a trailing
		// comment or the brace of the flow mapping it sits in, stays where it is.
		if !strings.HasPrefix(rest, node.Value) {
			return yamlPlace{}, "a plain scalar continued on the line under it"
		}
		return yamlPlace{line: node.Line, from: at, to: at + len(node.Value)}, ""
	}
}

// yamlAfterColon returns the offset just past the ":" that follows a key.
func yamlAfterColon(line string, column int) (int, bool) {
	at := yamlColumn(line, column)
	if at > len(line) {
		return 0, false
	}
	i := strings.IndexByte(line[at:], ':')
	if i < 0 {
		return 0, false
	}
	return at + i + 1, true
}

// yamlQuotedLen is the length of the quoted scalar that starts at s, up to and
// including its closing quote. ok is false when the quote does not close on this
// line, which is a value spread over several of them.
func yamlQuotedLen(s string) (int, bool) {
	quote := s[0]
	for i := 1; i < len(s); i++ {
		switch {
		case quote == '"' && s[i] == '\\':
			i++
		case s[i] == quote:
			if quote == '\'' && i+1 < len(s) && s[i+1] == '\'' {
				// Two single quotes inside a single quoted scalar are one quote.
				i++
				continue
			}
			return i + 1, true
		}
	}
	return 0, false
}

// yamlFlowLen is the length of the flow collection that starts at s, which
// yamlClosesOnItsLine has already established closes on this line.
func yamlFlowLen(s string) int {
	depth := 0
	for i := 0; i < len(s); {
		switch s[i] {
		case '[', '{':
			depth++
			i++
		case ']', '}':
			depth--
			i++
			if depth == 0 {
				return i
			}
		case '"', '\'':
			width, ok := yamlQuotedLen(s[i:])
			if !ok {
				return len(s)
			}
			i += width
		default:
			i++
		}
	}
	return len(s)
}

// yamlInsert plans the edit that adds a key the file does not state, at the end of
// the deepest mapping the file already has on the way to it.
func yamlInsert(doc *Doc, found *yamlFound, key Key, want Literal) (Edit, bool, error) {
	if found.value.Kind != KindMissing {
		// The walk stopped on a construct it reported rather than on a missing key.
		return Edit{}, false, NotEditable(key, found.value.Line, found.value.Reason)
	}
	if found.stopped == nil {
		if doc.NumLines() > 0 && strings.TrimSpace(doc.Text()) != "" {
			return Edit{}, false, NotEditable(key, 1, "the top of the file is not a mapping: change it by hand in "+doc.Path)
		}
		lines := yamlNest("", found.step, key, want)
		return Edit{Start: 1, End: 0, Lines: lines, Description: describe(key, want, true)}, true, nil
	}
	mapping := found.stopped
	if mapping.Style&yaml.FlowStyle != 0 {
		return Edit{}, false, NotEditable(key, mapping.Line, "the mapping it belongs to is written as a flow mapping: change it by hand in "+doc.Path)
	}
	if len(mapping.Content) == 0 {
		return Edit{}, false, NotEditable(key, mapping.Line, "the mapping it belongs to states no keys to measure the indentation from: change it by hand in "+doc.Path)
	}
	indent := Indent(doc.Line(mapping.Content[0].Line))
	at := yamlBlockEnd(doc, mapping, len(indent))
	lines := yamlNest(indent, found.step, key[found.depth:], want)
	return Edit{Start: at + 1, End: at, Lines: lines, Description: describe(key, want, true)}, true, nil
}

// yamlBlockEnd is the last line of a mapping's own block. The parser only reports
// where the nodes it built start, so the lines under the last of them that are
// indented deeper are followed too, which is what a block scalar's body is.
func yamlBlockEnd(doc *Doc, mapping *yaml.Node, indent int) int {
	end := yamlEnd(mapping)
	for end < doc.NumLines() {
		next := doc.Line(end + 1)
		if strings.TrimSpace(next) == "" || len(Indent(next)) <= indent {
			return end
		}
		end++
	}
	return end
}

// yamlNest writes the lines that state a key, one nesting level per segment left,
// which is what a rule that asks for a key two levels down in a file that has
// neither of them needs.
func yamlNest(indent string, step int, key Key, want Literal) []string {
	pad := strings.Repeat(" ", step)
	lines := make([]string, 0, len(key)+len(want.Items))
	for i, part := range key[:len(key)-1] {
		lines = append(lines, indent+strings.Repeat(pad, i)+yamlString(part)+":")
	}
	deep := indent + strings.Repeat(pad, len(key)-1)
	name := yamlString(key[len(key)-1])
	if want.Kind != KindList {
		return append(lines, deep+name+": "+yamlSpell(want))
	}
	lines = append(lines, deep+name+":")
	for _, item := range want.Items {
		lines = append(lines, deep+pad+"- "+yamlString(item))
	}
	return lines
}

// yamlStep is how much one nesting level is indented in this file, so a key added
// under a new parent lines up with the rest of it. Two spaces is the default
// because it is what every one of these files is written with.
func yamlStep(top *yaml.Node) int {
	const fallback = 2
	if top == nil {
		return fallback
	}
	if step := yamlStepOf(top); step > 0 {
		return step
	}
	return fallback
}

// yamlStepOf looks for the first parent and child whose columns differ.
func yamlStepOf(n *yaml.Node) int {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			value := n.Content[i+1]
			if value.Kind == yaml.MappingNode && value.Style&yaml.FlowStyle == 0 && len(value.Content) > 0 {
				if step := value.Content[0].Column - n.Content[i].Column; step > 0 {
					return step
				}
			}
		}
	}
	for _, child := range n.Content {
		if step := yamlStepOf(child); step > 0 {
			return step
		}
	}
	return 0
}

// yamlColumn turns a node's 1-based column, which the parser counts in characters,
// into a byte offset in the line, so a value that follows a non-ASCII one on the
// same line is still cut in the right place.
func yamlColumn(line string, column int) int {
	n := 1
	for i := range line {
		if n == column {
			return i
		}
		n++
	}
	return len(line)
}

// yamlSpell writes a literal the way yaml spells it.
func yamlSpell(want Literal) string {
	switch want.Kind {
	case KindBool:
		return strconv.FormatBool(want.Bool)
	case KindInt:
		return want.Text
	case KindList:
		parts := make([]string, 0, len(want.Items))
		for _, item := range want.Items {
			parts = append(parts, yamlString(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return yamlString(want.Text)
	}
}

// yamlString writes a string plainly where yaml would read it back as itself, and
// in double quotes otherwise. Quoting everything would be safe and would also
// rewrite half of a file that has never quoted anything.
func yamlString(s string) string {
	if yamlPlain(s) {
		return s
	}
	// Go's quoting and yaml's double quoted style agree on every escape a value in
	// one of these files can hold.
	return strconv.Quote(s)
}

// yamlPlain reports whether a string can be written without quotes and read back
// as the same string.
func yamlPlain(s string) bool {
	if s == "" || strings.TrimSpace(s) != s || strings.ContainsAny(s, ":#\n\r\t") {
		return false
	}
	if strings.ContainsAny(s[:1], `-?,[]{}&*!|>'"%@`+"`") {
		return false
	}
	switch strings.ToLower(s) {
	case "true", "false", "null", "~", "yes", "no", "on", "off":
		// A word yaml resolves to something other than a string has to be quoted to
		// stay a string.
		return false
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return false
	}
	return true
}
