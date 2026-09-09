// Package configfile reads and edits the configuration files a project's package
// managers are configured through: ini (.npmrc, pip.conf), YAML
// (pnpm-workspace.yaml, .yarnrc.yml), TOML (bunfig.toml, pyproject.toml) and JSON
// with or without comments (package.json, deno.jsonc).
//
// The files belong to the people who wrote them. A comment above a setting, the
// order the keys are in, the indentation, a blank line between two blocks: all of
// it is somebody's decision and all of it survives an edit here, because nothing is
// ever re-serialized. A format's reader answers where a key is and what it holds,
// and an edit replaces or inserts the lines that hold it. ADR 0003 records why.
//
// A codec that cannot edit a key safely says so instead of guessing. A value inside
// a YAML anchor, a flow mapping spanning lines or a multi-line string is reported
// with its location and left alone: a wrong write into a configuration file is worse
// than no write, because the setting looks present afterwards.
package configfile

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Format is one configuration file shape.
type Format string

// The formats the doctor rules need.
const (
	FormatINI   Format = "ini"
	FormatYAML  Format = "yaml"
	FormatTOML  Format = "toml"
	FormatJSON  Format = "json"
	FormatJSONC Format = "jsonc"
)

// ErrUnsupported means no codec is registered for a format.
var ErrUnsupported = errors.New("no codec for this configuration format")

// ErrNotEditable is the error a codec returns from Set when the key it found sits
// in a construct it will not write into. The message says what and where, and the
// caller reports it beside the rule rather than failing the run.
var ErrNotEditable = errors.New("this key cannot be edited safely")

// Kind is the shape of a value, as far as the rules care.
type Kind string

// The value shapes a rule can ask for. A codec reports KindOther for anything else
// it found, which a rule can print but not compare.
const (
	KindMissing Kind = ""
	KindString  Kind = "string"
	KindInt     Kind = "int"
	KindBool    Kind = "bool"
	KindList    Kind = "list"
	KindMap     Kind = "map"
	KindOther   Kind = "other"
)

// Key is a path into a document, one segment per level: {"install",
// "minimumReleaseAge"} is the minimumReleaseAge key of the install table. A
// single-segment key is a top-level one, which is every key of an .npmrc without
// sections.
type Key []string

// String writes the key the way a message should name it, which is how the
// format's own documentation spells it.
func (k Key) String() string { return strings.Join(k, ".") }

// Equal reports whether two keys name the same place.
func (k Key) Equal(other Key) bool {
	if len(k) != len(other) {
		return false
	}
	for i := range k {
		if k[i] != other[i] {
			return false
		}
	}
	return true
}

// Value is a key a codec found, with everything a rule needs to judge it and a
// writer needs to replace it.
type Value struct {
	// Key is the key as it was asked for.
	Key Key
	// Kind is the shape the codec read. KindMissing means the file does not state
	// the key, and then only Key is set, so a message can still name what was
	// looked for.
	Kind Kind
	// Text is a scalar as a Go string: quotes removed, escapes resolved, the number
	// or the boolean written as the file wrote it. Empty for a list or a map.
	Text string
	// Items are the entries of a list of scalars, in file order.
	Items []string
	// Raw is the bytes of the value as the file holds them, quotes and all, for a
	// message that has to show what is there rather than what it means.
	Raw string
	// Line and EndLine are the 1-based line range the whole key and value occupy,
	// inclusive. A key on one line has Line == EndLine.
	Line, EndLine int
	// Editable is false when the writer must not replace those lines. Reason says
	// why, in the words the scorecard prints.
	Editable bool
	// Reason is why the value cannot be edited, empty when it can.
	Reason string
}

// Found reports whether the file states the key. The receiver is a pointer because
// a Value carries six fields and is handed to every rule that judges a setting.
func (v *Value) Found() bool { return v != nil && v.Kind != KindMissing }

// Literal is a value a rule wants written, in a format-neutral shape. The codec
// spells it the way its own format does: a string is quoted where the format
// requires quoting, a list becomes a YAML sequence, a TOML array or a JSON array.
type Literal struct {
	Kind Kind
	// Text is the string or the number, as the value should read.
	Text string
	// Bool is the value when Kind is KindBool.
	Bool bool
	// Items are the entries when Kind is KindList.
	Items []string
}

// String makes a string literal.
func String(s string) Literal { return Literal{Kind: KindString, Text: s} }

// Int makes a numeric literal from its text, so a rule that computed 259200 and a
// rule that wants 3 write the same way.
func Int(n int64) Literal { return Literal{Kind: KindInt, Text: fmt.Sprint(n)} }

// Bool makes a boolean literal.
func Bool(b bool) Literal { return Literal{Kind: KindBool, Bool: b} }

// List makes a list of strings.
func List(items ...string) Literal { return Literal{Kind: KindList, Items: items} }

// Doc is one configuration file: the bytes as they were read, split into lines
// once, with the newline style remembered so an edit writes the file back the way
// it found it.
type Doc struct {
	// Path is the file as the caller named it, for messages.
	Path string
	// Format is the codec that reads it.
	Format Format
	// lines are the file's lines without their line endings.
	lines []string
	// crlf is true when the file's first line ending was a carriage return and a
	// newline, which is how a file written on Windows reaches us.
	crlf bool
	// finalNewline is true when the file ends with a line ending. A file that does
	// not is left without one.
	finalNewline bool
}

// NewDoc splits data into lines and remembers how to put it back together.
func NewDoc(path string, format Format, data []byte) *Doc {
	d := &Doc{Path: path, Format: format}
	text := string(data)
	d.crlf = strings.Contains(text, "\r\n")
	// The split is on "\n" and the carriage returns are trimmed, so a file with
	// mixed endings is read whole and written back with one style, which is the
	// only case here where a file does not come out byte for byte.
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if d.finalNewline = strings.HasSuffix(text, "\n"); d.finalNewline {
		text = strings.TrimSuffix(text, "\n")
	}
	if text == "" && !d.finalNewline {
		// An empty file has no lines, not one empty line.
		return d
	}
	d.lines = strings.Split(text, "\n")
	return d
}

// Lines returns the document's lines, without their endings. The slice is the
// document's own and must not be written to.
func (d *Doc) Lines() []string { return d.lines }

// Line returns the 1-based line, or "" when there is none.
func (d *Doc) Line(n int) string {
	if n < 1 || n > len(d.lines) {
		return ""
	}
	return d.lines[n-1]
}

// NumLines is how many lines the document has.
func (d *Doc) NumLines() int { return len(d.lines) }

// Bytes writes the document back out, with the line ending style and the trailing
// newline it was read with.
func (d *Doc) Bytes() []byte {
	var b bytes.Buffer
	end := "\n"
	if d.crlf {
		end = "\r\n"
	}
	for i, line := range d.lines {
		b.WriteString(line)
		if i < len(d.lines)-1 || d.finalNewline {
			b.WriteString(end)
		}
	}
	return b.Bytes()
}

// Text is the document as one string, for a diff.
func (d *Doc) Text() string { return string(d.Bytes()) }

// Edit is a line range replaced by other lines. It is the only way this package
// changes a file: a value that exists is replaced where it sits, and a key that
// does not is inserted at a line the codec chose.
type Edit struct {
	// Start is the 1-based first line replaced. An insertion before line n has
	// Start n and End n-1, which is the empty range at that point.
	Start int
	// End is the 1-based last line replaced, inclusive. End < Start is an
	// insertion.
	End int
	// Lines are what goes there, without line endings.
	Lines []string
	// Description is what the edit does, in the words a preview prints, for
	// example "set minimumReleaseAge to 4320".
	Description string
}

// Insertion reports whether the edit adds lines without replacing any.
func (e Edit) Insertion() bool { return e.End < e.Start }

// Apply returns a copy of the document with the edit applied. The receiver is not
// changed, because a preview is built before anything is written and the caller
// may decide not to write.
func (d *Doc) Apply(e Edit) (*Doc, error) {
	if e.Start < 1 || e.Start > len(d.lines)+1 {
		return nil, fmt.Errorf("%s: edit starts at line %d, which the file does not have", d.Path, e.Start)
	}
	if !e.Insertion() && (e.End < e.Start || e.End > len(d.lines)) {
		return nil, fmt.Errorf("%s: edit ends at line %d, which the file does not have", d.Path, e.End)
	}
	out := *d
	out.lines = make([]string, 0, len(d.lines)+len(e.Lines))
	out.lines = append(out.lines, d.lines[:e.Start-1]...)
	out.lines = append(out.lines, e.Lines...)
	if !e.Insertion() {
		out.lines = append(out.lines, d.lines[e.End:]...)
	} else {
		out.lines = append(out.lines, d.lines[e.Start-1:]...)
	}
	// A file that gained a line ends with a newline, because a last line without one
	// is a file the next tool appends to badly. A file that only had a value
	// replaced keeps the ending it had, since changing it would be a change nobody
	// asked for in a diff nobody expected it in.
	out.finalNewline = d.finalNewline || len(out.lines) > len(d.lines)
	return &out, nil
}

// Codec reads one configuration format and plans edits to it.
type Codec interface {
	// Format is the format the codec handles.
	Format() Format
	// Get locates a key. A key the file does not state is a Value with KindMissing
	// and no error: absence is an answer, not a failure.
	Get(doc *Doc, key Key) (Value, error)
	// Set returns the edit that makes the key hold the literal. A key that is
	// already exactly that returns ok false and no edit, which is what makes a
	// second run of the fixer change nothing. A key the codec will not write
	// returns an error wrapping ErrNotEditable.
	Set(doc *Doc, key Key, want Literal) (edit Edit, ok bool, err error)
}

var (
	codecsMu sync.Mutex
	codecs   = map[Format]Codec{}
)

// Register adds a codec; each format's file calls it from init. Registering a
// format twice is a programming error and panics.
func Register(c Codec) {
	codecsMu.Lock()
	defer codecsMu.Unlock()
	if _, dup := codecs[c.Format()]; dup {
		panic("configfile: duplicate codec for " + string(c.Format()))
	}
	codecs[c.Format()] = c
}

// For returns the codec of a format.
func For(f Format) (Codec, bool) {
	codecsMu.Lock()
	defer codecsMu.Unlock()
	c, ok := codecs[f]
	return c, ok
}

// Formats returns every registered format, sorted, for a message that has to list
// them.
func Formats() []Format {
	codecsMu.Lock()
	defer codecsMu.Unlock()
	out := make([]Format, 0, len(codecs))
	for f := range codecs {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Get locates a key with the codec of the document's format.
func Get(doc *Doc, key Key) (Value, error) {
	c, ok := For(doc.Format)
	if !ok {
		return Value{}, fmt.Errorf("%w: %s", ErrUnsupported, doc.Format)
	}
	return c.Get(doc, key)
}

// Set plans the edit that makes a key hold a value, with the codec of the
// document's format.
func Set(doc *Doc, key Key, want Literal) (Edit, bool, error) {
	c, ok := For(doc.Format)
	if !ok {
		return Edit{}, false, fmt.Errorf("%w: %s", ErrUnsupported, doc.Format)
	}
	return c.Set(doc, key, want)
}

// NotEditable makes the error a codec returns for a value it will not write.
func NotEditable(key Key, line int, why string) error {
	return fmt.Errorf("%s at line %d: %w: %s", key, line, ErrNotEditable, why)
}

// Indent returns the leading whitespace of a line, which is what an inserted line
// beside it should carry so the file keeps its own indentation.
func Indent(line string) string {
	return line[:len(line)-len(strings.TrimLeft(line, " \t"))]
}

// FormatOf guesses the format from a file name, which is how the doctor rules
// name the files they read. An unknown name returns false rather than a default,
// because writing YAML into a file that turned out to be TOML is exactly the kind
// of guess this package refuses to make.
func FormatOf(name string) (Format, bool) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".jsonc"):
		return FormatJSONC, true
	case strings.HasSuffix(lower, ".json"):
		return FormatJSON, true
	case strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".yml"):
		return FormatYAML, true
	case strings.HasSuffix(lower, ".toml"):
		return FormatTOML, true
	case strings.HasSuffix(lower, ".conf"), strings.HasSuffix(lower, ".ini"),
		strings.HasSuffix(lower, "npmrc"), strings.HasSuffix(lower, ".cfg"):
		// .npmrc and .yarnrc are ini; .yarnrc.yml is caught by the yaml case above
		// because it is tried first.
		return FormatINI, true
	}
	return "", false
}
