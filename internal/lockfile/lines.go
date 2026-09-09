package lockfile

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
)

// LineIndex turns a byte offset in a file into the 1-based line it falls on, so a
// parser that knows where a value started in the byte stream (encoding/json
// reports it through Decoder.InputOffset) can give the entry a line number.
type LineIndex struct {
	// starts[i] is the offset of the first byte of line i+1.
	starts []int64
	size   int64
}

// NewLineIndex indexes the line starts of data.
func NewLineIndex(data []byte) *LineIndex {
	idx := &LineIndex{starts: make([]int64, 1, bytes.Count(data, []byte{'\n'})+1), size: int64(len(data))}
	for i, b := range data {
		if b == '\n' {
			idx.starts = append(idx.starts, int64(i)+1)
		}
	}
	return idx
}

// Line returns the 1-based line the offset falls on. An offset before the file is
// line 1 and one past its end is the last line, so a caller never has to guard.
func (i *LineIndex) Line(offset int64) int {
	if i == nil || len(i.starts) == 0 {
		return 0
	}
	if offset < 0 {
		offset = 0
	}
	if offset > i.size {
		offset = i.size
	}
	// The line is the last start at or before the offset.
	n := sort.Search(len(i.starts), func(k int) bool { return i.starts[k] > offset })
	return n
}

// LineOf returns the 1-based line of the first occurrence of needle in data, or 0
// when it does not occur. It is for formats whose decoder reports no positions
// (TOML), where the parser knows the text of the key it just read.
func LineOf(data []byte, needle string) int {
	i := bytes.Index(data, []byte(needle))
	if i < 0 {
		return 0
	}
	return bytes.Count(data[:i], []byte{'\n'}) + 1
}

// At names a line for a message. A table the finder could not place has no line
// to name, and a reason that said "line 0" would send a reader nowhere.
func At(line int) string {
	if line <= 0 {
		return "an unplaced table"
	}
	return "line " + strconv.Itoa(line)
}

// TableFinder places the tables of a TOML lockfile, for the formats whose decoder
// loses positions (Cargo.lock and uv.lock). It indexes every header line once,
// ignoring the ones that sit inside a multi-line string, and then hands them out in
// file order: the nth table the decoder returned is paired with the nth header.
//
// A lockfile in a pull request is text somebody else wrote, so the pairing is
// confirmed rather than trusted. Next takes the name the decoder read and accepts a
// header only when the table under it declares that name, skipping forward over the
// headers that do not. A header a package writes inside a string value therefore
// costs at most the line number of its own entry, and never moves a finding onto
// another package's line: a header the finder cannot confirm yields 0, which
// Entry.Line documents as "the parser could not place it".
type TableFinder struct {
	lines   []string
	code    []bool
	headers []int
	next    int
}

// NewTableFinder indexes the header lines of data: the lines whose trimmed text is
// header, "[[package]]" for both formats read here.
func NewTableFinder(data []byte, header string) *TableFinder {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	f := &TableFinder{lines: lines, code: codeLines(lines)}
	for i, line := range lines {
		if f.code[i] && strings.TrimSpace(line) == header {
			f.headers = append(f.headers, i+1)
		}
	}
	return f
}

// Next returns the 1-based line of the header of the next table that declares
// name, or 0 when no header left in the file does. An empty name, which is what a
// table the decoder could not read has, takes the next header as it comes.
func (f *TableFinder) Next(name string) int {
	if f == nil || f.next >= len(f.headers) {
		return 0
	}
	if name == "" {
		line := f.headers[f.next]
		f.next++
		return line
	}
	for i := f.next; i < len(f.headers); i++ {
		if f.declares(i, name) {
			f.next = i + 1
			return f.headers[i]
		}
	}
	return 0
}

// declares reports whether the table under the ith header writes name = "<name>"
// before its first sub-table. The search stops at the next header, so the work of
// every call together is one pass over the file.
func (f *TableFinder) declares(i int, name string) bool {
	end := len(f.lines)
	if i+1 < len(f.headers) {
		end = f.headers[i+1] - 1
	}
	for j := f.headers[i]; j < end; j++ {
		if !f.code[j] {
			continue
		}
		line := strings.TrimSpace(f.lines[j])
		if strings.HasPrefix(line, "[") {
			// A sub-table starts, so the table's own keys are behind us.
			return false
		}
		if value, ok := tomlKeyValue(line, "name"); ok {
			return value == name
		}
	}
	return false
}

// tomlKeyValue reads a quoted value out of a single line "key = \"value\"", the
// only spelling either lockfile writes a package name in. The value is returned as
// the file wrote it, because a name that needs an escape is not a name either
// format allows.
func tomlKeyValue(line, key string) (string, bool) {
	rest, ok := cutKey(line, key)
	if !ok {
		return "", false
	}
	return quotedValue(rest)
}

// cutKey matches "<key> =" at the start of the line, bare or quoted, and returns
// what follows.
func cutKey(line, key string) (rest string, ok bool) {
	for _, spelling := range []string{key, `"` + key + `"`, "'" + key + "'"} {
		if !strings.HasPrefix(line, spelling) {
			continue
		}
		rest = strings.TrimLeft(line[len(spelling):], " \t")
		if strings.HasPrefix(rest, "=") {
			return strings.TrimLeft(rest[1:], " \t"), true
		}
	}
	return "", false
}

// quotedValue reads the string that starts at s, basic or literal, and returns its
// text without the quotes.
func quotedValue(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	quote := s[0]
	if quote != '"' && quote != '\'' {
		return "", false
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' && quote == '"' {
			i++
			continue
		}
		if s[i] == quote {
			return s[1:i], true
		}
	}
	return "", false
}

// codeLines reports, for each line, whether it begins outside a multi-line string.
// A line inside one is text a package chose, so a "[[package]]" written there is a
// value and not a header.
func codeLines(lines []string) []bool {
	code := make([]bool, len(lines))
	var basic, literal bool
	for i, line := range lines {
		code[i] = !basic && !literal
		scanLine(line, &basic, &literal)
	}
	return code
}

// scanLine walks one line and leaves the multi-line string state as the line ends
// it. Single-line strings and comments are walked past so that a quote or a "#"
// inside them changes nothing.
func scanLine(line string, basic, literal *bool) {
	for i := 0; i < len(line); {
		switch {
		case *basic:
			switch {
			case line[i] == '\\':
				i += 2
			case strings.HasPrefix(line[i:], `"""`):
				*basic = false
				i += 3
			default:
				i++
			}
		case *literal:
			if strings.HasPrefix(line[i:], "'''") {
				*literal = false
				i += 3
				continue
			}
			i++
		case line[i] == '#':
			return
		case strings.HasPrefix(line[i:], `"""`):
			*basic = true
			i += 3
		case strings.HasPrefix(line[i:], "'''"):
			*literal = true
			i += 3
		case line[i] == '"' || line[i] == '\'':
			i += singleLineString(line[i:])
		default:
			i++
		}
	}
}

// singleLineString returns the length of the string that starts at s, up to and
// including its closing quote, or the rest of the line when it is not closed.
func singleLineString(s string) int {
	quote := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' && quote == '"' {
			i++
			continue
		}
		if s[i] == quote {
			return i + 1
		}
	}
	return len(s)
}
