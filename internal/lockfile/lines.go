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
//
// A name a header cannot be found for is not a hypothetical. A decoder reads TOML
// escapes and the finder reads the text a header was written in, so a file that
// spells its names with an escape ("name = \"pkg\\u0030\"") confirms none of them,
// and neither does a file whose tables the decoder reordered. Those entries carry
// no line, and finding that out has to be cheap: the name each header declares is
// read once, when the file is indexed, and Next is then a lookup. The work of the
// finder over a whole file is therefore one pass over it however many names it
// fails to place, which TestTableFinderReadsTheFileOnce holds it to.
type TableFinder struct {
	// headers[i] is the 1-based line of the ith header, in file order.
	headers []int
	// byName holds, for each name some table declares, the headers left to hand out
	// for it. Next takes from the front, so a name spelled by several tables is
	// placed on a different header each time it is asked for.
	byName map[string][]int
	next   int
	// examined counts the lines the finder has looked at, so that the promise
	// above is a thing a test can fail on rather than a thing the comment claims.
	examined int
}

// NewTableFinder indexes the header lines of data: the lines whose trimmed text is
// header, "[[package]]" for both formats read here. The name the table under each
// header declares is read in the same pass, because a name looked up later cannot
// be looked for in the file again without reading the file again.
func NewTableFinder(data []byte, header string) *TableFinder {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	f := &TableFinder{byName: make(map[string][]int)}
	var basic, literal bool
	// naming is true while the lines being read are the keys of the table under the
	// last header, before its first sub-table, which is where its name is written.
	naming := false
	for i, line := range lines {
		f.examined++
		code := !basic && !literal
		scanLine(line, &basic, &literal)
		if !code {
			// The line began inside a multi-line string, so it is text a package
			// chose: a header written there is a value and not a header.
			continue
		}
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == header:
			f.headers = append(f.headers, i+1)
			naming = true
		case !naming:
			continue // Whatever the line says, it says it about no header.
		case strings.HasPrefix(trimmed, "["):
			// A sub-table starts, so the table's own keys are behind us.
			naming = false
		default:
			if name, ok := tomlKeyValue(trimmed, "name"); ok {
				f.byName[name] = append(f.byName[name], len(f.headers)-1)
				naming = false
			}
		}
	}
	return f
}

// Next returns the 1-based line of the header of the next table that declares
// name, or 0 when no header left in the file does. An empty name, which is what a
// table the decoder could not read has, takes the next header as it comes.
//
// A name it cannot place leaves the finder where it stands, so that the tables
// after it keep the headers they would have had: a file the finder cannot confirm
// one name in is still a file every other name is placed in.
func (f *TableFinder) Next(name string) int {
	if f == nil || f.next >= len(f.headers) {
		return 0
	}
	if name == "" {
		line := f.headers[f.next]
		f.next++
		return line
	}
	left, ok := f.byName[name]
	if !ok {
		return 0
	}
	// Headers behind the cursor were handed to an earlier table, and dropping them
	// here is what keeps a repeated miss from costing a walk over them again.
	for len(left) > 0 && left[0] < f.next {
		left = left[1:]
	}
	if len(left) == 0 {
		delete(f.byName, name)
		return 0
	}
	i := left[0]
	f.byName[name] = left[1:]
	f.next = i + 1
	return f.headers[i]
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
