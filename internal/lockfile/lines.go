package lockfile

import (
	"bytes"
	"sort"
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

// LineFinder walks a file once and answers where a table or key appears, for the
// formats whose decoder loses positions. It scans forward from the line it last
// answered, so a parser asking about entries in file order stays linear.
type LineFinder struct {
	lines []string
	next  int
}

// NewLineFinder indexes the lines of data.
func NewLineFinder(data []byte) *LineFinder {
	return &LineFinder{lines: strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")}
}

// Find returns the 1-based line of the next line whose trimmed text equals want,
// searching from where the last answer left off and wrapping once. It returns 0
// when the text is nowhere in the file.
func (f *LineFinder) Find(want string) int {
	if f == nil {
		return 0
	}
	if line := f.scan(f.next, len(f.lines), want); line > 0 {
		f.next = line
		return line
	}
	if line := f.scan(0, f.next, want); line > 0 {
		f.next = line
		return line
	}
	return 0
}

// Reset starts the next search from the top of the file.
func (f *LineFinder) Reset() { f.next = 0 }

func (f *LineFinder) scan(from, to int, want string) int {
	for i := from; i < to && i < len(f.lines); i++ {
		if strings.TrimSpace(f.lines[i]) == want {
			return i + 1
		}
	}
	return 0
}
