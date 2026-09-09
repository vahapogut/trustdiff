package lockfile

import (
	"fmt"
	"strings"
	"testing"
)

// escapedTables writes a lockfile of n tables whose names are spelled with a TOML
// escape, so that the text of a header never matches the name a decoder hands the
// parser. It is the shape that turned the finder's search quadratic: every call
// fails to confirm a name, and a finder that answered each failure by starting
// again at the top read the whole file once per table.
func escapedTables(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "[[package]]\nname = \"pkg%04d\\u0030\"\nversion = \"1.0.0\"\nsource = \"registry\"\n\n", i)
	}
	return b.String()
}

// TestTableFinderReadsTheFileOnce holds the finder to the bound its comment
// promises: the lines every call looks at, added up, stay inside one pass over the
// file. Counting lines rather than timing the calls keeps the test honest on a
// loaded machine, and it fails on the growth itself rather than on how fast the
// machine that ran it happened to be.
func TestTableFinderReadsTheFileOnce(t *testing.T) {
	const tables = 200
	data := escapedTables(tables)
	f := NewTableFinder([]byte(data), "[[package]]")
	for i := range tables {
		// The decoded name, which is what the decoder reads out of the escape and
		// what no header in the file spells.
		if got := f.Next(fmt.Sprintf("pkg%04d0", i)); got != 0 {
			t.Fatalf("Next placed table %d on line %d, but no header spells its decoded name", i, got)
		}
	}
	lines := strings.Count(data, "\n") + 1
	if f.examined > lines {
		t.Errorf("the finder read %d lines of a %d line file, so its work is not one pass over it", f.examined, lines)
	}
}

// TestTableFinderPlacesEveryTableInOnePass is the same bound for the file the
// finder was written for, where every name does confirm its header: the placing
// must still be right, and still cost one pass.
func TestTableFinderPlacesEveryTableInOnePass(t *testing.T) {
	const tables = 200
	var b strings.Builder
	for i := range tables {
		fmt.Fprintf(&b, "[[package]]\nname = \"pkg%04d\"\nversion = \"1.0.0\"\n\n", i)
	}
	data := b.String()
	f := NewTableFinder([]byte(data), "[[package]]")
	for i := range tables {
		if got, want := f.Next(fmt.Sprintf("pkg%04d", i)), i*4+1; got != want {
			t.Fatalf("Next placed table %d on line %d, want %d", i, got, want)
		}
	}
	lines := strings.Count(data, "\n") + 1
	if f.examined > lines {
		t.Errorf("the finder read %d lines of a %d line file, so its work is not one pass over it", f.examined, lines)
	}
}
