package lockfile

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// fakeParser stands in for a format package in the registry tests.
type fakeParser struct {
	name string
	base string
	err  error
}

func (p fakeParser) Name() string            { return p.name }
func (p fakeParser) Detect(base string) bool { return base == p.base }
func (p fakeParser) Parse(path string, r io.Reader) (*Lockfile, error) {
	if p.err != nil {
		return nil, p.err
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	lf := &Lockfile{Path: path, Format: p.name, Ecosystem: model.NPM}
	lf.Add(Entry{Ref: model.MustParseRef("npm:" + strings.TrimSpace(string(body)) + "@1.0.0"), Source: SourceRegistry, Line: 1})
	return lf, nil
}

// withParsers swaps the registry for the duration of a test.
func withParsers(t *testing.T, ps ...Parser) {
	t.Helper()
	parsersMu.Lock()
	saved := parsers
	parsers = nil
	parsersMu.Unlock()
	t.Cleanup(func() {
		parsersMu.Lock()
		parsers = saved
		parsersMu.Unlock()
	})
	for _, p := range ps {
		Register(p)
	}
}

func TestRegisterOrdersByNameAndRejectsDuplicates(t *testing.T) {
	withParsers(t, fakeParser{name: "zeta", base: "zeta.lock"}, fakeParser{name: "alpha", base: "alpha.lock"})
	got := Parsers()
	if len(got) != 2 || got[0].Name() != "alpha" || got[1].Name() != "zeta" {
		t.Fatalf("Parsers() = %v, want alpha then zeta", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("registering a duplicate name did not panic")
		}
	}()
	Register(fakeParser{name: "alpha", base: "other.lock"})
}

func TestForMatchesByBaseNameCaseInsensitively(t *testing.T) {
	withParsers(t, fakeParser{name: "package-lock.json", base: "package-lock.json"})
	for _, path := range []string{"package-lock.json", "a/b/package-lock.json", "A/B/Package-Lock.JSON"} {
		if _, ok := For(path); !ok {
			t.Errorf("For(%q) found no parser", path)
		}
	}
	if _, ok := For("a/b/yarn.lock"); ok {
		t.Error("For(yarn.lock) found a parser although none is registered")
	}
}

func TestParseWrapsErrorsWithThePath(t *testing.T) {
	boom := errors.New("boom")
	withParsers(t, fakeParser{name: "ok.lock", base: "ok.lock"}, fakeParser{name: "bad.lock", base: "bad.lock", err: boom})

	lf, err := Parse("dir/ok.lock", strings.NewReader("express"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if lf.Path != "dir/ok.lock" || len(lf.Entries) != 1 || lf.Entries[0].Ref.Name != "express" {
		t.Fatalf("Parse = %+v", lf)
	}

	_, err = Parse("dir/bad.lock", strings.NewReader(""))
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "dir/bad.lock") {
		t.Fatalf("Parse error = %v, want boom wrapped with the path", err)
	}

	_, err = Parse("dir/unknown.lock", strings.NewReader(""))
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "unknown.lock") {
		t.Fatalf("Parse error = %v, want ErrUnsupported naming the file", err)
	}
}

func TestRefsDeduplicatesInFirstSeenOrder(t *testing.T) {
	lf := &Lockfile{}
	a := model.MustParseRef("npm:a@1.0.0")
	b := model.MustParseRef("npm:b@2.0.0")
	for _, ref := range []model.PackageRef{b, a, b, a} {
		lf.Add(Entry{Ref: ref})
	}
	got := lf.Refs()
	if len(got) != 2 || got[0] != b || got[1] != a {
		t.Fatalf("Refs() = %v, want b then a", got)
	}
	if len((&Lockfile{}).Refs()) != 0 {
		t.Error("Refs() of an empty lockfile is not empty")
	}
}

func TestDropRecordsAReason(t *testing.T) {
	lf := &Lockfile{}
	lf.Drop("entry %q has no version", "node_modules/foo")
	if len(lf.Dropped) != 1 || !strings.Contains(lf.Dropped[0], `"node_modules/foo"`) {
		t.Fatalf("Dropped = %v", lf.Dropped)
	}
}

func TestLineIndex(t *testing.T) {
	data := []byte("one\ntwo\n\nfour\n")
	idx := NewLineIndex(data)
	tests := []struct {
		offset int64
		want   int
	}{
		{offset: 0, want: 1},  // start of line 1
		{offset: 3, want: 1},  // its newline
		{offset: 4, want: 2},  // start of line 2
		{offset: 8, want: 3},  // the empty line
		{offset: 9, want: 4},  // start of line 4
		{offset: 13, want: 4}, // its newline
		{offset: 14, want: 5}, // one past the end: the empty last line
		{offset: 99, want: 5}, // clamped
		{offset: -1, want: 1}, // clamped
	}
	for _, tt := range tests {
		if got := idx.Line(tt.offset); got != tt.want {
			t.Errorf("Line(%d) = %d, want %d", tt.offset, got, tt.want)
		}
	}
	var nilIndex *LineIndex
	if got := nilIndex.Line(3); got != 0 {
		t.Errorf("nil index Line() = %d, want 0", got)
	}
	if got := NewLineIndex(nil).Line(0); got != 1 {
		t.Errorf("empty file Line(0) = %d, want 1", got)
	}
}

func TestLineOf(t *testing.T) {
	data := []byte("a\nb\n[package]\nname = \"x\"\n")
	if got := LineOf(data, "[package]"); got != 3 {
		t.Errorf("LineOf([package]) = %d, want 3", got)
	}
	if got := LineOf(data, "missing"); got != 0 {
		t.Errorf("LineOf(missing) = %d, want 0", got)
	}
}

func TestLineFinderScansForwardAndWraps(t *testing.T) {
	data := []byte("[[package]]\nname = \"a\"\n\n[[package]]\nname = \"b\"\n\n[[package]]\nname = \"c\"\n")
	f := NewLineFinder(data)
	// In file order the finder walks forward, so repeated headers resolve to
	// successive occurrences rather than always the first.
	for i, want := range []int{1, 4, 7} {
		if got := f.Find("[[package]]"); got != want {
			t.Errorf("Find #%d = %d, want %d", i+1, got, want)
		}
	}
	// Past the last occurrence it wraps once.
	if got := f.Find("[[package]]"); got != 1 {
		t.Errorf("Find after the last = %d, want the wrap to 1", got)
	}
	f.Reset()
	if got := f.Find(`name = "a"`); got != 2 {
		t.Errorf("Find(name a) = %d, want 2", got)
	}
	if got := f.Find("nowhere"); got != 0 {
		t.Errorf("Find(nowhere) = %d, want 0", got)
	}
	var nilFinder *LineFinder
	if got := nilFinder.Find("x"); got != 0 {
		t.Errorf("nil finder Find() = %d, want 0", got)
	}
}

func TestLineFinderHandlesCRLF(t *testing.T) {
	f := NewLineFinder([]byte("one\r\n[table]\r\n"))
	if got := f.Find("[table]"); got != 2 {
		t.Errorf("Find in a CRLF file = %d, want 2", got)
	}
}
