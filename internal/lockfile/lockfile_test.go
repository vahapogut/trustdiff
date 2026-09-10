package lockfile

import (
	"errors"
	"io"
	"path/filepath"
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

func TestTableFinderWalksForwardAndDoesNotWrap(t *testing.T) {
	data := []byte("[[package]]\nname = \"a\"\n\n[[package]]\nname = \"b\"\n\n[[package]]\nname = \"c\"\n")
	f := NewTableFinder(data, "[[package]]")
	// In file order the finder walks forward, so repeated headers resolve to
	// successive occurrences rather than always the first.
	for i, tt := range []struct {
		name string
		want int
	}{{name: "a", want: 1}, {name: "b", want: 4}, {name: "c", want: 7}} {
		if got := f.Next(tt.name); got != tt.want {
			t.Errorf("Next(%q) #%d = %d, want %d", tt.name, i+1, got, tt.want)
		}
	}
	// Past the last header it says it cannot place the table rather than wrapping
	// round to the top and pointing at another package's line.
	if got := f.Next("d"); got != 0 {
		t.Errorf("Next after the last header = %d, want 0", got)
	}
	var nilFinder *TableFinder
	if got := nilFinder.Next("a"); got != 0 {
		t.Errorf("nil finder Next() = %d, want 0", got)
	}
}

func TestTableFinderIgnoresHeadersInsideStrings(t *testing.T) {
	// The notes value of the first package spells a header and a name; neither may
	// count, or every entry after it is placed on somebody else's line.
	data := []byte(strings.Join([]string{
		`[[package]]`,       // 1
		`name = "innocent"`, // 2
		`notes = """`,       // 3
		`[[package]]`,       // 4
		`name = "evil"`,     // 5
		`"""`,               // 6
		``,                  // 7
		`[[package]]`,       // 8
		`name = "evil"`,     // 9
		`version = "6.6.6"`, // 10
		``,                  // 11
		`[[package]]`,       // 12
		`literal = '''`,     // 13
		`[[package]]`,       // 14
		`'''`,               // 15
		`name = "last"`,     // 16
	}, "\n"))
	f := NewTableFinder(data, "[[package]]")
	for _, tt := range []struct {
		name string
		want int
	}{{name: "innocent", want: 1}, {name: "evil", want: 8}, {name: "last", want: 12}} {
		if got := f.Next(tt.name); got != tt.want {
			t.Errorf("Next(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestTableFinderResyncsAndGivesUp(t *testing.T) {
	data := []byte("[[package]]\nname = \"a\"\n\n[[package]]\nname = \"b\"\n")
	// A table the decoder read but whose header is not the next one moves the
	// finder forward rather than taking the header it is standing on.
	f := NewTableFinder(data, "[[package]]")
	if got := f.Next("b"); got != 4 {
		t.Errorf("Next(b) = %d, want 4", got)
	}
	// A name no header declares places nothing and leaves the finder where it was.
	f = NewTableFinder(data, "[[package]]")
	if got := f.Next("nowhere"); got != 0 {
		t.Errorf("Next(nowhere) = %d, want 0", got)
	}
	if got := f.Next("a"); got != 1 {
		t.Errorf("Next(a) after a miss = %d, want 1", got)
	}
	// An empty name is a table the decoder could not read: it takes the next
	// header as it comes, so the tables after it keep their places.
	f = NewTableFinder(data, "[[package]]")
	if got := f.Next(""); got != 1 {
		t.Errorf("Next(unnamed) = %d, want 1", got)
	}
	if got := f.Next("b"); got != 4 {
		t.Errorf("Next(b) after an unnamed table = %d, want 4", got)
	}
}

func TestTableFinderHandlesCRLFAndQuoting(t *testing.T) {
	f := NewTableFinder([]byte("one\r\n[table]\r\nname   =   'x'  # a comment\r\n"), "[table]")
	if got := f.Next("x"); got != 2 {
		t.Errorf("Next in a CRLF file = %d, want 2", got)
	}
	f = NewTableFinder([]byte("[table]\n\"name\" = \"y\"\n"), "[table]")
	if got := f.Next("y"); got != 1 {
		t.Errorf("Next with a quoted key = %d, want 1", got)
	}
}

func TestRegistryHostsWeighTheFileAgainstAnOutlier(t *testing.T) {
	hosts := NPMRegistryHosts()
	// A file that installs everything through one private registry, with a single
	// entry pointing somewhere else.
	for range 3 {
		hosts.Count("Artifacts.Example.Com")
	}
	hosts.Count("evil.example.com")

	if !hosts.Known("registry.npmjs.org") || !hosts.Known("npm.pkg.github.com") {
		t.Error("the public registry and GitHub Packages are not known hosts")
	}
	if hosts.Known("artifacts.example.com") {
		t.Error("a host nobody listed is known")
	}
	// The host is compared without regard to case, as host names are.
	if !hosts.Serves("artifacts.example.com") {
		t.Error("the host three quarters of the file installs from is not a registry")
	}
	if hosts.Serves("evil.example.com") {
		t.Error("a host one entry names on its own reads as the project's registry")
	}
	if hosts.Serves("nowhere.example.com") {
		t.Error("a host the file never names reads as the project's registry")
	}
	// A file of one package cannot tell an outlier from a registry, and says so
	// the way that keeps a one-package private lockfile readable.
	single := NewRegistryHosts(nil)
	single.Count("only.example.com")
	if !single.Serves("only.example.com") {
		t.Error("the only host of a one-entry file is not its registry")
	}
	// An empty host is not a count.
	empty := NewRegistryHosts(nil)
	empty.Count("")
	if empty.Serves("") {
		t.Error("an empty host reads as a registry")
	}
	// The substitution this exists to catch, in the smallest file it fits in: two
	// packages, one of them repointed. A share alone would call the outlier half
	// the project's downloads and let it through.
	small := NPMRegistryHosts()
	small.Count("registry.npmjs.org")
	small.Count("evil.example.com")
	if !small.Known("registry.npmjs.org") {
		t.Error("the public registry is not a registry in a two-entry file")
	}
	if small.Serves("evil.example.com") {
		t.Error("half of a two-entry file reads as the project's registry")
	}
	// A file wholly on a private registry keeps reading as one however large it
	// grows, and the one entry pointed elsewhere is still the outlier.
	private := NPMRegistryHosts()
	for range 300 {
		private.Count("artifacts.example.com")
	}
	private.Count("evil.example.com")
	if !private.Serves("artifacts.example.com") {
		t.Error("the host a whole private file installs from is not a registry")
	}
	if private.Serves("evil.example.com") {
		t.Error("one entry of 301 reads as the project's registry")
	}
	// Two registries side by side, which is a project mirroring part of its tree.
	both := NPMRegistryHosts()
	for range 200 {
		both.Count("artifacts.example.com")
	}
	for range 300 {
		both.Count("registry.npmjs.org")
	}
	if !both.Serves("artifacts.example.com") {
		t.Error("a host serving two fifths of the file is not a registry")
	}
}

func TestAtNamesALineOrSaysItHasNone(t *testing.T) {
	if got := At(12); got != "line 12" {
		t.Errorf("At(12) = %q", got)
	}
	if got := At(0); got != "an unplaced table" {
		t.Errorf("At(0) = %q", got)
	}
}

// One format is identified by the directory it sits in. A requirements directory
// holding main.txt and dev.txt is as common as a requirements.txt, and "dev.txt"
// alone says nothing, so For asks a second time with the parent directory in front
// of the name.
func TestForAsksAboutTheParentDirectory(t *testing.T) {
	// The registry is swapped for the duration, so this parser is the only answer
	// and cannot be left behind for another test to trip over.
	withParsers(t, parentParser{})
	tests := []struct {
		path string
		want bool
	}{
		{"requirements/dev.txt", true},
		{filepath.Join("python", "requirements", "main.txt"), true},
		{"dev.txt", false},
		{"docs/dev.txt", false},
	}
	for _, tt := range tests {
		p, ok := For(tt.path)
		if ok != tt.want {
			t.Errorf("For(%q) = %v, want %v", tt.path, ok, tt.want)
			continue
		}
		if ok && p.Name() != "parent-directory-test" {
			t.Errorf("For(%q) chose %s", tt.path, p.Name())
		}
	}
}

// parentParser recognizes only the form with a parent directory, which is what the
// test above is about. It is registered by that test alone.
type parentParser struct{}

func (parentParser) Name() string { return "parent-directory-test" }

func (parentParser) Detect(name string) bool {
	return strings.HasPrefix(name, "requirements/") && strings.HasSuffix(name, ".txt")
}

func (parentParser) Parse(path string, _ io.Reader) (*Lockfile, error) {
	return &Lockfile{Path: path, Format: "parent-directory-test"}, nil
}

// A version a file locks at two places is one thing to evaluate while the two lines
// install the same artifact, and a mirror rewrite of a registry location is not a
// disagreement: it is the same release fetched through somewhere else.
func TestInstallsCollapsesTheCopiesOfOneArtifact(t *testing.T) {
	lf := &Lockfile{Ecosystem: model.NPM}
	ref := model.MustParseRef("npm:left-pad@1.3.0")
	lf.Add(Entry{Ref: ref, Source: SourceRegistry, Resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", Integrity: "sha512-pad", Line: 12})
	lf.Add(Entry{Ref: ref, Source: SourceRegistry, Resolved: "https://npm.example.com/left-pad/-/left-pad-1.3.0.tgz", Integrity: "sha512-pad", Direct: true, Line: 340})

	got := lf.Installs()
	if len(got) != 1 {
		t.Fatalf("Installs() = %d entries, want one: a mirror serves the same artifact", len(got))
	}
	if got[0].Line != 12 || !got[0].Direct {
		t.Errorf("Installs()[0] = line %d, direct %v, want line 12 and direct", got[0].Line, got[0].Direct)
	}
}

// This is finding F3 of docs/review-2026-09-10.md at the level the collapsing
// happens: a copy repointed at an archive of its own installs other bytes under the
// same version, so it is a line of its own to judge.
func TestInstallsKeepsACopyThatInstallsSomethingElse(t *testing.T) {
	lf := &Lockfile{Ecosystem: model.NPM}
	ref := model.MustParseRef("npm:left-pad@1.3.0")
	lf.Add(Entry{Ref: ref, Source: SourceRegistry, Resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", Integrity: "sha512-pad", Line: 12})
	lf.Add(Entry{Ref: ref, Source: SourceURL, Resolved: "https://tarballs.example.com/left-pad.tgz", Line: 340})

	got := lf.Installs()
	if len(got) != 2 {
		t.Fatalf("Installs() = %d entries, want both: the two lines install different bytes", len(got))
	}
	if got[0].Line != 12 || got[1].Line != 340 {
		t.Errorf("Installs() lines = %d and %d, want 12 and 340", got[0].Line, got[1].Line)
	}
}

// npm records neither a location nor a hash for a dependency bundled inside another
// package's archive, so such a line contradicts nothing the fetched line says,
// whichever of the two the file writes first. minimatch's 411 line lockfile holds 68
// versions of this shape and 11 of them put the bundled line first, so reading a
// bundled line as a copy that installs something else would turn 327 subjects into
// 395, every one of the extra ones a line that says nothing.
func TestInstallsFoldsABundledLineInEitherOrder(t *testing.T) {
	ref := model.MustParseRef("npm:ansi-regex@5.0.1")
	bundled := Entry{Ref: ref, Source: SourceUnknown, Bundled: true, Line: 12}
	fetched := Entry{Ref: ref, Source: SourceRegistry, Resolved: "https://registry.npmjs.org/ansi-regex/-/ansi-regex-5.0.1.tgz", Integrity: "sha512-ansi", Direct: true, Line: 340}

	for _, tt := range []struct {
		name     string
		entries  []Entry
		wantLine int
	}{
		{name: "the fetched line first", entries: []Entry{fetched, bundled}, wantLine: 340},
		{name: "the bundled line first", entries: []Entry{bundled, fetched}, wantLine: 340},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lf := &Lockfile{Ecosystem: model.NPM, Entries: tt.entries}
			got := lf.Installs()
			if len(got) != 1 {
				t.Fatalf("Installs() = %d entries, want one", len(got))
			}
			if got[0].Line != tt.wantLine {
				t.Errorf("Installs()[0].Line = %d, want %d, the line that says where the version comes from", got[0].Line, tt.wantLine)
			}
			if !got[0].Direct || got[0].Bundled {
				t.Errorf("Installs()[0] = direct %v, bundled %v, want direct and not bundled", got[0].Direct, got[0].Bundled)
			}
		})
	}
}

// A parser that leaves the source empty has not vouched for the registry, and the
// checks read it that way too, so the grouping has to agree or one file written by
// two hands reports a package twice for nothing.
func TestInstallsReadsAnUnstatedSourceAsUnknown(t *testing.T) {
	ref := model.MustParseRef("npm:left-pad@1.3.0")
	lf := &Lockfile{Ecosystem: model.NPM, Entries: []Entry{
		{Ref: ref, Resolved: "https://tarballs.example.com/left-pad.tgz", Line: 12},
		{Ref: ref, Source: SourceUnknown, Resolved: "https://tarballs.example.com/left-pad.tgz", Line: 340},
	}}
	if got := lf.Installs(); len(got) != 1 {
		t.Fatalf("Installs() = %d entries, want one: neither line claims the registry", len(got))
	}
}

func TestInstallsFillsInTheFilesEcosystem(t *testing.T) {
	lf := &Lockfile{Ecosystem: model.Cargo}
	lf.Add(Entry{Ref: model.PackageRef{Name: "serde", Version: "1.0.210"}, Source: SourceRegistry, Integrity: "sha256-ser"})
	if got := lf.Installs(); len(got) != 1 || got[0].Ref.Ecosystem != model.Cargo {
		t.Fatalf("Installs() = %+v, want the file's ecosystem filled in", got)
	}
	if len((*Lockfile)(nil).Installs()) != 0 {
		t.Error("Installs() of a nil lockfile is not empty")
	}
}
