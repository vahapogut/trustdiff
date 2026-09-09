package configfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The helpers every codec's test uses live here, beside the first codec, for the
// same reason holds does: one file per format is this package's whole layout and a
// file of shared test scaffolding would be the only exception to it.

// load reads a fixture into a document. The fixtures are real configuration files,
// checked in with the line endings and the comments a person would have written,
// because a test written against a file this package generated would only prove
// that it can read itself back.
func load(t *testing.T, name string, format Format) *Doc {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	return NewDoc(name, format, data)
}

// edit runs Set and applies whatever it planned. It returns the file as it would
// be written and whether there was anything to write, which is the pair every
// round trip here asserts on.
func edit(t *testing.T, doc *Doc, key Key, want Literal) (string, bool) {
	t.Helper()
	e, ok, err := Set(doc, key, want)
	if err != nil {
		t.Fatalf("Set(%s): %v", key, err)
	}
	if !ok {
		return doc.Text(), false
	}
	out, err := doc.Apply(e)
	if err != nil {
		t.Fatalf("Apply(%s): %v", key, err)
	}
	return out.Text(), true
}

// changed strips the lines the two versions of a file have in common, at the front
// and at the back, and returns what is left: exactly the lines the edit replaced
// and the lines it put in their place. A test that names those two has asserted
// that every other byte of the file, its line endings included, is untouched.
func changed(before, after string) (was, now []string, at int) {
	// The empty string a trailing newline leaves behind is dropped, so an insertion
	// at the end of a file reads as the lines it added rather than as the newline
	// moving. Whether the file kept its own trailing newline is asserted, where it
	// matters, by comparing the whole text.
	b, a := lastLine(strings.Split(before, "\n")), lastLine(strings.Split(after, "\n"))
	head := 0
	for head < len(b) && head < len(a) && b[head] == a[head] {
		head++
	}
	tail := 0
	for tail < len(b)-head && tail < len(a)-head && b[len(b)-1-tail] == a[len(a)-1-tail] {
		tail++
	}
	return b[head : len(b)-tail], a[head : len(a)-tail], head + 1
}

// lastLine drops the empty element a text ending in a newline splits into.
func lastLine(lines []string) []string {
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		return lines[:len(lines)-1]
	}
	return lines
}

// wantChange asserts that an edit replaced one set of lines with another and
// touched nothing else in the file.
func wantChange(t *testing.T, before, after string, was, now []string) {
	t.Helper()
	gotWas, gotNow, at := changed(before, after)
	if !equalLines(gotWas, was) || !equalLines(gotNow, now) {
		t.Errorf("the edit at line %d replaced\n\t%q\nwith\n\t%q\nand should have replaced\n\t%q\nwith\n\t%q",
			at, gotWas, gotNow, was, now)
	}
}

// equalLines compares two runs of lines.
func equalLines(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// wantRefused asserts that Set reported a construct it will not write into, and
// that the message says which construct it is, because a reason that does not name
// it sends somebody to a line with nothing to go on.
func wantRefused(t *testing.T, doc *Doc, key Key, want Literal, names string) {
	t.Helper()
	_, ok, err := Set(doc, key, want)
	if err == nil {
		t.Fatalf("Set(%s) planned an edit (ok %v) and should have refused", key, ok)
	}
	if !errors.Is(err, ErrNotEditable) {
		t.Fatalf("Set(%s) failed with %v, and should have wrapped ErrNotEditable", key, err)
	}
	if !strings.Contains(err.Error(), names) {
		t.Errorf("Set(%s) refused with %q, which does not name %q", key, err, names)
	}
}

// wantMissing asserts that a key the file does not state reads as missing and not
// as an error, because absence is an answer.
func wantMissing(t *testing.T, doc *Doc, key Key) {
	t.Helper()
	v, err := Get(doc, key)
	if err != nil {
		t.Fatalf("Get(%s): %v", key, err)
	}
	if v.Found() || v.Kind != KindMissing {
		t.Errorf("Get(%s) = %+v, want a missing value", key, v)
	}
}

// wantIdempotent asserts that setting a key to what it already says changes
// nothing, which is what makes a second run of the fixer a no-op.
func wantIdempotent(t *testing.T, doc *Doc, key Key, want Literal) {
	t.Helper()
	e, ok, err := Set(doc, key, want)
	if err != nil {
		t.Fatalf("Set(%s): %v", key, err)
	}
	if ok {
		t.Errorf("Set(%s) planned %+v on a file that already says it", key, e)
	}
}

func TestINIGetReadsNpmrcAndPipConf(t *testing.T) {
	npmrc := load(t, "npmrc", FormatINI)
	pip := load(t, "pip.conf", FormatINI)
	tests := []struct {
		name  string
		doc   *Doc
		key   Key
		kind  Kind
		text  string
		items []string
		line  int
	}{
		{name: "an integer", doc: npmrc, key: Key{"minimumReleaseAge"}, kind: KindInt, text: "4320", line: 5},
		{name: "a boolean", doc: npmrc, key: Key{"ignore-scripts"}, kind: KindBool, text: "true", line: 6},
		{name: "a string", doc: npmrc, key: Key{"registry"}, kind: KindString, text: "https://registry.npmjs.org/", line: 2},
		{
			name: "a repeated key[] list", doc: npmrc, key: Key{"minimumReleaseAgeExclude"},
			kind: KindList, items: []string{"@acme/ui", "@acme/tokens"}, line: 9,
		},
		{name: "a key of a section", doc: pip, key: Key{"global", "timeout"}, kind: KindInt, text: "60", line: 4},
		{name: "a key of the second section", doc: pip, key: Key{"install", "no-binary"}, kind: KindString, text: ":none:", line: 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Get(tc.doc, tc.key)
			if err != nil {
				t.Fatalf("Get(%s): %v", tc.key, err)
			}
			if v.Kind != tc.kind || v.Text != tc.text || v.Line != tc.line {
				t.Errorf("Get(%s) = kind %q text %q line %d, want kind %q text %q line %d",
					tc.key, v.Kind, v.Text, v.Line, tc.kind, tc.text, tc.line)
			}
			if !equalLines(v.Items, tc.items) {
				t.Errorf("Get(%s).Items = %q, want %q", tc.key, v.Items, tc.items)
			}
		})
	}
}

func TestINIGetMissingKeysAreNotErrors(t *testing.T) {
	npmrc := load(t, "npmrc", FormatINI)
	wantMissing(t, npmrc, Key{"nothing-like-this"})
	wantMissing(t, load(t, "pip.conf", FormatINI), Key{"install", "nothing-like-this"})
	wantMissing(t, load(t, "pip.conf", FormatINI), Key{"freeze", "all"})
}

func TestINISetReplacesOnlyTheValue(t *testing.T) {
	doc := load(t, "npmrc", FormatINI)
	before := doc.Text()
	after, ok := edit(t, doc, Key{"minimumReleaseAge"}, Int(7200))
	if !ok {
		t.Fatal("Set planned nothing on a value that has to change")
	}
	wantChange(t, before, after, []string{"minimumReleaseAge=4320"}, []string{"minimumReleaseAge=7200"})
}

func TestINISetKeepsTheSpacingAroundTheEquals(t *testing.T) {
	doc := load(t, "pip.conf", FormatINI)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"global", "timeout"}, Int(120))
	wantChange(t, before, after, []string{"timeout = 60"}, []string{"timeout = 120"})
}

func TestINISetRewritesARepeatedKeyList(t *testing.T) {
	doc := load(t, "npmrc", FormatINI)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"minimumReleaseAgeExclude"}, List("@acme/ui", "@acme/tokens", "@acme/icons"))
	wantChange(t, before, after, nil, []string{"minimumReleaseAgeExclude[]=@acme/icons"})
}

func TestINISetReplacesARepeatedKeyListInPlace(t *testing.T) {
	doc := load(t, "npmrc", FormatINI)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"minimumReleaseAgeExclude"}, List("@acme/icons"))
	wantChange(t, before, after,
		[]string{"minimumReleaseAgeExclude[]=@acme/ui", "minimumReleaseAgeExclude[]=@acme/tokens"},
		[]string{"minimumReleaseAgeExclude[]=@acme/icons"})
}

func TestINIInsertAddsToTheRightSection(t *testing.T) {
	tests := []struct {
		name string
		key  Key
		want Literal
		now  []string
	}{
		{
			name: "into a section that already has keys",
			key:  Key{"global", "retries"}, want: Int(5),
			now: []string{"retries = 5"},
		},
		{
			name: "into the last section of the file",
			key:  Key{"install", "no-compile"}, want: Bool(true),
			now: []string{"no-compile = true"},
		},
		{
			name: "into a section the file does not have yet",
			key:  Key{"freeze", "all"}, want: Bool(true),
			now: []string{"", "[freeze]", "all = true"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := load(t, "pip.conf", FormatINI)
			before := doc.Text()
			after, ok := edit(t, doc, tc.key, tc.want)
			if !ok {
				t.Fatal("Set planned nothing for a key the file does not state")
			}
			wantChange(t, before, after, nil, tc.now)
		})
	}
}

func TestINIInsertJoinsTheKeysAboveTheFirstSection(t *testing.T) {
	doc := load(t, "npmrc", FormatINI)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"save-exact"}, Bool(true))
	wantChange(t, before, after, nil, []string{"save-exact=true"})
}

func TestINIInsertWritesAListAsOneKeyLinePerItem(t *testing.T) {
	doc := load(t, "npmrc", FormatINI)
	before := doc.Text()
	after, ok := edit(t, doc, Key{"onlyBuiltDependencies"}, List("esbuild", "sharp"))
	if !ok {
		t.Fatal("Set planned nothing for a key the file does not state")
	}
	wantChange(t, before, after, nil,
		[]string{"onlyBuiltDependencies[]=esbuild", "onlyBuiltDependencies[]=sharp"})
}

func TestINISetOnAnAlreadyCorrectValueDoesNothing(t *testing.T) {
	doc := load(t, "npmrc", FormatINI)
	wantIdempotent(t, doc, Key{"minimumReleaseAge"}, Int(4320))
	wantIdempotent(t, doc, Key{"ignore-scripts"}, Bool(true))
	wantIdempotent(t, doc, Key{"registry"}, String("https://registry.npmjs.org/"))
	wantIdempotent(t, doc, Key{"minimumReleaseAgeExclude"}, List("@acme/ui", "@acme/tokens"))
	wantIdempotent(t, load(t, "pip.conf", FormatINI), Key{"global", "timeout"}, Int(60))
}

func TestINIRefusesAnInterpolatedValue(t *testing.T) {
	doc := load(t, "npmrc", FormatINI)
	key := Key{"//registry.npmjs.org/:_authToken"}
	v, err := Get(doc, key)
	if err != nil {
		t.Fatalf("Get(%s): %v", key, err)
	}
	if v.Editable {
		t.Errorf("Get(%s) reported an interpolated value as editable", key)
	}
	wantRefused(t, doc, key, String("nope"), "${NPM_TOKEN}")
}

func TestINIRejectsAKeyDeeperThanASection(t *testing.T) {
	doc := load(t, "pip.conf", FormatINI)
	if _, err := Get(doc, Key{"global", "a", "b"}); err == nil {
		t.Error("Get accepted a three level key, which an ini file has no room for")
	}
}

func TestCRLFSurvivesAnEdit(t *testing.T) {
	// The file is built here rather than checked in because the repository keeps
	// every file with newline endings, which is the one thing this test needs not to
	// be true.
	source := "registry=https://registry.npmjs.org/\r\nminimumReleaseAge=1440\r\nignore-scripts=true\r\n"
	doc := NewDoc(".npmrc", FormatINI, []byte(source))
	after, ok := edit(t, doc, Key{"minimumReleaseAge"}, Int(4320))
	if !ok {
		t.Fatal("Set planned nothing on a value that has to change")
	}
	want := "registry=https://registry.npmjs.org/\r\nminimumReleaseAge=4320\r\nignore-scripts=true\r\n"
	if after != want {
		t.Errorf("the edit wrote %q, want %q", after, want)
	}
}

func TestAFileWithNoTrailingNewlineGetsOneWhenALineIsAdded(t *testing.T) {
	source := "registry=https://registry.npmjs.org/\nignore-scripts=true"
	doc := NewDoc(".npmrc", FormatINI, []byte(source))
	after, ok := edit(t, doc, Key{"minimumReleaseAge"}, Int(4320))
	if !ok {
		t.Fatal("Set planned nothing for a key the file does not state")
	}
	want := "registry=https://registry.npmjs.org/\nignore-scripts=true\nminimumReleaseAge=4320\n"
	if after != want {
		t.Errorf("the edit wrote %q, want %q", after, want)
	}
}

func TestAnUnchangedFileKeepsItsMissingTrailingNewline(t *testing.T) {
	// Doc.Apply gives every file it changes a trailing newline, so the only way a
	// file without one keeps it is for Set to plan nothing at all. That is the case
	// this asserts; the case where a line is added is the test above it.
	source := "registry=https://registry.npmjs.org/\nminimumReleaseAge=4320"
	doc := NewDoc(".npmrc", FormatINI, []byte(source))
	after, ok := edit(t, doc, Key{"minimumReleaseAge"}, Int(4320))
	if ok {
		t.Fatal("Set planned an edit on a file that already says the right thing")
	}
	if after != source {
		t.Errorf("the file read back as %q, want %q", after, source)
	}
}

func TestAnEmptyFileGetsTheKeyAndNothingElse(t *testing.T) {
	// doctor creates an .npmrc that is not there and then writes into it, so the
	// first key of an empty file has to land without a blank line above it.
	tests := []struct {
		name   string
		format Format
		key    Key
		want   Literal
		text   string
	}{
		{name: "ini", format: FormatINI, key: Key{"minimumReleaseAge"}, want: Int(4320), text: "minimumReleaseAge=4320\n"},
		{
			name: "toml", format: FormatTOML, key: Key{"install", "minimumReleaseAge"}, want: Int(4320),
			text: "[install]\nminimumReleaseAge = 4320\n",
		},
		{
			name: "yaml", format: FormatYAML, key: Key{"minimumReleaseAge"}, want: Int(4320),
			text: "minimumReleaseAge: 4320\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := NewDoc("new-file", tc.format, nil)
			wantMissing(t, doc, tc.key)
			after, ok := edit(t, doc, tc.key, tc.want)
			if !ok {
				t.Fatal("Set planned nothing for a key an empty file cannot state")
			}
			if after != tc.text {
				t.Errorf("the edit wrote %q, want %q", after, tc.text)
			}
		})
	}
}

func TestFormatsAreRegistered(t *testing.T) {
	for _, format := range []Format{FormatINI, FormatTOML, FormatYAML, FormatJSON, FormatJSONC} {
		if _, ok := For(format); !ok {
			t.Errorf("no codec is registered for %s", format)
		}
	}
}
