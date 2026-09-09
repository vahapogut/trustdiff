package configfile

import (
	"strings"
	"testing"
)

func TestTOMLGetFindsTheSameKeyInAllThreeSpellings(t *testing.T) {
	tests := []struct {
		name string
		file string
		line int
	}{
		{name: "under a table header", file: "bunfig.toml", line: 6},
		{name: "as a dotted key at the top", file: "bunfig-dotted.toml", line: 2},
		{name: "inside an inline table", file: "bunfig-inline.toml", line: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := load(t, tc.file, FormatTOML)
			v, err := Get(doc, Key{"install", "minimumReleaseAge"})
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if v.Kind != KindInt || v.Text != "4320" || v.Line != tc.line || !v.Editable {
				t.Errorf("Get = kind %q text %q line %d editable %v, want an editable int 4320 on line %d",
					v.Kind, v.Text, v.Line, v.Editable, tc.line)
			}
		})
	}
}

func TestTOMLGetReadsTheShapesRulesCompare(t *testing.T) {
	doc := load(t, "bunfig.toml", FormatTOML)
	tests := []struct {
		name string
		key  Key
		kind Kind
		text string
		line int
	}{
		{name: "a boolean at the top of the file", key: Key{"telemetry"}, kind: KindBool, text: "false", line: 2},
		{name: "a quoted string in a table", key: Key{"install", "registry"}, kind: KindString, text: "https://registry.npmjs.org", line: 8},
		{name: "a key of a sub-table", key: Key{"install", "cache", "disable"}, kind: KindBool, text: "false", line: 11},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Get(doc, tc.key)
			if err != nil {
				t.Fatalf("Get(%s): %v", tc.key, err)
			}
			if v.Kind != tc.kind || v.Text != tc.text || v.Line != tc.line {
				t.Errorf("Get(%s) = kind %q text %q line %d, want kind %q text %q line %d",
					tc.key, v.Kind, v.Text, v.Line, tc.kind, tc.text, tc.line)
			}
		})
	}
}

func TestTOMLGetMissingKeysAreNotErrors(t *testing.T) {
	doc := load(t, "bunfig.toml", FormatTOML)
	wantMissing(t, doc, Key{"install", "frozenLockfile"})
	wantMissing(t, doc, Key{"registry"})
	wantMissing(t, doc, Key{"tool", "uv", "exclude-newer"})
}

func TestTOMLSetReplacesOnlyTheValue(t *testing.T) {
	tests := []struct {
		name string
		file string
		was  string
		now  string
	}{
		{
			name: "under a table header", file: "bunfig.toml",
			was: "minimumReleaseAge = 4320", now: "minimumReleaseAge = 7200",
		},
		{
			name: "as a dotted key at the top", file: "bunfig-dotted.toml",
			was: "install.minimumReleaseAge = 4320", now: "install.minimumReleaseAge = 7200",
		},
		{
			name: "inside an inline table", file: "bunfig-inline.toml",
			was: "install = { minimumReleaseAge = 4320, exact = true }",
			now: "install = { minimumReleaseAge = 7200, exact = true }",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := load(t, tc.file, FormatTOML)
			before := doc.Text()
			after, ok := edit(t, doc, Key{"install", "minimumReleaseAge"}, Int(7200))
			if !ok {
				t.Fatal("Set planned nothing on a value that has to change")
			}
			wantChange(t, before, after, []string{tc.was}, []string{tc.now})
		})
	}
}

func TestTOMLSetKeepsACommentOnTheSameLine(t *testing.T) {
	doc := load(t, "bunfig.toml", FormatTOML)
	before := doc.Text()
	e, ok, err := Set(doc, Key{"install", "exact"}, Bool(false))
	if err != nil || !ok {
		t.Fatalf("Set: %v, ok %v", err, ok)
	}
	if e.Description != "set install.exact to false" {
		t.Errorf("the edit reads %q, and a preview should say what it does", e.Description)
	}
	out, err := doc.Apply(e)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantChange(t, before, out.Text(),
		[]string{"exact = true # keep the resolutions pinned"},
		[]string{"exact = false # keep the resolutions pinned"})
}

func TestTOMLInsertIntoATableThatExists(t *testing.T) {
	doc := load(t, "bunfig.toml", FormatTOML)
	before := doc.Text()
	after, ok := edit(t, doc, Key{"install", "frozenLockfile"}, Bool(true))
	if !ok {
		t.Fatal("Set planned nothing for a key the file does not state")
	}
	// The key joins the end of [install] rather than the end of the file, so the
	// [install.cache] table under it keeps its own keys.
	wantChange(t, before, after, nil, []string{"frozenLockfile = true"})
}

func TestTOMLInsertCreatesTheTableAtTheEndOfTheFile(t *testing.T) {
	doc := load(t, "bunfig-plain.toml", FormatTOML)
	before := doc.Text()
	after, ok := edit(t, doc, Key{"install", "minimumReleaseAge"}, Int(4320))
	if !ok {
		t.Fatal("Set planned nothing for a key the file does not state")
	}
	wantChange(t, before, after, nil, []string{"", "[install]", "minimumReleaseAge = 4320"})
}

func TestTOMLInsertSpellsStringsAndArraysTheWayTOMLDoes(t *testing.T) {
	tests := []struct {
		name string
		key  Key
		want Literal
		now  string
	}{
		{name: "a string", key: Key{"install", "registry"}, want: String("https://registry.npmjs.org"), now: `registry = "https://registry.npmjs.org"`},
		{name: "an array", key: Key{"install", "peers"}, want: List("react", "vue"), now: `peers = ["react", "vue"]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := load(t, "bunfig-plain.toml", FormatTOML)
			before := doc.Text()
			after, _ := edit(t, doc, tc.key, tc.want)
			wantChange(t, before, after, nil, []string{"", "[install]", tc.now})
		})
	}
}

func TestTOMLInsertAboveTheFirstTableWhenTheFileHasNoKeysOfItsOwn(t *testing.T) {
	doc := NewDoc("uv.toml", FormatTOML, []byte("# the pip settings for this project\n[pip]\nindex-url = \"https://pypi.org/simple\"\n"))
	before := doc.Text()
	after, ok := edit(t, doc, Key{"exclude-newer"}, String("2026-01-01T00:00:00Z"))
	if !ok {
		t.Fatal("Set planned nothing for a key the file does not state")
	}
	// The comment introduces [pip], so the key of the file itself goes above it
	// rather than between the comment and the table it is about.
	wantChange(t, before, after, nil, []string{`exclude-newer = "2026-01-01T00:00:00Z"`})
	if !strings.HasPrefix(after, "exclude-newer") {
		t.Errorf("the key landed inside the table: %q", after)
	}
}

func TestTOMLInsertKeepsAKeyOfTheFileAboveTheFirstTable(t *testing.T) {
	doc := load(t, "bunfig.toml", FormatTOML)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"smol"}, Bool(true))
	wantChange(t, before, after, nil, []string{"smol = true"})
}

func TestTOMLInsertRefusesATableWrittenInline(t *testing.T) {
	doc := load(t, "bunfig-inline.toml", FormatTOML)
	wantRefused(t, doc, Key{"install", "frozenLockfile"}, Bool(true), "written inline at line 2")
}

func TestTOMLSetOnAnAlreadyCorrectValueDoesNothing(t *testing.T) {
	doc := load(t, "bunfig.toml", FormatTOML)
	wantIdempotent(t, doc, Key{"install", "minimumReleaseAge"}, Int(4320))
	wantIdempotent(t, doc, Key{"install", "exact"}, Bool(true))
	wantIdempotent(t, doc, Key{"install", "registry"}, String("https://registry.npmjs.org"))
	wantIdempotent(t, doc, Key{"telemetry"}, Bool(false))
	wantIdempotent(t, load(t, "bunfig-inline.toml", FormatTOML), Key{"install", "minimumReleaseAge"}, Int(4320))
	wantIdempotent(t, load(t, "refuse.toml", FormatTOML), Key{"install", "peers"}, List("react", "vue"))
}

func TestTOMLRefusesValuesItCannotRewriteOneLineAtATime(t *testing.T) {
	tests := []struct {
		name  string
		key   Key
		want  Literal
		names string
	}{
		{name: "a multi-line string", key: Key{"install", "note"}, want: String("no"), names: "a multi-line string"},
		{name: "an array over several lines", key: Key{"install", "peers"}, want: List("react"), names: "an array that spans lines"},
		{
			name: "a key inside an inline table that spans lines",
			key:  Key{"install", "scopes", "other", "url"}, want: String("https://example.test"),
			names: "an inline table that spans lines",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := load(t, "refuse.toml", FormatTOML)
			v, err := Get(doc, tc.key)
			if err != nil {
				t.Fatalf("Get(%s): %v", tc.key, err)
			}
			if v.Editable {
				t.Errorf("Get(%s) reported %s as editable", tc.key, tc.names)
			}
			wantRefused(t, doc, tc.key, tc.want, tc.names)
		})
	}
}

func TestTOMLReportsAFileItCannotParse(t *testing.T) {
	doc := NewDoc("bunfig.toml", FormatTOML, []byte("[install\nminimumReleaseAge = 4320\n"))
	if _, err := Get(doc, Key{"install", "minimumReleaseAge"}); err == nil {
		t.Error("Get read a file the decoder rejects, and should have said so")
	}
}
