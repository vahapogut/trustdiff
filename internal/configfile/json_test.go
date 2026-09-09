package configfile

import "testing"

func TestJSONGetReadsTheShapesRulesCompare(t *testing.T) {
	pkg := load(t, "package.json", FormatJSON)
	renovate := load(t, "renovate.json", FormatJSON)
	deno := load(t, "deno.jsonc", FormatJSONC)
	tests := []struct {
		name  string
		doc   *Doc
		key   Key
		kind  Kind
		text  string
		items []string
		line  int
	}{
		{name: "a string", doc: pkg, key: Key{"name"}, kind: KindString, text: "acme-app", line: 2},
		{name: "a boolean", doc: pkg, key: Key{"private"}, kind: KindBool, text: "true", line: 4},
		{name: "a key inside an object", doc: pkg, key: Key{"scripts", "build"}, kind: KindString, text: "tsc", line: 6},
		{name: "an object", doc: pkg, key: Key{"dependencies"}, kind: KindMap, line: 8},
		{
			name: "an array of strings", doc: renovate, key: Key{"extends"},
			kind: KindList, items: []string{"config:recommended"}, line: 2,
		},
		{
			name: "a key past a block comment", doc: deno, key: Key{"lock"},
			kind: KindBool, text: "true", line: 4,
		},
		{
			name: "a key with a comment after it", doc: deno, key: Key{"imports", "@std/assert"},
			kind: KindString, text: "jsr:@std/assert@1", line: 6,
		},
		{
			name: "a key after a trailing comma", doc: deno, key: Key{"nodeModulesDir"},
			kind: KindString, text: "auto", line: 9,
		},
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

func TestJSONGetMissingKeysAreNotErrors(t *testing.T) {
	wantMissing(t, load(t, "package.json", FormatJSON), Key{"pnpm"})
	wantMissing(t, load(t, "package.json", FormatJSON), Key{"scripts", "test"})
	wantMissing(t, load(t, "deno.jsonc", FormatJSONC), Key{"imports", "@std/path"})
}

func TestJSONSetReplacesOnlyTheValue(t *testing.T) {
	tests := []struct {
		name   string
		file   string
		format Format
		key    Key
		want   Literal
		was    string
		now    string
	}{
		{
			name: "a string in a package.json", file: "package.json", format: FormatJSON,
			key: Key{"version"}, want: String("2.0.0"),
			was: `  "version": "1.0.0",`, now: `  "version": "2.0.0",`,
		},
		{
			name: "a value whose line ends in a trailing comma", file: "deno.jsonc", format: FormatJSONC,
			key: Key{"nodeModulesDir"}, want: String("manual"),
			was: `  "nodeModulesDir": "auto",`, now: `  "nodeModulesDir": "manual",`,
		},
		{
			name: "a value with a comment after it", file: "deno.jsonc", format: FormatJSONC,
			key: Key{"imports", "@std/assert"}, want: String("jsr:@std/assert@2"),
			was: `    "@std/assert": "jsr:@std/assert@1", // pinned on purpose`,
			now: `    "@std/assert": "jsr:@std/assert@2", // pinned on purpose`,
		},
		{
			name: "an array of strings", file: "renovate.json", format: FormatJSON,
			key: Key{"extends"}, want: List("config:recommended", "config:js-app"),
			was: `  "extends": ["config:recommended"],`,
			now: `  "extends": ["config:recommended", "config:js-app"],`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := load(t, tc.file, tc.format)
			before := doc.Text()
			after, ok := edit(t, doc, tc.key, tc.want)
			if !ok {
				t.Fatal("Set planned nothing on a value that has to change")
			}
			wantChange(t, before, after, []string{tc.was}, []string{tc.now})
		})
	}
}

func TestJSONInsertGivesTheOldLastMemberItsComma(t *testing.T) {
	doc := load(t, "package.json", FormatJSON)
	before := doc.Text()
	after, ok := edit(t, doc, Key{"scripts", "test"}, String("vitest"))
	if !ok {
		t.Fatal("Set planned nothing for a key the file does not state")
	}
	wantChange(t, before, after,
		[]string{`    "build": "tsc"`},
		[]string{`    "build": "tsc",`, `    "test": "vitest"`})
}

func TestJSONInsertBuildsTheObjectsOnTheWay(t *testing.T) {
	doc := load(t, "package.json", FormatJSON)
	after, _ := edit(t, doc, Key{"pnpm", "minimumReleaseAge"}, Int(4320))
	// The whole file is named here rather than the lines that moved, because the
	// object this writes is three lines and the comma the old last member gained is
	// on a fourth, and a reader should be able to see that the result parses.
	want := `{
  "name": "acme-app",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "build": "tsc"
  },
  "dependencies": {
    "react": "19.0.0"
  },
  "pnpm": {
    "minimumReleaseAge": 4320
  }
}
`
	if after != want {
		t.Errorf("the edit wrote\n%s\nwant\n%s", after, want)
	}
}

func TestJSONCInsertLeavesAnExistingTrailingCommaAlone(t *testing.T) {
	doc := load(t, "deno.jsonc", FormatJSONC)
	before := doc.Text()
	after, ok := edit(t, doc, Key{"imports", "@std/path"}, String("jsr:@std/path@1"))
	if !ok {
		t.Fatal("Set planned nothing for a key the file does not state")
	}
	// The member above already ends in a comma, so a second one would be written
	// into a file that has one, which is what the blanked copy is there to see.
	wantChange(t, before, after, nil, []string{`    "@std/path": "jsr:@std/path@1"`})
}

func TestJSONSetOnAnAlreadyCorrectValueDoesNothing(t *testing.T) {
	pkg := load(t, "package.json", FormatJSON)
	wantIdempotent(t, pkg, Key{"name"}, String("acme-app"))
	wantIdempotent(t, pkg, Key{"private"}, Bool(true))
	wantIdempotent(t, pkg, Key{"scripts", "build"}, String("tsc"))
	wantIdempotent(t, load(t, "renovate.json", FormatJSON), Key{"extends"}, List("config:recommended"))
	wantIdempotent(t, load(t, "deno.jsonc", FormatJSONC), Key{"lock"}, Bool(true))
	wantIdempotent(t, load(t, "deno.jsonc", FormatJSONC), Key{"imports", "@std/assert"}, String("jsr:@std/assert@1"))
}

func TestJSONRefusesAnObjectWrittenOnOneLine(t *testing.T) {
	doc := load(t, "renovate.json", FormatJSON)
	wantRefused(t, doc, Key{"vulnerabilityAlerts", "minimumReleaseAge"}, Int(4320), "written on one line")
}

func TestJSONRefusesAPathThroughSomethingThatIsNotAnObject(t *testing.T) {
	doc := load(t, "package.json", FormatJSON)
	wantRefused(t, doc, Key{"name", "first"}, String("no"), "does not hold an object")
}

func TestJSONReportsAFileItCannotParse(t *testing.T) {
	// The same bytes are a valid .jsonc and not a valid .json, which is the whole
	// difference between the two codecs.
	source := []byte("{\n  // a note\n  \"lock\": true,\n}\n")
	if _, err := Get(NewDoc("deno.json", FormatJSON, source), Key{"lock"}); err == nil {
		t.Error("the json codec read a file with comments in it")
	}
	v, err := Get(NewDoc("deno.jsonc", FormatJSONC, source), Key{"lock"})
	if err != nil {
		t.Fatalf("the jsonc codec could not read the same bytes: %v", err)
	}
	if v.Kind != KindBool || v.Text != "true" || v.Line != 3 {
		t.Errorf("Get = kind %q text %q line %d, want a boolean true on line 3", v.Kind, v.Text, v.Line)
	}
}

func TestJSONReportsATopLevelThatIsNotAnObject(t *testing.T) {
	doc := NewDoc("renovate.json", FormatJSON, []byte("[1, 2]\n"))
	if _, err := Get(doc, Key{"anything"}); err == nil {
		t.Error("Get read a document whose top is an array, and should have said so")
	}
}

func TestJSONCFileWithNoTrailingNewlineGetsOneWhenALineIsAdded(t *testing.T) {
	source := "{\n  \"lock\": true\n}"
	doc := NewDoc("deno.jsonc", FormatJSONC, []byte(source))
	after, ok := edit(t, doc, Key{"nodeModulesDir"}, String("auto"))
	if !ok {
		t.Fatal("Set planned nothing for a key the file does not state")
	}
	want := "{\n  \"lock\": true,\n  \"nodeModulesDir\": \"auto\"\n}\n"
	if after != want {
		t.Errorf("the edit wrote %q, want %q", after, want)
	}
}
