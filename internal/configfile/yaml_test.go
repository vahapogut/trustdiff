package configfile

import "testing"

func TestYAMLGetReadsTheShapesRulesCompare(t *testing.T) {
	pnpm := load(t, "pnpm-workspace.yaml", FormatYAML)
	dependabot := load(t, "dependabot.yml", FormatYAML)
	yarn := load(t, "yarnrc.yml", FormatYAML)
	tests := []struct {
		name  string
		doc   *Doc
		key   Key
		kind  Kind
		text  string
		items []string
		line  int
		end   int
	}{
		{name: "an integer", doc: pnpm, key: Key{"minimumReleaseAge"}, kind: KindInt, text: "4320", line: 6, end: 6},
		{
			name: "a block sequence of scalars", doc: pnpm, key: Key{"packages"},
			kind: KindList, items: []string{"packages/*", "apps/*"}, line: 1, end: 3,
		},
		{name: "a boolean", doc: yarn, key: Key{"enableScripts"}, kind: KindBool, text: "false", line: 9, end: 9},
		{
			name: "a key two mappings down", doc: dependabot, key: Key{"registries", "npm-acme", "url"},
			kind: KindString, text: "https://npm.acme.dev", line: 6, end: 6,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Get(tc.doc, tc.key)
			if err != nil {
				t.Fatalf("Get(%s): %v", tc.key, err)
			}
			if v.Kind != tc.kind || v.Text != tc.text || v.Line != tc.line || v.EndLine != tc.end || !v.Editable {
				t.Errorf("Get(%s) = kind %q text %q lines %d to %d editable %v, want kind %q text %q lines %d to %d, editable",
					tc.key, v.Kind, v.Text, v.Line, v.EndLine, v.Editable, tc.kind, tc.text, tc.line, tc.end)
			}
			if !equalLines(v.Items, tc.items) {
				t.Errorf("Get(%s).Items = %q, want %q", tc.key, v.Items, tc.items)
			}
		})
	}
}

func TestYAMLGetMissingKeysAreNotErrors(t *testing.T) {
	wantMissing(t, load(t, "pnpm-workspace.yaml", FormatYAML), Key{"ignoredBuiltDependencies"})
	wantMissing(t, load(t, "dependabot.yml", FormatYAML), Key{"registries", "npm-acme", "replaces-base"})
	wantMissing(t, load(t, "dependabot.yml", FormatYAML), Key{"registries", "other", "url"})
}

func TestYAMLSetKeepsTheCommentAboveAndTheBlankLineBelow(t *testing.T) {
	doc := load(t, "pnpm-workspace.yaml", FormatYAML)
	before := doc.Text()
	after, ok := edit(t, doc, Key{"minimumReleaseAge"}, Int(7200))
	if !ok {
		t.Fatal("Set planned nothing on a value that has to change")
	}
	wantChange(t, before, after, []string{"minimumReleaseAge: 4320"}, []string{"minimumReleaseAge: 7200"})
}

func TestYAMLSetRewritesABlockSequenceAtItsOwnIndentation(t *testing.T) {
	doc := load(t, "pnpm-workspace.yaml", FormatYAML)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"onlyBuiltDependencies"}, List("esbuild"))
	wantChange(t, before, after, []string{"  - sharp"}, nil)

	doc = load(t, "pnpm-workspace.yaml", FormatYAML)
	before = doc.Text()
	after, _ = edit(t, doc, Key{"onlyBuiltDependencies"}, List("esbuild", "sharp", "fsevents"))
	wantChange(t, before, after, nil, []string{"  - fsevents"})
}

func TestYAMLSetRewritesAFlowSequenceInPlace(t *testing.T) {
	doc := load(t, "flow.yaml", FormatYAML)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"oneline"}, List("z"))
	wantChange(t, before, after, []string{"oneline: [x, y]"}, []string{"oneline: [z]"})
}

func TestYAMLSetKeepsACommentOnTheSameLine(t *testing.T) {
	doc := load(t, "flow.yaml", FormatYAML)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"count"}, Int(5))
	wantChange(t, before, after,
		[]string{"count: 3 # how many of them there are"},
		[]string{"count: 5 # how many of them there are"})
}

func TestYAMLSetAScalarWhereABlockSequenceWas(t *testing.T) {
	doc := load(t, "pnpm-workspace.yaml", FormatYAML)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"onlyBuiltDependencies"}, String("none"))
	// The sequence's own lines go with it and the value moves up beside its key,
	// which is the only shape a scalar has in a block mapping.
	wantChange(t, before, after,
		[]string{"onlyBuiltDependencies:", "  - esbuild", "  - sharp"},
		[]string{"onlyBuiltDependencies: none"})
}

func TestYAMLInsertAddsToTheEndOfTheMappingItBelongsTo(t *testing.T) {
	tests := []struct {
		name string
		file string
		key  Key
		want Literal
		now  []string
	}{
		{
			name: "a key of the file", file: "pnpm-workspace.yaml",
			key: Key{"ignoredBuiltDependencies"}, want: List("fsevents"),
			now: []string{"ignoredBuiltDependencies:", "  - fsevents"},
		},
		{
			name: "a key two mappings down", file: "dependabot.yml",
			key: Key{"registries", "npm-acme", "replaces-base"}, want: Bool(true),
			now: []string{"    replaces-base: true"},
		},
		{
			name: "a mapping the file does not have yet", file: "dependabot.yml",
			key: Key{"registries", "other", "url"}, want: String("https://npm.other.dev"),
			now: []string{"  other:", `    url: "https://npm.other.dev"`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := load(t, tc.file, FormatYAML)
			before := doc.Text()
			after, ok := edit(t, doc, tc.key, tc.want)
			if !ok {
				t.Fatal("Set planned nothing for a key the file does not state")
			}
			wantChange(t, before, after, nil, tc.now)
		})
	}
}

func TestYAMLSetInsideAFlowMappingOnOneLine(t *testing.T) {
	doc := load(t, "flow.yaml", FormatYAML)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"single", "a"}, Int(9))
	wantChange(t, before, after, []string{"single: {a: 1}"}, []string{"single: {a: 9}"})
}

func TestYAMLSetReplacesAQuotedScalarWithTheQuotesItNeeds(t *testing.T) {
	doc := load(t, "flow.yaml", FormatYAML)
	before := doc.Text()
	after, _ := edit(t, doc, Key{"label"}, String("c: d"))
	wantChange(t, before, after, []string{`label: "a b"`}, []string{`label: "c: d"`})
}

func TestYAMLInsertRefusesAMappingWrittenInFlowStyle(t *testing.T) {
	doc := load(t, "flow.yaml", FormatYAML)
	wantRefused(t, doc, Key{"single", "b"}, Int(2), "written as a flow mapping")
}

func TestYAMLSetOnAnAlreadyCorrectValueDoesNothing(t *testing.T) {
	pnpm := load(t, "pnpm-workspace.yaml", FormatYAML)
	wantIdempotent(t, pnpm, Key{"minimumReleaseAge"}, Int(4320))
	wantIdempotent(t, pnpm, Key{"packages"}, List("packages/*", "apps/*"))
	wantIdempotent(t, load(t, "yarnrc.yml", FormatYAML), Key{"enableScripts"}, Bool(false))
	wantIdempotent(t, load(t, "flow.yaml", FormatYAML), Key{"oneline"}, List("x", "y"))
	wantIdempotent(t, load(t, "dependabot.yml", FormatYAML), Key{"registries", "npm-acme", "url"}, String("https://npm.acme.dev"))
}

func TestYAMLRefusesTheConstructsItWillNotWriteInto(t *testing.T) {
	tests := []struct {
		name  string
		file  string
		key   Key
		want  Literal
		names string
	}{
		{name: "an anchor", file: "yarnrc.yml", key: Key{"defaults"}, want: Bool(true), names: "an anchor, &defaults"},
		{
			name: "a mapping reached through an anchor", file: "yarnrc.yml",
			key: Key{"defaults", "npmAlwaysAuth"}, want: Bool(false), names: "an anchor, &defaults",
		},
		{
			name: "a mapping that merges another one", file: "yarnrc.yml",
			key: Key{"npmScopes", "acme", "npmRegistryServer"}, want: String("https://example.test"),
			names: "a merge key, <<",
		},
		{name: "a block scalar", file: "yarnrc.yml", key: Key{"notice"}, want: String("no"), names: "a block scalar written with |"},
		{name: "a folded scalar", file: "flow.yaml", key: Key{"folded"}, want: String("no"), names: "a block scalar written with >"},
		{
			name: "a flow sequence over two lines", file: "flow.yaml",
			key: Key{"tags"}, want: List("c"), names: "a flow sequence that spans lines",
		},
		{
			name: "a flow mapping over two lines", file: "flow.yaml",
			key: Key{"inline"}, want: String("no"), names: "a flow mapping that spans lines",
		},
		{
			name: "a key inside a flow mapping over two lines", file: "flow.yaml",
			key: Key{"inline", "a"}, want: Int(9), names: "a flow mapping that spans lines",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := load(t, tc.file, FormatYAML)
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

func TestYAMLReportsAFileItCannotParse(t *testing.T) {
	doc := NewDoc("pnpm-workspace.yaml", FormatYAML, []byte("packages:\n  - a\n - b\n"))
	if _, err := Get(doc, Key{"packages"}); err == nil {
		t.Error("Get read a file the parser rejects, and should have said so")
	}
}
