package crates

import "testing"

func TestScanManifest(t *testing.T) {
	tests := []struct {
		name string
		toml string
		want manifest
	}{
		{name: "empty", toml: ""},
		{
			name: "proc-macro in lib",
			toml: "[package]\nname = \"m\"\n\n[lib]\nproc-macro = true\n",
			want: manifest{procMacro: true},
		},
		{
			name: "underscore spelling",
			toml: "[lib]\nproc_macro = true\n",
			want: manifest{procMacro: true},
		},
		{
			name: "explicit false",
			toml: "[lib]\nproc-macro = false\n",
		},
		{
			name: "trailing comment and odd spacing",
			toml: "[ lib ]\n  proc-macro   =   true   # a comment\n",
			want: manifest{procMacro: true},
		},
		{
			name: "quoted key",
			toml: "[lib]\n\"proc-macro\" = true\n",
			want: manifest{procMacro: true},
		},
		{
			name: "dotted key at the top level",
			toml: "lib.proc-macro = true\npackage.build = \"build.rs\"\n",
			want: manifest{procMacro: true, build: "build.rs"},
		},
		{
			name: "key in another table",
			toml: "[package]\nproc-macro = true\n\n[lib.metadata]\nproc-macro = true\n\n[[lib]]\nproc-macro = true\n",
		},
		{
			name: "build script path",
			toml: "[package]\nname = \"m\"\nbuild = \"build/main.rs\"\n",
			want: manifest{build: "build/main.rs"},
		},
		{
			name: "build script disabled",
			toml: "[package]\nbuild = false\n",
			want: manifest{buildDisabled: true},
		},
		{
			name: "build outside package",
			toml: "[lib]\nbuild = \"build.rs\"\n",
		},
		{
			name: "hash inside the build string",
			toml: "[package]\nbuild = \"bui#ld.rs\" # comment\n",
			want: manifest{build: "bui#ld.rs"},
		},
		{
			name: "single quoted build string",
			toml: "[package]\nbuild = 'build.rs'\n",
			want: manifest{build: "build.rs"},
		},
		{
			name: "multi-line string does not open a table",
			toml: "[package]\ndescription = \"\"\"\n[lib]\nproc-macro = true\n\"\"\"\nbuild = \"build.rs\"\n",
			want: manifest{build: "build.rs"},
		},
		{
			name: "multi-line array in lib is skipped",
			toml: "[lib]\ncrate-type = [\n    \"proc-macro = true\",\n]\nname = \"x\"\n",
		},
		{
			name: "one-line array then a key",
			toml: "[lib]\ncrate-type = [\"lib\"]\nproc-macro = true\n",
			want: manifest{procMacro: true},
		},
		{
			name: "comment lines and windows line endings",
			toml: "# generated\r\n[lib]\r\n# proc-macro = false\r\nproc-macro = true\r\n",
			want: manifest{procMacro: true},
		},
		{
			name: "later table does not leak",
			toml: "[lib]\nproc-macro = true\n\n[package]\nbuild = false\n\n[dependencies]\nproc-macro = false\n",
			want: manifest{procMacro: true, buildDisabled: true},
		},
		{
			name: "cargo normalized paste manifest",
			toml: string(fixtureManifest(t, "paste-1.0.15.crate", "paste-1.0.15")),
			want: manifest{procMacro: true, build: "build.rs"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scanManifest([]byte(tt.toml)); got != tt.want {
				t.Errorf("scanManifest = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestBracketDepthAndStripComment(t *testing.T) {
	depths := []struct {
		line string
		want int
	}{
		{"[", 1},
		{"[\"a]\",", 1},
		{"]", -1},
		{"[\"x\", \"y\"]", 0},
		{"[ # ]", 1},
		{"'[' ]", -1},
	}
	for _, tt := range depths {
		if got := bracketDepth(tt.line); got != tt.want {
			t.Errorf("bracketDepth(%q) = %d, want %d", tt.line, got, tt.want)
		}
	}
	comments := []struct {
		value, want string
	}{
		{"true # yes", "true"},
		{"\"a#b\" # c", "\"a#b\""},
		{"'a#b'", "'a#b'"},
		{"  true  ", "true"},
	}
	for _, tt := range comments {
		if got := stripComment(tt.value); got != tt.want {
			t.Errorf("stripComment(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}
