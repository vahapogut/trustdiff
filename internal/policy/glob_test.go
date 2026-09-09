package policy

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/model"
)

// scalarNode and sequenceNode build the yaml nodes the UnmarshalYAML tests feed in.
func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Line: 7}
}

func sequenceNode(values ...string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Line: 7}
	for _, v := range values {
		n.Content = append(n.Content, scalarNode(v))
	}
	return n
}

func TestParsePattern(t *testing.T) {
	tests := []struct {
		in            string
		wantEcosystem model.Ecosystem
		wantString    string
	}{
		{in: "npm:@myorg/*", wantEcosystem: model.NPM, wantString: "npm:@myorg/*"},
		{in: "pypi:myorg-*", wantEcosystem: model.PyPI, wantString: "pypi:myorg-*"},
		{in: "esbuild", wantEcosystem: "", wantString: "esbuild"},
		{in: "npm:esbuild", wantEcosystem: model.NPM, wantString: "npm:esbuild"},
		{in: "npm:esbuild@0.20.0", wantEcosystem: model.NPM, wantString: "npm:esbuild@0.20.0"},
		{in: "cargo:serde@1.*", wantEcosystem: model.Cargo, wantString: "cargo:serde@1.*"},
		{in: "NPM:Express", wantEcosystem: model.NPM, wantString: "NPM:Express"},
		{in: "  npm:foo  ", wantEcosystem: model.NPM, wantString: "npm:foo"},
		{in: "*", wantEcosystem: "", wantString: "*"},
		{in: "jsr:@std/*", wantEcosystem: model.JSR, wantString: "jsr:@std/*"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParsePattern(tt.in)
			if err != nil {
				t.Fatalf("ParsePattern(%q) error: %v", tt.in, err)
			}
			if got.Ecosystem() != tt.wantEcosystem {
				t.Errorf("Ecosystem() = %q, want %q", got.Ecosystem(), tt.wantEcosystem)
			}
			if got.String() != tt.wantString {
				t.Errorf("String() = %q, want %q", got.String(), tt.wantString)
			}
		})
	}
}

func TestParsePatternRejects(t *testing.T) {
	tests := []struct {
		in      string
		wantErr string
	}{
		{in: "", wantErr: "empty"},
		{in: "   ", wantErr: "empty"},
		{in: "gem:rails", wantErr: "unknown ecosystem"},
		{in: "npm:", wantErr: "empty package name"},
		{in: "**", wantErr: `"**" is not supported`},
		{in: "npm:**", wantErr: `"**" is not supported`},
		{in: "npm:@myorg/**", wantErr: `"**" is not supported`},
		{in: "npm:foo@**", wantErr: `"**" is not supported`},
		{in: "npm:foo bar", wantErr: "whitespace"},
		{in: "npm:foo@", wantErr: "empty version"},
		{in: "npm:[a-", wantErr: "malformed"},
		{in: "npm:foo@[", wantErr: "malformed"},
		{in: "npm:foo:bar", wantErr: "colon"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParsePattern(tt.in)
			if err == nil {
				t.Fatalf("ParsePattern(%q) = %v, want an error containing %q", tt.in, got, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParsePattern(%q) error = %q, want it to contain %q", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestPatternMatch(t *testing.T) {
	tests := []struct {
		pattern string
		ref     model.PackageRef
		want    bool
	}{
		// Scoped npm glob: the star stays inside the scope.
		{pattern: "npm:@myorg/*", ref: model.MustParseRef("npm:@myorg/foo"), want: true},
		{pattern: "npm:@myorg/*", ref: model.MustParseRef("npm:@myorg/foo@1.0.0"), want: true},
		{pattern: "npm:@myorg/*", ref: model.MustParseRef("npm:@other/foo"), want: false},
		{pattern: "npm:@myorg/*", ref: model.MustParseRef("npm:myorg"), want: false},
		// The ecosystem prefix restricts.
		{pattern: "npm:@myorg/*", ref: model.PackageRef{Ecosystem: model.PyPI, Name: "@myorg/foo"}, want: false},
		{pattern: "pypi:myorg-*", ref: model.MustParseRef("pypi:myorg-tools"), want: true},
		{pattern: "pypi:myorg-*", ref: model.MustParseRef("npm:myorg-tools"), want: false},
		// Names are normalized before matching, on both sides.
		{pattern: "pypi:myorg-*", ref: model.MustParseRef("pypi:MyOrg_Tools"), want: true},
		{pattern: "pypi:myorg-*", ref: model.PackageRef{Ecosystem: model.PyPI, Name: "MyOrg_Tools"}, want: true},
		{pattern: "pypi:my_org.*", ref: model.MustParseRef("pypi:my-org-x"), want: true},
		{pattern: "npm:Express", ref: model.MustParseRef("npm:express"), want: true},
		{pattern: "npm:express", ref: model.PackageRef{Ecosystem: model.NPM, Name: "Express"}, want: true},
		{pattern: "cargo:Serde", ref: model.MustParseRef("cargo:serde"), want: false},
		// No prefix matches every ecosystem.
		{pattern: "esbuild", ref: model.MustParseRef("npm:esbuild"), want: true},
		{pattern: "esbuild", ref: model.MustParseRef("pypi:esbuild"), want: true},
		{pattern: "esbuild", ref: model.MustParseRef("cargo:esbuild"), want: true},
		{pattern: "esbuild", ref: model.MustParseRef("npm:esbuild-wasm"), want: false},
		// An exact ref with a version matches that version only.
		{pattern: "npm:esbuild@0.20.0", ref: model.MustParseRef("npm:esbuild@0.20.0"), want: true},
		{pattern: "npm:esbuild@0.20.0", ref: model.MustParseRef("npm:esbuild@0.20.1"), want: false},
		{pattern: "npm:esbuild@0.20.0", ref: model.MustParseRef("npm:esbuild"), want: false},
		{pattern: "cargo:serde@1.*", ref: model.MustParseRef("cargo:serde@1.0.210"), want: true},
		{pattern: "cargo:serde@1.*", ref: model.MustParseRef("cargo:serde@2.0.0"), want: false},
		// A star never crosses a slash, so npm:* leaves scoped packages alone.
		{pattern: "npm:*", ref: model.MustParseRef("npm:express"), want: true},
		{pattern: "npm:*", ref: model.MustParseRef("npm:@types/node"), want: false},
		{pattern: "*", ref: model.MustParseRef("pypi:requests@2.32.3"), want: true},
		{pattern: "npm:ex?ress", ref: model.MustParseRef("npm:express"), want: true},
		{pattern: "npm:ex[a-z]ress", ref: model.MustParseRef("npm:express"), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+" vs "+tt.ref.String(), func(t *testing.T) {
			p := MustParsePattern(tt.pattern)
			if got := p.Match(tt.ref); got != tt.want {
				t.Fatalf("Match(%s) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestPatternYAML(t *testing.T) {
	var got struct {
		Exclude []Pattern `yaml:"exclude"`
	}
	if err := yaml.Unmarshal([]byte("exclude:\n  - \"npm:@myorg/*\"\n  - pypi:myorg-*\n"), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Exclude) != 2 || got.Exclude[0].String() != "npm:@myorg/*" || got.Exclude[1].String() != "pypi:myorg-*" {
		t.Fatalf("Unmarshal = %v", got.Exclude)
	}
	out, err := yaml.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), "npm:@myorg/*") || !strings.Contains(string(out), "pypi:myorg-*") {
		t.Fatalf("Marshal = %q", out)
	}

	err = yaml.Unmarshal([]byte("exclude:\n  - \"npm:**\"\n"), &got)
	if err == nil || !strings.Contains(err.Error(), `"**" is not supported`) || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("Unmarshal(**) error = %v, want the ** error with a line number", err)
	}
	err = yaml.Unmarshal([]byte("exclude:\n  - [npm]\n"), &got)
	if err == nil || !strings.Contains(err.Error(), "want a package pattern") {
		t.Fatalf("Unmarshal(sequence) error = %v, want a kind error", err)
	}
}

func TestMustParsePatternPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustParsePattern did not panic")
		}
	}()
	MustParsePattern("npm:**")
}
