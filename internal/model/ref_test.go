package model

import (
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		in      string
		want    PackageRef
		wantErr string
	}{
		{in: "npm:express@4.19.2", want: PackageRef{NPM, "express", "4.19.2"}},
		{in: "npm:express", want: PackageRef{NPM, "express", ""}},
		{in: "npm:@types/node@20.0.0", want: PackageRef{NPM, "@types/node", "20.0.0"}},
		{in: "npm:@types/node", want: PackageRef{NPM, "@types/node", ""}},
		// npm names keep their case: JSONStream and jsonstream are different packages.
		{in: "NPM:Express", want: PackageRef{NPM, "Express", ""}},
		{in: "npm:JSONStream@1.3.5", want: PackageRef{NPM, "JSONStream", "1.3.5"}},
		{in: "pypi:requests@2.32.3", want: PackageRef{PyPI, "requests", "2.32.3"}},
		{in: "pypi:Typing_Extensions", want: PackageRef{PyPI, "typing-extensions", ""}},
		{in: "pypi:zope.interface@6.0", want: PackageRef{PyPI, "zope-interface", "6.0"}},
		{in: "pypi:a--b__c..d", want: PackageRef{PyPI, "a-b-c-d", ""}},
		{in: "cargo:serde@1.0.210", want: PackageRef{Cargo, "serde", "1.0.210"}},
		{in: "cargo:Serde_Json", want: PackageRef{Cargo, "Serde_Json", ""}},
		{in: "jsr:@std/path@1.0.0", want: PackageRef{JSR, "@std/path", "1.0.0"}},
		{in: "  npm:express@1.0.0  ", want: PackageRef{NPM, "express", "1.0.0"}},
		{in: "npm:lodash@4.17.21-beta.1+build.5", want: PackageRef{NPM, "lodash", "4.17.21-beta.1+build.5"}},

		{in: "express", wantErr: "want <ecosystem>:<name>[@<version>]"},
		{in: "gem:rails", wantErr: "unknown ecosystem"},
		{in: "npm:", wantErr: "empty package name"},
		{in: "npm:@1.0.0", wantErr: "scoped name must look like @scope/name"},
		{in: "npm:express@", wantErr: "empty version after @"},
		{in: "npm:@types/node@", wantErr: "empty version after @"},
		{in: "npm:@types", wantErr: "scoped name must look like @scope/name"},
		{in: "npm:@/node", wantErr: "scoped name must look like @scope/name"},
		{in: "npm:foo/bar", wantErr: "contains a slash"},
		{in: "pypi:foo/bar", wantErr: "contains a slash"},
		{in: "npm:foo bar", wantErr: "illegal characters"},
		{in: "npm:express@1.0 .0", wantErr: "contains whitespace"},
		{in: "pypi:@foo", wantErr: "must not start with @"},
		{in: "cargo:@scope/name", wantErr: "must not start with @"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseRef(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseRef(%q) = %+v, want error containing %q", tt.in, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseRef(%q) error = %q, want it to contain %q", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRef(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("ParseRef(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestPackageRefStringRoundTrips(t *testing.T) {
	for _, in := range []string{"npm:express@4.19.2", "npm:@types/node", "pypi:requests", "cargo:serde@1.0.0", "jsr:@std/path@1.0.0"} {
		ref := MustParseRef(in)
		if got := ref.String(); got != in {
			t.Errorf("String() = %q, want %q", got, in)
		}
		again, err := ParseRef(ref.String())
		if err != nil || again != ref {
			t.Errorf("re-parse of %q = %+v, %v; want %+v", ref.String(), again, err, ref)
		}
	}
}

func TestPackageRefHelpers(t *testing.T) {
	ref := MustParseRef("npm:express@4.19.2")
	if !ref.HasVersion() {
		t.Fatal("HasVersion() = false, want true")
	}
	pkg := ref.Package()
	if pkg.HasVersion() || pkg.String() != "npm:express" {
		t.Fatalf("Package() = %+v", pkg)
	}
	if got := pkg.WithVersion("5.0.0").String(); got != "npm:express@5.0.0" {
		t.Fatalf("WithVersion() = %q", got)
	}
	if ref.Version != "4.19.2" {
		t.Fatal("WithVersion must not mutate the receiver")
	}
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		eco  Ecosystem
		in   string
		want string
	}{
		{PyPI, "Django", "django"},
		{PyPI, "typing_extensions", "typing-extensions"},
		{PyPI, "zope.interface", "zope-interface"},
		{PyPI, "A__b-.-C", "a-b-c"},
		{NPM, "@Scope/Name", "@Scope/Name"},
		{NPM, "JSONStream", "JSONStream"},
		{Cargo, "Serde_Json", "Serde_Json"},
		{JSR, "@std/Path", "@std/Path"},
	}
	for _, tt := range tests {
		if got := NormalizeName(tt.eco, tt.in); got != tt.want {
			t.Errorf("NormalizeName(%s, %q) = %q, want %q", tt.eco, tt.in, got, tt.want)
		}
	}
}

func TestParseEcosystem(t *testing.T) {
	for _, in := range []string{"npm", "NPM", " PyPI ", "cargo", "deno", "jsr"} {
		if _, err := ParseEcosystem(in); err != nil {
			t.Errorf("ParseEcosystem(%q) error: %v", in, err)
		}
	}
	if _, err := ParseEcosystem("maven"); err == nil || !strings.Contains(err.Error(), "npm, pypi, cargo, deno, jsr") {
		t.Errorf("ParseEcosystem(maven) error = %v, want the list of known ecosystems", err)
	}
	if got := Ecosystems(); len(got) != 5 || got[0] != NPM {
		t.Errorf("Ecosystems() = %v", got)
	}
}

func TestMustParseRefPanicsOnBadInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustParseRef did not panic")
		}
	}()
	MustParseRef("nope")
}
