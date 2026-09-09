package manifest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// declaration is one expected dependency, spelled the way the assertions read best:
// the package that is really installed, the alias when there is one, and the range
// as the manifest wrote it.
type declaration struct {
	name      string
	alias     string
	rangeText string
	syntax    Syntax
	table     string
	dev       bool
	optional  bool
	extras    []string
	marker    string
}

// skip is one expected skipped declaration. reason is matched as a substring, so a
// test says what a reader must tell somebody without pinning the whole sentence.
type skip struct {
	name   string
	reason string
}

// readFixture reads one manifest out of testdata, under its real name so that the
// reader is chosen the way it is in a run.
func readFixture(t *testing.T, dir, name string) *Manifest {
	t.Helper()
	path := filepath.Join("testdata", dir, name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := Read(filepath.ToSlash(path), f)
	if err != nil {
		t.Fatalf("Read(%s) = %v", path, err)
	}
	return m
}

func TestReadDeclaresDirectDependencies(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		file    string
		project string
		want    []declaration
		skipped []skip
	}{
		{
			name:    "package.json of a workspace root",
			dir:     "npm-root",
			file:    FormatPackageJSON,
			project: "trustdiff-fixture-app",
			want: []declaration{
				{name: "@scope/ui", rangeText: "~1.2.3", syntax: SyntaxNPM, table: TableDependencies},
				{name: "d3", alias: "d3v3", rangeText: "^3", syntax: SyntaxNPM, table: TableDependencies},
				{name: "express", rangeText: "^4.17.1", syntax: SyntaxNPM, table: TableDependencies},
				{name: "typescript", rangeText: ">=5 <6", syntax: SyntaxNPM, table: TableDevDependencies, dev: true},
				{name: "fsevents", rangeText: "2.x", syntax: SyntaxNPM, table: TableOptionalDependencies, optional: true},
			},
			skipped: []skip{
				{name: "forked", reason: "a git repository"},
				{name: "left-pad", reason: "a path on this machine"},
				{name: "member", reason: "the workspace protocol"},
				{name: "shorthand", reason: "a repository shorthand"},
				{name: "tagged", reason: "dist-tag"},
				{name: "tarball", reason: "a tarball URL"},
			},
		},
		{
			name:    "package.json of a workspace member",
			dir:     "npm-member",
			file:    FormatPackageJSON,
			project: "@trustdiff-fixture/ui",
			want: []declaration{
				{name: "react", rangeText: "^18.2.0", syntax: SyntaxNPM, table: TableDependencies},
				{name: "vitest", rangeText: "1.2.3 - 2", syntax: SyntaxNPM, table: TableDevDependencies, dev: true},
			},
		},
		{
			name:    "a manifest with no dependencies at all",
			dir:     "npm-empty",
			file:    FormatPackageJSON,
			project: "trustdiff-fixture-empty",
		},
		{
			name:    "a manifest whose every dependency is exotic",
			dir:     "npm-exotic",
			file:    FormatPackageJSON,
			project: "trustdiff-fixture-exotic",
			skipped: []skip{
				{name: "forked", reason: "a git repository"},
				{name: "local", reason: "a path on this machine"},
				{name: "member", reason: "the workspace protocol"},
				{name: "numeric", reason: "not a string"},
			},
		},
		{
			name:    "pyproject.toml with PEP 621 dependencies",
			dir:     "pep621",
			file:    FormatPyproject,
			project: "trustdiff-fixture",
			want: []declaration{
				{name: "requests", rangeText: ">=2.31,<3", syntax: SyntaxPEP440, table: TableProjectDependencies},
				{
					name: "urllib3", rangeText: ">= 1.26", syntax: SyntaxPEP440, table: TableProjectDependencies,
					extras: []string{"socks", "brotli"}, marker: "python_version < '3.12'",
				},
				{name: "packaging", rangeText: "", syntax: SyntaxPEP440, table: TableProjectDependencies},
				{name: "pinned", rangeText: "== 24.1", syntax: SyntaxPEP440, table: TableProjectDependencies},
				{name: "pytest", rangeText: "~=7.4", syntax: SyntaxPEP440, table: "project.optional-dependencies.dev", optional: true},
				{name: "sphinx", rangeText: ">=7", syntax: SyntaxPEP440, table: "project.optional-dependencies.docs", optional: true},
			},
			skipped: []skip{
				{name: "vendored", reason: "a direct reference"},
			},
		},
		{
			name:    "pyproject.toml with Poetry tables",
			dir:     "poetry",
			file:    FormatPyproject,
			project: "trustdiff-fixture-poetry",
			want: []declaration{
				{name: "attrs", rangeText: "*", syntax: SyntaxPoetry, table: TablePoetryDependencies},
				{name: "click", rangeText: "~8.1", syntax: SyntaxPoetry, table: TablePoetryDependencies, optional: true},
				{name: "requests", rangeText: "^2.31", syntax: SyntaxPoetry, table: TablePoetryDependencies},
				{
					name: "rich", rangeText: ">=13,<14", syntax: SyntaxPoetry, table: TablePoetryDependencies,
					extras: []string{"jupyter"}, marker: "sys_platform == 'linux'",
				},
				{name: "black", rangeText: "^24", syntax: SyntaxPoetry, table: TablePoetryDev, dev: true},
				{name: "pytest", rangeText: "^7.4", syntax: SyntaxPoetry, table: "tool.poetry.group.dev.dependencies", dev: true},
			},
			skipped: []skip{
				{name: "archived", reason: "an archive URL"},
				{name: "forked", reason: "a git repository"},
				{name: "local", reason: "a path on this machine"},
				{name: "python", reason: "the interpreter"},
			},
		},
		{
			name:    "Cargo.toml of a package",
			dir:     "cargo-package",
			file:    FormatCargoToml,
			project: "trustdiff-fixture",
			want: []declaration{
				{name: "rand", rangeText: "0.8.5", syntax: SyntaxCargo, table: TableDependencies},
				{name: "serde_json", alias: "renamed", rangeText: "1", syntax: SyntaxCargo, table: TableDependencies},
				{name: "serde", rangeText: "1.0", syntax: SyntaxCargo, table: TableDependencies},
				{name: "criterion", rangeText: "0.5", syntax: SyntaxCargo, table: TableCargoDev, dev: true},
				{name: "cc", rangeText: "^1.0", syntax: SyntaxCargo, table: TableCargoBuild},
			},
			skipped: []skip{
				{name: "featureless", reason: "names no version"},
				{name: "gitdep", reason: "a git repository"},
				{name: "localdep", reason: "a path on this machine"},
				{name: "private", reason: `pinned to the "internal" registry`},
			},
		},
		{
			name:    "Cargo.toml of a workspace root",
			dir:     "cargo-workspace",
			file:    FormatCargoToml,
			project: "trustdiff-fixture-root",
			want: []declaration{
				{name: "serde", rangeText: "1.0.203", syntax: SyntaxCargo, table: TableDependencies},
				{name: "serde", rangeText: "1.0.203", syntax: SyntaxCargo, table: TableCargoWorkspace},
				{name: "tokio", rangeText: "1.38", syntax: SyntaxCargo, table: TableCargoWorkspace},
			},
			skipped: []skip{
				{name: "anyhow", reason: "inherited from the workspace"},
			},
		},
		{
			name:    "a Cargo.toml whose every dependency is exotic",
			dir:     "cargo-exotic",
			file:    FormatCargoToml,
			project: "trustdiff-fixture-exotic",
			skipped: []skip{
				{name: "gitdep", reason: "a git repository"},
				{name: "localdep", reason: "a path on this machine"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := readFixture(t, tt.dir, tt.file)
			if m.Name != tt.project {
				t.Errorf("project name = %q, want %q", m.Name, tt.project)
			}
			if m.Format != tt.file {
				t.Errorf("format = %q, want %q", m.Format, tt.file)
			}
			assertDeclarations(t, m.Dependencies, tt.want)
			assertSkipped(t, m.Skipped, tt.skipped)
		})
	}
}

// assertDeclarations compares what a reader produced against what the fixture
// declares, field by field, in order: the order is part of the answer, because two
// runs over one file must report the same subjects in the same order.
func assertDeclarations(t *testing.T, got []Declaration, want []declaration) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("read %d declarations, want %d:\n%s", len(got), len(want), formatDeclarations(got))
	}
	for i := range want {
		g, w := &got[i], &want[i]
		if g.Ref.Name != w.name || g.Alias != w.alias || g.Range != w.rangeText || g.Syntax != w.syntax {
			t.Errorf("declaration %d = %s (alias %q) %q as %s, want %s (alias %q) %q as %s",
				i, g.Ref.Name, g.Alias, g.Range, g.Syntax, w.name, w.alias, w.rangeText, w.syntax)
		}
		if g.Table != w.table || g.Dev != w.dev || g.Optional != w.optional {
			t.Errorf("declaration %d (%s) from %q dev=%v optional=%v, want %q dev=%v optional=%v",
				i, g.Ref.Name, g.Table, g.Dev, g.Optional, w.table, w.dev, w.optional)
		}
		if !slices.Equal(g.Extras, w.extras) {
			t.Errorf("declaration %d (%s) extras = %v, want %v", i, g.Ref.Name, g.Extras, w.extras)
		}
		if g.Marker != w.marker {
			t.Errorf("declaration %d (%s) marker = %q, want %q", i, g.Ref.Name, g.Marker, w.marker)
		}
	}
}

// assertSkipped compares the skipped declarations, matching each reason as a
// substring so the assertion is about what a reader is told and not about wording.
func assertSkipped(t *testing.T, got []Skipped, want []skip) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("skipped %d declarations, want %d:\n%s", len(got), len(want), formatSkipped(got))
	}
	for i := range want {
		if got[i].Name != want[i].name || !strings.Contains(got[i].Reason, want[i].reason) {
			t.Errorf("skipped %d = %q, want %s skipped for %q", i, got[i].String(), want[i].name, want[i].reason)
		}
	}
}

func formatDeclarations(declarations []Declaration) string {
	var b strings.Builder
	for i := range declarations {
		d := &declarations[i]
		b.WriteString("  " + d.Ref.Name + " " + d.Range + " (" + d.Table + ")\n")
	}
	return b.String()
}

func formatSkipped(skipped []Skipped) string {
	var b strings.Builder
	for _, s := range skipped {
		b.WriteString("  " + s.String() + "\n")
	}
	return b.String()
}

// Every spelling a package.json dependency value can take, and what it resolves to
// or is skipped for. The protocols are the whole reason a manifest cannot simply be
// handed to a registry.
func TestNPMSpecClassifiesEveryValue(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		installed string
		rangeText string
		reason    string
	}{
		{name: "a caret range", value: "^4.17.1", installed: "lib", rangeText: "^4.17.1"},
		{name: "an empty range is any version", value: "", installed: "lib", rangeText: "*"},
		{name: "an alias", value: "npm:d3@^3", installed: "d3", rangeText: "^3"},
		{name: "an alias of a scoped package", value: "npm:@scope/pkg@~1.0", installed: "@scope/pkg", rangeText: "~1.0"},
		{name: "an alias with no range", value: "npm:d3", installed: "d3", rangeText: "*"},
		{name: "an alias naming nothing", value: "npm:", reason: "names no package"},
		{name: "a file path", value: "file:../left-pad", reason: "a path on this machine"},
		{name: "a link", value: "link:../ui", reason: "a link to a directory"},
		{name: "a portal", value: "portal:../ui", reason: "a portal to a directory"},
		{name: "the workspace protocol", value: "workspace:^", reason: "the workspace protocol"},
		{name: "a patch", value: "patch:lib@1.0.0#./fix.patch", reason: "a patch of another dependency"},
		{name: "a git URL", value: "git+https://example.test/r.git", reason: "a git repository"},
		{name: "a git scheme", value: "git://example.test/r.git", reason: "a git repository"},
		{name: "an ssh remote", value: "ssh://git@example.test/r.git", reason: "over ssh"},
		{name: "a GitHub shorthand with a protocol", value: "github:user/repo", reason: "on GitHub"},
		{name: "a GitLab shorthand", value: "gitlab:user/repo", reason: "on GitLab"},
		{name: "a Bitbucket shorthand", value: "bitbucket:user/repo", reason: "on Bitbucket"},
		{name: "a gist", value: "gist:11081aaa281", reason: "a gist"},
		{name: "a tarball URL", value: "https://example.test/lib-1.0.0.tgz", reason: "a tarball URL"},
		{name: "a bare repository shorthand", value: "user/repo#v1", reason: "a repository shorthand"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installed, rangeText, reason := npmSpec("lib", tt.value)
			if tt.reason != "" {
				if !strings.Contains(reason, tt.reason) {
					t.Fatalf("npmSpec(%q) reason = %q, want it to say %q", tt.value, reason, tt.reason)
				}
				return
			}
			if reason != "" {
				t.Fatalf("npmSpec(%q) was skipped for %q", tt.value, reason)
			}
			if installed != tt.installed || rangeText != tt.rangeText {
				t.Fatalf("npmSpec(%q) = %q %q, want %q %q", tt.value, installed, rangeText, tt.installed, tt.rangeText)
			}
		})
	}
}

// A manifest is read for the ecosystem its name belongs to, and nothing else is
// read at all.
func TestForRecognizesTheManifestsAndNothingElse(t *testing.T) {
	tests := []struct {
		path   string
		format string
	}{
		{path: "package.json", format: FormatPackageJSON},
		{path: "packages/ui/package.json", format: FormatPackageJSON},
		{path: `C:\projects\app\PACKAGE.JSON`, format: FormatPackageJSON},
		{path: "pyproject.toml", format: FormatPyproject},
		{path: "Cargo.toml", format: FormatCargoToml},
		{path: "cargo.toml", format: FormatCargoToml},
		{path: "my-package.json", format: ""},
		{path: "Cargo.lock", format: ""},
		{path: "package-lock.json", format: ""},
		{path: "setup.py", format: ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			format, ok := For(tt.path)
			if ok != (tt.format != "") || format != tt.format {
				t.Fatalf("For(%q) = %q, %v; want %q", tt.path, format, ok, tt.format)
			}
		})
	}
}

// A manifest that is not readable fails the whole read: there is nothing to
// evaluate and saying so is the only honest answer.
func TestReadRefusesWhatItCannotRead(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want string
	}{
		{
			name: "a package.json that is not JSON",
			path: "testdata/npm-invalid/package.json",
			want: "not a package.json this reader can parse",
		},
		{
			name: "a pyproject.toml that is not TOML",
			path: "pyproject.toml",
			body: "[project\nname = ",
			want: "not a pyproject.toml this reader can parse",
		},
		{
			name: "a Cargo.toml that is not TOML",
			path: "Cargo.toml",
			body: "[dependencies\n",
			want: "not a Cargo.toml this reader can parse",
		},
		{
			name: "a file no reader knows",
			path: "setup.py",
			body: "",
			want: "no manifest reader for this file name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.body
			if tt.path == "testdata/npm-invalid/package.json" {
				data, err := os.ReadFile(tt.path)
				if err != nil {
					t.Fatal(err)
				}
				body = string(data)
			}
			_, err := Read(tt.path, strings.NewReader(body))
			if err == nil {
				t.Fatalf("Read(%s) succeeded, want an error", tt.path)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Read(%s) = %v, want it to say %q", tt.path, err, tt.want)
			}
			if !strings.Contains(err.Error(), tt.path) {
				t.Fatalf("Read(%s) = %v, want the message to name the file", tt.path, err)
			}
		})
	}
}

// The ecosystem of every declaration is the file's, and PyPI names are normalized
// so that a manifest's spelling and the registry's compare equal.
func TestReadNormalizesNamesPerEcosystem(t *testing.T) {
	m, err := Read("pyproject.toml", strings.NewReader("[project]\nname = \"x\"\ndependencies = [\"Typing_Extensions>=4\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Dependencies) != 1 {
		t.Fatalf("read %d declarations, want 1", len(m.Dependencies))
	}
	got := m.Dependencies[0].Ref
	want := model.PackageRef{Ecosystem: model.PyPI, Name: "typing-extensions"}
	if got != want {
		t.Fatalf("ref = %v, want %v", got, want)
	}
}

// A range no grammar reads is a skipped declaration carrying the text, never a
// declaration nobody can resolve and never a guess.
func TestReadSkipsARangeItCannotParse(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want string
	}{
		{
			name: "an npm range with two hyphen sides and a comparator",
			path: "package.json",
			body: `{"dependencies":{"lib":">=1 2.0.0 - 3.0.0"}}`,
			want: "hyphen range",
		},
		{
			name: "an npm range that is nonsense",
			path: "package.json",
			body: `{"dependencies":{"lib":"^^1.2.3"}}`,
			want: "not a version range this reader parses",
		},
		{
			name: "a PEP 440 specifier with no operator",
			path: "pyproject.toml",
			body: "[project]\ndependencies = [\"lib 1.2.3\"]\n",
			want: "names no operator",
		},
		{
			name: "a Cargo requirement that is nonsense",
			path: "Cargo.toml",
			body: "[dependencies]\nlib = \"~>1.2\"\n",
			want: "not a version requirement this reader parses",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Read(tt.path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Dependencies) != 0 {
				t.Fatalf("declared %d dependencies, want none:\n%s", len(m.Dependencies), formatDeclarations(m.Dependencies))
			}
			if len(m.Skipped) != 1 {
				t.Fatalf("skipped %d declarations, want 1:\n%s", len(m.Skipped), formatSkipped(m.Skipped))
			}
			if !strings.Contains(m.Skipped[0].Reason, tt.want) {
				t.Fatalf("skipped for %q, want it to say %q", m.Skipped[0].Reason, tt.want)
			}
			if m.Skipped[0].Range == "" {
				t.Error("a skipped declaration must carry the text of the range it could not read")
			}
		})
	}
}
