package uv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

const pypiFiles = "https://files.pythonhosted.org/packages/"

// parseFixture reads a file from testdata with the parser under test.
func parseFixture(t *testing.T, name string) *lockfile.Lockfile {
	t.Helper()
	path := filepath.Join("testdata", name)
	f, err := os.Open(path) // #nosec G304 -- the path is a test fixture in this package
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	lf, err := Parser{}.Parse(path, f)
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return lf
}

// entryOf returns the entry with this ref, and fails when the lockfile has none.
func entryOf(t *testing.T, lf *lockfile.Lockfile, ref string) lockfile.Entry {
	t.Helper()
	for _, e := range lf.Entries {
		if e.Ref.String() == ref {
			return e
		}
	}
	t.Fatalf("no entry for %s in %s", ref, lf.Path)
	return lockfile.Entry{}
}

func TestDetectMatchesTheFileNameOnly(t *testing.T) {
	tests := []struct {
		base string
		want bool
	}{
		{base: "uv.lock", want: true},
		{base: "cargo.lock", want: false},
		{base: "poetry.lock", want: false},
		{base: "my-uv.lock", want: false},
		{base: "", want: false},
	}
	for _, tt := range tests {
		if got := (Parser{}).Detect(tt.base); got != tt.want {
			t.Errorf("Detect(%q) = %v, want %v", tt.base, got, tt.want)
		}
	}
}

func TestParserIsRegistered(t *testing.T) {
	p, ok := lockfile.For("some/project/uv.lock")
	if !ok {
		t.Fatal("lockfile.For(uv.lock) found no parser")
	}
	if p.Name() != Format {
		t.Fatalf("registered parser is %q, want %q", p.Name(), Format)
	}
	if _, ok := lockfile.For("SOME/PROJECT/UV.LOCK"); !ok {
		t.Error("lockfile.For(UV.LOCK) found no parser")
	}
}

func TestParseVirtualProjectLockfile(t *testing.T) {
	lf := parseFixture(t, "uv-fastapi-example.uv.lock")

	if lf.Format != Format || lf.Ecosystem != model.PyPI {
		t.Errorf("Format = %q, Ecosystem = %q", lf.Format, lf.Ecosystem)
	}
	if lf.Version != "1" {
		t.Errorf("Version = %q, want 1", lf.Version)
	}
	// The file holds 35 packages; the project itself is not an installed one.
	if len(lf.Entries) != 34 {
		t.Errorf("read %d entries, want 34", len(lf.Entries))
	}
	wantDrop := `line 406: "uv-fastapi-example" is the project itself (virtual = "."), not an installed package`
	if len(lf.Dropped) != 1 || lf.Dropped[0] != wantDrop {
		t.Errorf("dropped %v, want [%s]", lf.Dropped, wantDrop)
	}

	tests := []struct {
		what string
		ref  string
		want lockfile.Entry
	}{
		{
			what: "the package the project asks for",
			ref:  "pypi:fastapi@0.112.1",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:fastapi@0.112.1"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "2c/09/71a961740a1121d7cc90c99036cc3fbb507bf0c69860d08d4388f842196b/fastapi-0.112.1.tar.gz",
				Integrity: "sha256:b2537146f8c23389a7faa8b03d0bd38d4986e6983874557d95eed2acc46448ef",
				Direct:    true,
				Line:      82,
			},
		},
		{
			what: "the first entry of the file, which nothing asks for directly",
			ref:  "pypi:annotated-types@0.7.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:annotated-types@0.7.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "ee/67/531ea369ba64dcff5ec9c3402f9f51bf748cec26dde048a2f973a4eea7f5/annotated_types-0.7.0.tar.gz",
				Integrity: "sha256:aff07c09a53a08bc8cfccb9c85b05f1aa9a2a6f23728d790723543408344ce89",
				Line:      8,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
}

func TestParseEditableProjectLockfileWithDependencyGroup(t *testing.T) {
	lf := parseFixture(t, "uv-docker-example.uv.lock")

	// A revision changes nothing the parser reads; the format version is still 1.
	if lf.Version != "1" {
		t.Errorf("Version = %q, want 1", lf.Version)
	}
	// An editable project is installed, so unlike a virtual one it stays an entry.
	if len(lf.Entries) != 42 || len(lf.Dropped) != 0 {
		t.Fatalf("read %d entries and dropped %v, want 42 entries and no drops", len(lf.Entries), lf.Dropped)
	}

	tests := []struct {
		what string
		ref  string
		want lockfile.Entry
	}{
		{
			what: "the project, installed from its own directory",
			ref:  "pypi:uv-docker-example@0.1.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:uv-docker-example@0.1.0"),
				Source:   lockfile.SourcePath,
				Resolved: ".",
				Line:     707,
			},
		},
		{
			what: "a runtime dependency of the project",
			ref:  "pypi:fastapi@0.118.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:fastapi@0.118.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "28/3c/2b9345a6504e4055eaa490e0b41c10e338ad61d9aeaae41d97807873cdf2/fastapi-0.118.0.tar.gz",
				Integrity: "sha256:5e81654d98c4d2f53790a7d32d25a7353b30c81441be7d0958a26b5d761fa1c8",
				Direct:    true,
				Line:      80,
			},
		},
		{
			what: "a package the project asks for in its dev group",
			ref:  "pypi:ruff@0.13.3",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:ruff@0.13.3"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "c7/8e/f9f9ca747fea8e3ac954e3690d4698c9737c23b51731d02df999c150b1c9/ruff-0.13.3.tar.gz",
				Integrity: "sha256:5b0ba0db740eefdfbcce4299f49e9eaefc643d4d007749d77d047c2bab19908e",
				Direct:    true,
				Dev:       true,
				Line:      592,
			},
		},
		{
			what: "the other one, which fastapi also pulls in but the project asks for",
			ref:  "pypi:fastapi-cli@0.0.13",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:fastapi-cli@0.0.13"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "32/4e/3f61850012473b097fc5297d681bd85788e186fadb8555b67baf4c7707f4/fastapi_cli-0.0.13.tar.gz",
				Integrity: "sha256:312addf3f57ba7139457cf0d345c03e2170cc5a034057488259c33cd7e494529",
				Direct:    true,
				Dev:       true,
				Line:      104,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
}

func TestParseReadsEverySourceKind(t *testing.T) {
	lf := parseFixture(t, "sources.uv.lock")

	if lf.Version != "1" {
		t.Errorf("Version = %q, want 1", lf.Version)
	}
	// Seventeen packages, one of which is the virtual project.
	if len(lf.Entries) != 16 {
		t.Fatalf("read %d entries, want 16", len(lf.Entries))
	}
	wantDrop := `line 24: "example-project" is the project itself (virtual = "."), not an installed package`
	if len(lf.Dropped) != 1 || lf.Dropped[0] != wantDrop {
		t.Errorf("dropped %v, want [%s]", lf.Dropped, wantDrop)
	}

	tests := []struct {
		what string
		ref  string
		want lockfile.Entry
	}{
		{
			what: "a workspace member, installed in place",
			ref:  "pypi:editable-member@0.2.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:editable-member@0.2.0"),
				Source:   lockfile.SourcePath,
				Resolved: "packages/editable",
				Line:     16,
			},
		},
		{
			what: "a PyPI name is normalized on both sides of the comparison",
			ref:  "pypi:flask-sqlalchemy@3.1.1",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:flask-sqlalchemy@3.1.1"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "93/8d/bea55fda1cfa9e2c34e6b8dcfea6c3d1d20bcbf6b9c9fb9d0d3b0e5f4a3c/flask_sqlalchemy-3.1.1.tar.gz",
				Integrity: "sha256:e4b68bb881802dda1a7d878b2fc84c06d1ee57fb40b874d3dc97dabfa36b8312",
				Direct:    true,
				Line:      44,
			},
		},
		{
			what: "a directory on the machine, which carries no artifact",
			ref:  "pypi:from-directory@0.6.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:from-directory@0.6.0"),
				Source:   lockfile.SourcePath,
				Resolved: "libs/from-directory",
				Direct:   true,
				Line:     53,
			},
		},
		{
			what: "what a workspace member asks for is direct too",
			ref:  "pypi:from-editable@0.7.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-editable@0.7.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "aa/bb/from_editable-0.7.0-py3-none-any.whl",
				Integrity: "sha256:5b3d1e9c9c2c9f1d3a2b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091",
				Direct:    true,
				Line:      58,
			},
		},
		{
			what: "a git repository, asked for in a dependency group",
			ref:  "pypi:from-git@0.4.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:from-git@0.4.0"),
				Source:   lockfile.SourceGit,
				Resolved: "https://github.com/example/from-git?rev=6f21b0a#6f21b0a3f7c5d8e9b0a1c2d3e4f5a6b7c8d9e0f1",
				Direct:   true,
				Dev:      true,
				Line:     66,
			},
		},
		{
			what: "a requirement the manifest states rather than a package",
			ref:  "pypi:from-manifest@5.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-manifest@5.0.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "cc/dd/from_manifest-5.0.0-py3-none-any.whl",
				Integrity: "sha256:6c4e2fa0d1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d",
				Direct:    true,
				Line:      71,
			},
		},
		{
			what: "a dependency group the manifest states",
			ref:  "pypi:from-manifest-group@0.9.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-manifest-group@0.9.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "ee/ff/from_manifest_group-0.9.0-py3-none-any.whl",
				Integrity: "sha256:7d5f30b1e2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d",
				Direct:    true,
				Dev:       true,
				Line:      79,
			},
		},
		{
			what: "an artifact already on the machine",
			ref:  "pypi:from-path@0.5.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-path@0.5.0"),
				Source:    lockfile.SourcePath,
				Resolved:  "vendor/from_path-0.5.0-py3-none-any.whl",
				Integrity: "sha256:8e6041c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8",
				Line:      87,
			},
		},
		{
			what: "the registry, where the sdist beats the wheels",
			ref:  "pypi:from-registry@1.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-registry@1.0.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "11/22/from_registry-1.0.0.tar.gz",
				Integrity: "sha256:9f7152d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f0",
				Direct:    true,
				Line:      95,
			},
		},
		{
			what: "an archive fetched by URL, asked for under an extra",
			ref:  "pypi:from-url@3.2.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-url@3.2.0"),
				Source:    lockfile.SourceURL,
				Resolved:  "https://downloads.example.com/from-url-3.2.0.tar.gz",
				Integrity: "sha256:b193742536475869a0b1c2d3e4f50617283940a5b6c7d8e9f0a1b2c3d4e5f607",
				Direct:    true,
				Optional:  true,
				Line:      107,
			},
		},
		{
			what: "a member the manifest names, whose source is a directory",
			ref:  "pypi:member-package@0.3.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:member-package@0.3.0"),
				Source:   lockfile.SourcePath,
				Resolved: "packages/member",
				Line:     113,
			},
		},
		{
			what: "a wheel with no hash, served over plain http",
			ref:  "pypi:no-hash@2.0.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:no-hash@2.0.0"),
				Source:   lockfile.SourceRegistry,
				Resolved: "http://mirror.example.com/simple/no_hash-2.0.0-py3-none-any.whl",
				Line:     121,
			},
		},
		{
			what: "a package only another package asks for",
			ref:  "pypi:transitive@1.5.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:transitive@1.5.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "55/66/transitive-1.5.0-py3-none-any.whl",
				Integrity: "sha256:c2a4851637485960a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718",
				Line:      129,
			},
		},
		{
			what: "a dependency pinned by version leaves the other version alone",
			ref:  "pypi:two-versions@1.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:two-versions@1.0.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "77/88/two_versions-1.0.0-py3-none-any.whl",
				Integrity: "sha256:d3b5962748596071a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819",
				Line:      137,
			},
		},
		{
			what: "and marks the version it names",
			ref:  "pypi:two-versions@2.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:two-versions@2.0.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  pypiFiles + "99/aa/two_versions-2.0.0-py3-none-any.whl",
				Integrity: "sha256:e4c60738495a6182b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819a2",
				Direct:    true,
				Line:      145,
			},
		},
		{
			what: "an origin the parser does not know",
			ref:  "pypi:unknown-origin@0.8.0",
			want: lockfile.Entry{
				Ref:    model.MustParseRef("pypi:unknown-origin@0.8.0"),
				Source: lockfile.SourceUnknown,
				Line:   153,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
}

func TestParseDropsTablesItCannotRead(t *testing.T) {
	lf := parseFixture(t, "broken.uv.lock")

	if len(lf.Entries) != 1 || lf.Entries[0].Ref.String() != "pypi:readable@2.0.0" {
		t.Fatalf("entries = %+v, want the one readable package", lf.Entries)
	}
	if !lf.Entries[0].Direct {
		t.Error("the project asks for the readable package, so it is direct")
	}
	if lf.Entries[0].Line != 28 {
		t.Errorf("readable package is on line %d, want 28", lf.Entries[0].Line)
	}
	want := []string{
		"line 7: [[package]] without a name",
		`line 11: package "no-version" without a version`,
		"line 15: unreadable [[package]] table",
		`line 20: "the-project" is the project itself`,
	}
	if len(lf.Dropped) != len(want) {
		t.Fatalf("dropped %v, want %d reasons", lf.Dropped, len(want))
	}
	for i, prefix := range want {
		if !strings.HasPrefix(lf.Dropped[i], prefix) {
			t.Errorf("drop %d = %q, want it to start with %q", i, lf.Dropped[i], prefix)
		}
	}
}

func TestParseRejectsAFileThatIsNotTOML(t *testing.T) {
	_, err := Parser{}.Parse("uv.lock", strings.NewReader("this is not = [ TOML"))
	if err == nil {
		t.Fatal("Parse accepted a file that is not TOML")
	}
	if !strings.Contains(err.Error(), Format) {
		t.Errorf("error = %v, want it to name the format", err)
	}
}

func TestFormatVersionRendersWhatTheFileWrote(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{
		{in: nil, want: ""},
		{in: int64(1), want: "1"},
		{in: "1", want: "1"},
		{in: true, want: "true"},
	}
	for _, tt := range tests {
		if got := formatVersion(tt.in); got != tt.want {
			t.Errorf("formatVersion(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSourceKindReadsTheKeyTheFileWrote(t *testing.T) {
	tests := []struct {
		what         string
		in           source
		wantKind     lockfile.Source
		wantLocation string
	}{
		{what: "registry", in: source{Registry: "https://pypi.org/simple"}, wantKind: lockfile.SourceRegistry, wantLocation: "https://pypi.org/simple"},
		{what: "git", in: source{Git: "https://host/repo#sha"}, wantKind: lockfile.SourceGit, wantLocation: "https://host/repo#sha"},
		{what: "url", in: source{URL: "https://host/pkg.tar.gz"}, wantKind: lockfile.SourceURL, wantLocation: "https://host/pkg.tar.gz"},
		{what: "path", in: source{Path: "vendor/pkg.whl"}, wantKind: lockfile.SourcePath, wantLocation: "vendor/pkg.whl"},
		{what: "directory", in: source{Directory: "libs/pkg"}, wantKind: lockfile.SourcePath, wantLocation: "libs/pkg"},
		{what: "editable", in: source{Editable: "."}, wantKind: lockfile.SourcePath, wantLocation: "."},
		{what: "nothing the parser knows", in: source{}, wantKind: lockfile.SourceUnknown, wantLocation: ""},
	}
	for _, tt := range tests {
		kind, location := tt.in.kind()
		if kind != tt.wantKind || location != tt.wantLocation {
			t.Errorf("%s: kind() = %q, %q, want %q, %q", tt.what, kind, location, tt.wantKind, tt.wantLocation)
		}
	}
}
