package cargo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

const cratesIndex = "registry+https://github.com/rust-lang/crates.io-index"

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
		{base: "cargo.lock", want: true},
		{base: "cargo.toml", want: false},
		{base: "uv.lock", want: false},
		{base: "my-cargo.lock", want: false},
		{base: "", want: false},
	}
	for _, tt := range tests {
		if got := (Parser{}).Detect(tt.base); got != tt.want {
			t.Errorf("Detect(%q) = %v, want %v", tt.base, got, tt.want)
		}
	}
}

func TestParserIsRegistered(t *testing.T) {
	p, ok := lockfile.For("some/project/Cargo.lock")
	if !ok {
		t.Fatal("lockfile.For(Cargo.lock) found no parser")
	}
	if p.Name() != Format {
		t.Fatalf("registered parser is %q, want %q", p.Name(), Format)
	}
	// lockfile.For lowercases the base name, so a Windows checkout that spells the
	// file differently still finds the parser.
	if _, ok := lockfile.For("SOME/PROJECT/CARGO.LOCK"); !ok {
		t.Error("lockfile.For(CARGO.LOCK) found no parser")
	}
}

func TestParseWorkspaceLockfileVersion3(t *testing.T) {
	lf := parseFixture(t, "ripgrep-14.1.1.Cargo.lock")

	if lf.Format != Format || lf.Ecosystem != model.Cargo {
		t.Errorf("Format = %q, Ecosystem = %q", lf.Format, lf.Ecosystem)
	}
	if lf.Version != "3" {
		t.Errorf("Version = %q, want 3", lf.Version)
	}
	if len(lf.Entries) != 61 {
		t.Errorf("read %d entries, want 61", len(lf.Entries))
	}
	if len(lf.Dropped) != 0 {
		t.Errorf("dropped %v, want nothing", lf.Dropped)
	}

	tests := []struct {
		ref  string
		want lockfile.Entry
	}{
		{
			// The first entry of the file, and a crate globset asks for by name.
			ref: "cargo:aho-corasick@1.1.3",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:aho-corasick@1.1.3"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:8e60d3430d3a69478ad0993f19238d2df97c507009a52b3c10addcd7f6bcb916",
				Direct:    true,
				Line:      5,
			},
		},
		{
			// Nothing in the workspace names cfg-if, so it is transitive.
			ref: "cargo:cfg-if@1.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:cfg-if@1.0.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd",
				Line:      42,
			},
		},
		{
			// A workspace member: no source, and the ripgrep package asks for it.
			ref: "cargo:grep@0.3.2",
			want: lockfile.Entry{
				Ref:    model.MustParseRef("cargo:grep@0.3.2"),
				Source: lockfile.SourcePath,
				Direct: true,
				Line:   120,
			},
		},
		{
			// The project itself: a path entry nobody depends on.
			ref: "cargo:ripgrep@14.1.1",
			want: lockfile.Entry{
				Ref:    model.MustParseRef("cargo:ripgrep@14.1.1"),
				Source: lockfile.SourcePath,
				Line:   362,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("entry %s =\n %+v\nwant\n %+v", tt.ref, got, tt.want)
		}
	}
}

func TestParseSingleCrateLockfileVersion4(t *testing.T) {
	lf := parseFixture(t, "zoxide-v0.9.8.Cargo.lock")

	if lf.Version != "4" {
		t.Errorf("Version = %q, want 4", lf.Version)
	}
	if len(lf.Entries) != 112 {
		t.Errorf("read %d entries, want 112", len(lf.Entries))
	}
	if got := lf.Entries[0].Ref.String(); got != "cargo:aho-corasick@1.1.3" {
		t.Errorf("first entry = %s, want aho-corasick, the first of the file", got)
	}

	tests := []struct {
		ref  string
		want lockfile.Entry
	}{
		{
			// zoxide names anyhow in its own dependencies.
			ref: "cargo:anyhow@1.0.98",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:anyhow@1.0.98"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:e16d2d3311acee920a9eb8d33b8cbc1787ce4a264e85f964c2404b969bdcd487",
				Direct:    true,
				Line:      70,
			},
		},
		{
			// The same crate that is direct in the ripgrep workspace is transitive here.
			ref: "cargo:aho-corasick@1.1.3",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:aho-corasick@1.1.3"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:8e60d3430d3a69478ad0993f19238d2df97c507009a52b3c10addcd7f6bcb916",
				Line:      5,
			},
		},
		{
			ref: "cargo:zoxide@0.9.8",
			want: lockfile.Entry{
				Ref:    model.MustParseRef("cargo:zoxide@0.9.8"),
				Source: lockfile.SourcePath,
				Line:   969,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("entry %s =\n %+v\nwant\n %+v", tt.ref, got, tt.want)
		}
	}
}

func TestParseReadsEverySourceKind(t *testing.T) {
	lf := parseFixture(t, "sources.Cargo.lock")

	if lf.Version != "4" {
		t.Errorf("Version = %q, want 4", lf.Version)
	}
	if len(lf.Entries) != 13 || len(lf.Dropped) != 0 {
		t.Fatalf("read %d entries and dropped %v, want 13 entries and no drops", len(lf.Entries), lf.Dropped)
	}

	tests := []struct {
		what string
		ref  string
		want lockfile.Entry
	}{
		{
			what: "a crates.io name keeps its case",
			ref:  "cargo:Inflector@0.11.4",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:Inflector@0.11.4"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:fe438c63458706e03479442743baae6c88256498e6431708f6dfc520a26515d3",
				Direct:    true,
				Line:      20,
			},
		},
		{
			what: "an origin the parser does not know",
			ref:  "cargo:from-elsewhere@0.3.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("cargo:from-elsewhere@0.3.0"),
				Source:   lockfile.SourceUnknown,
				Resolved: "svn+https://svn.example.com/crates/from-elsewhere",
				Direct:   true,
				Line:     26,
			},
		},
		{
			what: "a git repository",
			ref:  "cargo:from-git@0.4.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("cargo:from-git@0.4.0"),
				Source:   lockfile.SourceGit,
				Resolved: "git+https://github.com/example/from-git?rev=6f21b0a#6f21b0a3f7c5d8e9b0a1c2d3e4f5a6b7c8d9e0f1",
				Direct:   true,
				Line:     31,
			},
		},
		{
			what: "a directory on the machine",
			ref:  "cargo:from-path@0.5.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("cargo:from-path@0.5.0"),
				Source:   lockfile.SourcePath,
				Resolved: "path+file:///home/dev/checkouts/from-path",
				Direct:   true,
				Line:     36,
			},
		},
		{
			what: "the registry",
			ref:  "cargo:from-registry@1.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:from-registry@1.0.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:8e60d3430d3a69478ad0993f19238d2df97c507009a52b3c10addcd7f6bcb916",
				Direct:    true,
				Line:      41,
			},
		},
		{
			what: "a sparse registry",
			ref:  "cargo:from-sparse-registry@2.1.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:from-sparse-registry@2.1.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  "sparse+https://crates.example.com/index/",
				Integrity: "sha256:40723b8fb387abc38f4f4a37c09073622e41dd12327033091ef8950659e6dc0c",
				Direct:    true,
				Line:      50,
			},
		},
		{
			what: "a workspace member, which is the project too",
			ref:  "cargo:member-crate@0.1.0",
			want: lockfile.Entry{
				Ref:    model.MustParseRef("cargo:member-crate@0.1.0"),
				Source: lockfile.SourcePath,
				Line:   56,
			},
		},
		{
			what: "what a member asks for is direct as well",
			ref:  "cargo:member-dependency@9.9.9",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:member-dependency@9.9.9"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:93fc1dc3aaa9bfed95e02e6eadabb4baf7e3078b0bd1b4d7b6b0b68378900502",
				Direct:    true,
				Line:      63,
			},
		},
		{
			what: "a package the file gives no checksum",
			ref:  "cargo:no-checksum@0.2.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("cargo:no-checksum@0.2.0"),
				Source:   lockfile.SourceRegistry,
				Resolved: cratesIndex,
				Direct:   true,
				Line:     69,
			},
		},
		{
			what: "a crate only another crate asks for",
			ref:  "cargo:transitive@1.5.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:transitive@1.5.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:c8e3592472072e6e22e0a54d5904d9febf8508f65fb8552499a1abc7d1078c3a",
				Line:      74,
			},
		},
		{
			what: "a dependency pinned by version leaves the other version alone",
			ref:  "cargo:two-versions@1.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:two-versions@1.0.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:7a66a03ae7c801facd77a29370b4faec201768915ac14a721ba36f20bc9c209b",
				Line:      80,
			},
		},
		{
			what: "and marks the version it names",
			ref:  "cargo:two-versions@2.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:two-versions@2.0.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:f3cb5ba0dc43242ce17de99c180e96db90b235b8a9fdc9543c96d2209116bd9f",
				Direct:    true,
				Line:      86,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
}

func TestParseReadsChecksumsOfTheFirstFormatVersions(t *testing.T) {
	lf := parseFixture(t, "metadata-v1.Cargo.lock")

	if lf.Version != "" {
		t.Errorf("Version = %q, want an empty string for a file that declares none", lf.Version)
	}
	tests := []struct {
		ref  string
		want lockfile.Entry
	}{
		{
			ref: "cargo:old-dependency@1.2.3",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("cargo:old-dependency@1.2.3"),
				Source:    lockfile.SourceRegistry,
				Resolved:  cratesIndex,
				Integrity: "sha256:d9a60d1e5c3b7a0ff0e9bd7d31ad2a49b5e1c2c1f8ea3d7bd5e6ff6a52b7f6f6",
				Direct:    true,
				Line:      17,
			},
		},
		{
			// "<none>" is not a hash, and a git dependency carries none.
			ref: "cargo:from-git@0.4.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("cargo:from-git@0.4.0"),
				Source:   lockfile.SourceGit,
				Resolved: "git+https://github.com/example/from-git#6f21b0a3f7c5d8e9b0a1c2d3e4f5a6b7c8d9e0f1",
				Direct:   true,
				Line:     12,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("entry %s =\n %+v\nwant\n %+v", tt.ref, got, tt.want)
		}
	}
}

func TestParseDropsTablesItCannotRead(t *testing.T) {
	lf := parseFixture(t, "broken.Cargo.lock")

	if len(lf.Entries) != 1 || lf.Entries[0].Ref.String() != "cargo:readable@1.0.0" {
		t.Fatalf("entries = %+v, want the one readable package", lf.Entries)
	}
	if lf.Entries[0].Line != 18 {
		t.Errorf("readable package is on line %d, want 18", lf.Entries[0].Line)
	}
	want := []string{
		"line 6: [[package]] without a name",
		`line 10: package "no-version" without a version`,
		"line 14: unreadable [[package]] table",
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
	_, err := Parser{}.Parse("Cargo.lock", strings.NewReader("this is not = [ TOML"))
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
		{in: int64(3), want: "3"},
		{in: int64(4), want: "4"},
		{in: "4", want: "4"},
		{in: true, want: "true"},
	}
	for _, tt := range tests {
		if got := formatVersion(tt.in); got != tt.want {
			t.Errorf("formatVersion(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSplitDependencyReadsNameAndVersion(t *testing.T) {
	tests := []struct {
		in          string
		wantName    string
		wantVersion string
	}{
		{in: "memchr", wantName: "memchr"},
		{in: "memchr 2.7.4", wantName: "memchr", wantVersion: "2.7.4"},
		{in: "memchr 2.7.4 (" + cratesIndex + ")", wantName: "memchr", wantVersion: "2.7.4"},
		{in: "", wantName: "", wantVersion: ""},
	}
	for _, tt := range tests {
		name, version := splitDependency(tt.in)
		if name != tt.wantName || version != tt.wantVersion {
			t.Errorf("splitDependency(%q) = %q, %q, want %q, %q", tt.in, name, version, tt.wantName, tt.wantVersion)
		}
	}
}
