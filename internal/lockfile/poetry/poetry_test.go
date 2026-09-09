package poetry

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

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
		{base: "poetry.lock", want: true},
		{base: "pyproject.toml", want: false},
		{base: "uv.lock", want: false},
		{base: "my-poetry.lock", want: false},
		{base: "", want: false},
	}
	for _, tt := range tests {
		if got := (Parser{}).Detect(tt.base); got != tt.want {
			t.Errorf("Detect(%q) = %v, want %v", tt.base, got, tt.want)
		}
	}
}

func TestParserIsRegistered(t *testing.T) {
	p, ok := lockfile.For("some/project/poetry.lock")
	if !ok {
		t.Fatal("lockfile.For(poetry.lock) found no parser")
	}
	if p.Name() != Format {
		t.Fatalf("registered parser is %q, want %q", p.Name(), Format)
	}
	// lockfile.For lowercases the base name, so a checkout that spells the file
	// differently still finds the parser.
	if _, ok := lockfile.For("SOME/PROJECT/POETRY.LOCK"); !ok {
		t.Error("lockfile.For(POETRY.LOCK) found no parser")
	}
}

func TestParseAProjectWithRuntimeAndDevelopmentGroups(t *testing.T) {
	lf := parseFixture(t, "pendulum.poetry.lock")

	if lf.Format != Format || lf.Ecosystem != model.PyPI {
		t.Errorf("Format = %q, Ecosystem = %q", lf.Format, lf.Ecosystem)
	}
	if lf.Version != "2.1" {
		t.Errorf("Version = %q, want 2.1", lf.Version)
	}
	if len(lf.Entries) != 52 {
		t.Errorf("read %d entries, want 52", len(lf.Entries))
	}
	if len(lf.Dropped) != 0 {
		t.Errorf("dropped %v, want nothing", lf.Dropped)
	}

	tests := []struct {
		what string
		ref  string
		want lockfile.Entry
	}{
		{
			// The first table of the file, and a package no runtime group needs.
			what: "a development dependency, whose sdist carries the hash",
			ref:  "pypi:babel@2.16.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:babel@2.16.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:d1f3554ca26605fe173f3de0c65f750f5a42f924499bf134de6423582298e316",
				Dev:       true,
				Line:      3,
			},
		},
		{
			what: "a package the runtime group needs",
			ref:  "pypi:tzdata@2024.2",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:tzdata@2024.2"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:7d85cc416e9382e69095b7bdf4afd9e3880418a2413feec7069d533d6b4e31cc",
				Line:      1225,
			},
		},
		{
			what: "a package both the runtime and a documentation group need, so not Dev",
			ref:  "pypi:python-dateutil@2.9.0.post0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:python-dateutil@2.9.0.post0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:37dd54208da7e1cd875388217d5e00ebd4179249f90fb72437e91a35459a0ad3",
				Line:      809,
			},
		},
		{
			what: "a package deep in the file, to prove the headers stay in step",
			ref:  "pypi:pytest@7.4.4",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:pytest@7.4.4"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:2cf0005922c6ace4a3e2ec8b4080eb0d9753fdc93107415332f50ce9e7994280",
				Dev:       true,
				Line:      733,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
}

// TestParseAProjectWithNoRuntimeDependencies is the other side of the Dev flag: a
// library that declares nothing to run with locks nothing in the "main" group, and
// every entry is a development dependency.
func TestParseAProjectWithNoRuntimeDependencies(t *testing.T) {
	lf := parseFixture(t, "cleo.poetry.lock")

	if lf.Version != "2.1" {
		t.Errorf("Version = %q, want 2.1", lf.Version)
	}
	if len(lf.Entries) != 53 || len(lf.Dropped) != 0 {
		t.Fatalf("read %d entries and dropped %v, want 53 entries and no drops", len(lf.Entries), lf.Dropped)
	}
	for _, e := range lf.Entries {
		if !e.Dev {
			t.Errorf("entry %s is not Dev, but no group in this file is the runtime one", e.Ref)
		}
	}
	want := lockfile.Entry{
		Ref:       model.MustParseRef("pypi:alabaster@0.7.16"),
		Source:    lockfile.SourceRegistry,
		Integrity: "sha256:75a8b99c28a5dad50dd7f8ccdd447a121ddb3892da9e53d1ca5cca3106d58d65",
		Dev:       true,
		Line:      3,
	}
	if got := entryOf(t, lf, "pypi:alabaster@0.7.16"); got != want {
		t.Errorf("entry alabaster =\n %+v\nwant\n %+v", got, want)
	}
}

func TestParseReadsEverySourceKind(t *testing.T) {
	lf := parseFixture(t, "sources.poetry.lock")

	if lf.Version != "2.1" {
		t.Errorf("Version = %q, want 2.1", lf.Version)
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
			what: "no source table, so the default index, which the file does not name",
			ref:  "pypi:from-default-index@1.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-default-index@1.0.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:d7f6e2823602fd2c51318e0f809dc3b7301e3db9b5a725d7bbcac624bbc57432",
				Line:      29,
			},
		},
		{
			what: "an index of its own, and a name PEP 503 rewrites",
			ref:  "pypi:from-legacy-index@2.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-legacy-index@2.0.0"),
				Source:    lockfile.SourceRegistry,
				Resolved:  "https://pypi.example.com/simple",
				Integrity: "sha256:eb25e1b422510ea63d0e3242421fb067f47b8a9dacf873b55f1c7d37299ca6c2",
				Line:      113,
			},
		},
		{
			what: "a git repository, whose remote and commit are joined into one location",
			ref:  "pypi:from-git@0.4.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:from-git@0.4.0"),
				Source:   lockfile.SourceGit,
				Resolved: "https://github.com/example/from-git.git#6f21b0a3f7c5d8e9b0a1c2d3e4f5a6b7c8d9e0f1",
				Line:     83,
			},
		},
		{
			what: "a git repository with no resolved commit, which falls back to the reference",
			ref:  "pypi:from-git-unresolved@0.5.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:from-git-unresolved@0.5.0"),
				Source:   lockfile.SourceGit,
				Resolved: "https://github.com/example/from-git-unresolved.git#v0.5.0",
				Line:     99,
			},
		},
		{
			what: "a directory on the machine",
			ref:  "pypi:from-directory@0.1.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:from-directory@0.1.0"),
				Source:   lockfile.SourcePath,
				Resolved: "libs/from-directory",
				Line:     41,
			},
		},
		{
			what: "an archive on the machine",
			ref:  "pypi:from-file@0.2.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-file@0.2.0"),
				Source:    lockfile.SourcePath,
				Resolved:  "vendor/from_file-0.2.0-py3-none-any.whl",
				Integrity: "sha256:a18bb9f7921e7bbcf4f59db55e006d59c4c0253df4ef919ca56d077ed50df8be",
				Line:      68,
			},
		},
		{
			what: "an archive fetched by URL",
			ref:  "pypi:from-url@3.1.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:from-url@3.1.0"),
				Source:    lockfile.SourceURL,
				Resolved:  "https://files.example.com/from_url-3.1.0.tar.gz",
				Integrity: "sha256:aaaaaf7a115ff4092a39039a04db010d621a41d34d86ff6624f9ad825c1636be",
				Line:      129,
			},
		},
		{
			what: "an origin the parser does not know",
			ref:  "pypi:from-elsewhere@0.3.0",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:from-elsewhere@0.3.0"),
				Source:   lockfile.SourceUnknown,
				Resolved: "https://svn.example.com/dists/from-elsewhere",
				Line:     55,
			},
		},
		{
			what: "no sdist, so the first wheel carries the hash",
			ref:  "pypi:only-wheels@5.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:only-wheels@5.0.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:6d1a537d0cd881b25d4b8157d5a0d7ae878529e98055983cbf0bc06e46170a73",
				Line:      153,
			},
		},
		{
			what: "no artifact at all, so no hash",
			ref:  "pypi:no-files@6.0.0",
			want: lockfile.Entry{
				Ref:    model.MustParseRef("pypi:no-files@6.0.0"),
				Source: lockfile.SourceRegistry,
				Line:   144,
			},
		},
		{
			what: "installed only with an extra",
			ref:  "pypi:optional-extra@7.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:optional-extra@7.0.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:3070b5a48bc2c02f3a61a95aceff8f5e1a328a624871c59325006e9dcb24fa7e",
				Optional:  true,
				Line:      165,
			},
		},
		{
			what: "a group that is not the runtime one, on its own",
			ref:  "pypi:dev-only@8.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:dev-only@8.0.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:c0dea4eca6f6ee9515d2114a01aaf73362747a53c62562f13df013691435daa2",
				Dev:       true,
				Line:      17,
			},
		},
		{
			what: "the runtime group next to a development one, which is not Dev",
			ref:  "pypi:dev-and-main@9.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:dev-and-main@9.0.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:59ba406332ed2476505d862bb66fd893743e222b9ce3305fbaec9a94b14f0ead",
				Line:      5,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
	// poetry.lock records the resolved graph and not what the project asked for,
	// so nothing in it may be reported as a direct dependency.
	for _, e := range lf.Entries {
		if e.Direct {
			t.Errorf("entry %s is marked direct, but poetry.lock never says which packages the project itself names", e.Ref)
		}
	}
}

func TestParseReadsTheFirstFormatVersions(t *testing.T) {
	lf := parseFixture(t, "legacy-v1.poetry.lock")

	if lf.Version != "1.1" {
		t.Errorf("Version = %q, want 1.1", lf.Version)
	}
	tests := []struct {
		what string
		ref  string
		want lockfile.Entry
	}{
		{
			what: `category = "main" is the runtime group, so not Dev, and the hash comes from [metadata.files]`,
			ref:  "pypi:old-runtime@1.2.3",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:old-runtime@1.2.3"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:ef1808c302c0f0e9aa6d6abcbe9a7b1b82ffb4e1fee44a0853f818b4202e5bc4",
				Line:      5,
			},
		},
		{
			what: `category = "dev" is a development group, and the name is normalized before the file lists are looked up`,
			ref:  "pypi:old-dev-tool@4.5.6",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:old-dev-tool@4.5.6"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:d1c0feabb10dd9b63cb93b3c0794c7aa5d44f58307030b7123ee8258a55cab7a",
				Dev:       true,
				Line:      13,
			},
		},
		{
			what: "an empty file list carries no hash",
			ref:  "pypi:old-optional@7.8.9",
			want: lockfile.Entry{
				Ref:      model.MustParseRef("pypi:old-optional@7.8.9"),
				Source:   lockfile.SourceRegistry,
				Optional: true,
				Line:     21,
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
	lf := parseFixture(t, "broken.poetry.lock")

	if len(lf.Entries) != 1 || lf.Entries[0].Ref.String() != "pypi:readable@1.0.0" {
		t.Fatalf("entries = %+v, want the one readable package", lf.Entries)
	}
	if lf.Entries[0].Line != 26 {
		t.Errorf("readable package is on line %d, want 26", lf.Entries[0].Line)
	}
	want := []string{
		"line 5: [[package]] without a name",
		`line 12: package "no-version" without a version`,
		"line 19: unreadable [[package]] table",
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

// TestParseReadsCRLF proves the line numbers on a Windows checkout: the same file
// with CRLF endings must give the same entries on the same lines. The fixture is
// only a test of anything while it really carries them, and the repository
// normalizes every other file to LF, so that is checked first.
func TestParseReadsCRLF(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "crlf.poetry.lock"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Contains(data, []byte("\r\n")) {
		t.Fatal("the fixture has lost its carriage returns, so it tests nothing: see testdata/.gitattributes")
	}
	lf := parseFixture(t, "sources.poetry.lock")
	crlf := parseFixture(t, "crlf.poetry.lock")

	if len(crlf.Entries) != len(lf.Entries) {
		t.Fatalf("read %d entries from the CRLF file, want %d", len(crlf.Entries), len(lf.Entries))
	}
	for i, want := range lf.Entries {
		if got := crlf.Entries[i]; got != want {
			t.Errorf("entry %d =\n %+v\nwant\n %+v", i, got, want)
		}
	}
}

// TestParseReportsATruncatedFile is the "half a file" case: a lockfile cut in the
// middle must come back as an error naming the file, and must not panic.
func TestParseReportsATruncatedFile(t *testing.T) {
	path := filepath.Join("testdata", "truncated.poetry.lock")
	f, err := os.Open(path) // #nosec G304 -- the path is a test fixture in this package
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	lf, err := Parser{}.Parse(path, f)
	if err == nil {
		t.Fatalf("Parse accepted a truncated file and returned %+v", lf)
	}
	if !strings.Contains(err.Error(), Format) {
		t.Errorf("error = %v, want it to name the file", err)
	}
}

// TestParseIsNotFooledByAHeaderInsideAValue places entries against a file that
// spells a table header inside a string. A poetry.lock in a pull request is text
// the author chose, and a finding that moved onto an innocent package's line would
// point a reviewer at the wrong distribution.
func TestParseIsNotFooledByAHeaderInsideAValue(t *testing.T) {
	lf, err := Parser{}.Parse("poetry.lock", strings.NewReader(`[[package]]
name = "innocent"
version = "1.0.0"
description = """
[[package]]
name = "evil"
"""
optional = false
groups = ["main"]

[[package]]
name = "evil"
version = "6.6.6"
description = "the real one"
optional = false
groups = ["main"]

[metadata]
lock-version = "2.1"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]int{"pypi:innocent@1.0.0": 1, "pypi:evil@6.6.6": 11}
	if len(lf.Entries) != len(want) {
		t.Fatalf("entries = %+v, want %d", lf.Entries, len(want))
	}
	for _, e := range lf.Entries {
		if line, ok := want[e.Ref.String()]; !ok || e.Line != line {
			t.Errorf("%s is on line %d, want %d", e.Ref, e.Line, line)
		}
	}
}

// TestParseKeepsAPackageWhoseHeaderCannotBeFound is the other end of the placing:
// a decoder reads a TOML escape and the finder reads the text the header was
// written in, so a name spelled with one is confirmed by no header. The package is
// still an installed package and still has to be evaluated, so it is kept with no
// line, which is what Entry.Line documents zero as.
func TestParseKeepsAPackageWhoseHeaderCannotBeFound(t *testing.T) {
	lf, err := Parser{}.Parse("poetry.lock", strings.NewReader(`[[package]]
name = "escape\u0064"
version = "1.0.0"
optional = false
groups = ["main"]

[metadata]
lock-version = "2.1"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := lockfile.Entry{
		Ref:    model.MustParseRef("pypi:escaped@1.0.0"),
		Source: lockfile.SourceRegistry,
	}
	if len(lf.Entries) != 1 || lf.Entries[0] != want {
		t.Fatalf("entries = %+v, want the one package with no line", lf.Entries)
	}
	if len(lf.Dropped) != 0 {
		t.Errorf("dropped %v, want nothing: a package the parser cannot place is still a package", lf.Dropped)
	}
}

// TestParseReadsMetadataLeniently holds Parse to what its doc says, that only a
// file which is not TOML fails. [metadata] is small enough to be written by hand,
// and a lock version spelled as a number instead of a string is the way it comes
// back wrong; a file that is otherwise perfectly readable must still be read, and a
// value nothing can be made of costs that one field and says so.
func TestParseReadsMetadataLeniently(t *testing.T) {
	const packages = `[[package]]
name = "readable"
version = "1.0.0"
optional = false
groups = ["main"]

[metadata]
`
	tests := []struct {
		what     string
		metadata string
		want     string
		dropped  string
	}{
		{what: "the spelling poetry writes", metadata: `lock-version = "2.1"`, want: "2.1"},
		{what: "a lock version written as a float", metadata: "lock-version = 2.1", want: "2.1"},
		{what: "a whole lock version written as a float, which keeps its fraction", metadata: "lock-version = 2.0", want: "2.0"},
		{what: "a lock version written as an integer", metadata: "lock-version = 2", want: "2"},
		{
			what:     "a lock version no spelling makes a version of",
			metadata: "lock-version = true",
			dropped:  `[metadata]: "lock-version" is a bool, not a version, so the file states none`,
		},
		{
			what:     "a file list that is not a file list",
			metadata: `files = "nope"`,
			dropped:  `[metadata]: "files" is not the table of artifact lists this format writes (it is a string), so the hashes it holds are not read`,
		},
		{what: "a metadata table with nothing the parser reads", metadata: `content-hash = "sha256:1234"`},
	}
	for _, tt := range tests {
		lf, err := Parser{}.Parse("poetry.lock", strings.NewReader(packages+tt.metadata+"\n"))
		if err != nil {
			t.Errorf("%s: Parse: %v", tt.what, err)
			continue
		}
		if len(lf.Entries) != 1 || lf.Entries[0].Ref.String() != "pypi:readable@1.0.0" || lf.Entries[0].Line != 1 {
			t.Errorf("%s: entries = %+v, want the one package on line 1", tt.what, lf.Entries)
		}
		if lf.Version != tt.want {
			t.Errorf("%s: Version = %q, want %q", tt.what, lf.Version, tt.want)
		}
		switch {
		case tt.dropped == "" && len(lf.Dropped) != 0:
			t.Errorf("%s: dropped %v, want nothing", tt.what, lf.Dropped)
		case tt.dropped != "" && (len(lf.Dropped) != 1 || lf.Dropped[0] != tt.dropped):
			t.Errorf("%s: dropped %v, want the one reason\n %s", tt.what, lf.Dropped, tt.dropped)
		}
	}
}

func TestParseRejectsAFileThatIsNotTOML(t *testing.T) {
	_, err := Parser{}.Parse("poetry.lock", strings.NewReader("this is not = [ TOML"))
	if err == nil {
		t.Fatal("Parse accepted a file that is not TOML")
	}
	if !strings.Contains(err.Error(), Format) {
		t.Errorf("error = %v, want it to name the format", err)
	}
}

func TestDevReadsBothSpellingsOfTheGroup(t *testing.T) {
	tests := []struct {
		what     string
		groups   []string
		category string
		want     bool
	}{
		{what: "poetry 2, the runtime group alone", groups: []string{"main"}},
		{what: "poetry 2, the runtime group among others", groups: []string{"main", "dev", "test"}},
		{what: "poetry 2, no runtime group", groups: []string{"dev", "doc"}, want: true},
		{what: "poetry 1, the runtime group", category: "main"},
		{what: "poetry 1, a development group", category: "dev", want: true},
		{what: "poetry 1, a group of the project's own naming", category: "typing", want: true},
		{what: "a file that says neither", want: false},
		{
			// A lock that carries both spellings is not something Poetry writes, and
			// the newer one is the one to believe.
			what:     "both spellings, where the newer one wins",
			groups:   []string{"main"},
			category: "dev",
			want:     false,
		},
	}
	for _, tt := range tests {
		p := decodedPackage{packageTable: packageTable{Groups: tt.groups, Category: tt.category}}
		if got := p.dev(); got != tt.want {
			t.Errorf("%s: dev() = %v, want %v", tt.what, got, tt.want)
		}
	}
}

func TestIntegrityPrefersTheSdist(t *testing.T) {
	tests := []struct {
		what  string
		files []file
		want  string
	}{
		{what: "no artifact at all"},
		{
			what:  "a wheel before the sdist, which is how poetry sorts them",
			files: []file{{File: "pkg-1.0-py3-none-any.whl", Hash: "sha256:wheel"}, {File: "pkg-1.0.tar.gz", Hash: "sha256:sdist"}},
			want:  "sha256:sdist",
		},
		{
			what:  "a zip is a source distribution too",
			files: []file{{File: "pkg-1.0-py3-none-any.whl", Hash: "sha256:wheel"}, {File: "pkg-1.0.zip", Hash: "sha256:zip"}},
			want:  "sha256:zip",
		},
		{
			what:  "only wheels, so the first one",
			files: []file{{File: "pkg-1.0-cp311-macosx.whl", Hash: "sha256:first"}, {File: "pkg-1.0-cp311-linux.whl", Hash: "sha256:second"}},
			want:  "sha256:first",
		},
		{
			what:  "a wheel spelled in capitals is still a wheel",
			files: []file{{File: "PKG-1.0-PY3-NONE-ANY.WHL", Hash: "sha256:first"}},
			want:  "sha256:first",
		},
	}
	for _, tt := range tests {
		if got := integrity(tt.files); got != tt.want {
			t.Errorf("%s: integrity(%v) = %q, want %q", tt.what, tt.files, got, tt.want)
		}
	}
}
