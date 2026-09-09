package deno

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
		{base: "deno.lock", want: true},
		{base: "deno.json", want: false},
		{base: "uv.lock", want: false},
		{base: "my-deno.lock", want: false},
		{base: "", want: false},
	}
	for _, tt := range tests {
		if got := (Parser{}).Detect(tt.base); got != tt.want {
			t.Errorf("Detect(%q) = %v, want %v", tt.base, got, tt.want)
		}
	}
}

func TestParserIsRegistered(t *testing.T) {
	p, ok := lockfile.For("some/project/deno.lock")
	if !ok {
		t.Fatal("lockfile.For(deno.lock) found no parser")
	}
	if p.Name() != Format {
		t.Fatalf("registered parser is %q, want %q", p.Name(), Format)
	}
	// lockfile.For lowercases the base name, so a checkout that spells the file
	// differently still finds the parser.
	if _, ok := lockfile.For("SOME/PROJECT/DENO.LOCK"); !ok {
		t.Error("lockfile.For(DENO.LOCK) found no parser")
	}
}

// TestParseLeavesTheEcosystemEmpty pins the one thing that makes this format
// different from the others: it mixes ecosystems, so the entry set names none and
// every entry carries its own.
func TestParseLeavesTheEcosystemEmpty(t *testing.T) {
	lf := parseFixture(t, "deployctl-v4.deno.lock")

	if lf.Ecosystem != "" {
		t.Errorf("Ecosystem = %q, want an empty string for a file that mixes ecosystems", lf.Ecosystem)
	}
	var jsr, npm int
	for _, e := range lf.Entries {
		switch e.Ref.Ecosystem {
		case model.JSR:
			jsr++
		case model.NPM:
			npm++
		default:
			t.Errorf("entry %s carries ecosystem %q", e.Ref, e.Ref.Ecosystem)
		}
	}
	if jsr != 23 || npm != 1 {
		t.Errorf("read %d JSR and %d npm entries, want 23 and 1", jsr, npm)
	}
}

func TestParseVersion4(t *testing.T) {
	lf := parseFixture(t, "deployctl-v4.deno.lock")

	if lf.Format != Format {
		t.Errorf("Format = %q, want %q", lf.Format, Format)
	}
	if lf.Version != "4" {
		t.Errorf("Version = %q, want 4", lf.Version)
	}
	if len(lf.Entries) != 24 {
		t.Errorf("read %d entries, want 24", len(lf.Entries))
	}

	tests := []struct {
		what string
		ref  string
		want lockfile.Entry
	}{
		{
			what: "a JSR package the workspace names, whose hash gains its algorithm",
			ref:  "jsr:@deno/emit@0.46.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("jsr:@deno/emit@0.46.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:e276be2c77bac1b93caf775762e2a49a54cb00da2d48ca2b01ed8d7cba9d082c",
				Direct:    true,
				Line:      41,
			},
		},
		{
			what: "a JSR package only another package asks for",
			ref:  "jsr:@deno/cache-dir@0.13.2",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("jsr:@deno/cache-dir@0.13.2"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:c22419dfe27ab85f345bee487aaaadba498b005cce3644e9d2528db035c5454d",
				Line:      32,
			},
		},
		{
			what: "one of two versions of the same package, the one the workspace pins",
			ref:  "jsr:@std/path@0.217.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("jsr:@std/path@0.217.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:1217cc25534bca9a2f672d7fe7c6f356e4027df400c0e85c0ef3e4343bc67d11",
				Direct:    true,
				Line:      117,
			},
		},
		{
			what: "and the other version, which only a dependency asks for",
			ref:  "jsr:@std/path@1.0.1",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("jsr:@std/path@1.0.1"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:e061ff02c28481ca49e3a14981875c345e9fc7e973190672782cd0ac8af70428",
				Line:      129,
			},
		},
		{
			what: "an npm package, whose SRI hash is recorded as written",
			ref:  "npm:keychain@1.5.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("npm:keychain@1.5.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha512-liyp4r+93RI7EB2jhwaRd4MWfdgHH6shuldkaPMkELCJjMFvOOVXuTvw1pGqFfhsrgA6OqfykWWPQgBjQakVag==",
				Line:      140,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
}

// TestParseDropsRemoteEntries pins the decision the format does not answer: a
// remote entry is one module file and has no name a lookup could use, so it is
// dropped with its URL rather than turned into an entry.
func TestParseDropsRemoteEntries(t *testing.T) {
	lf := parseFixture(t, "deployctl-v4.deno.lock")

	if len(lf.Dropped) != 4 {
		t.Fatalf("dropped %v, want the four remote URLs", lf.Dropped)
	}
	const first = "https://raw.githubusercontent.com/denosaurs/wait/453df8babdd72c59d865c5a616c5b04ee1154b9f/deps.ts"
	if !strings.HasPrefix(lf.Dropped[0], first+": a remote URL names one module file") {
		t.Errorf("first drop = %q, want it to name %s and say why", lf.Dropped[0], first)
	}
	for _, e := range lf.Entries {
		if strings.HasPrefix(e.Ref.Name, "http") {
			t.Errorf("entry %s carries a URL as a name", e.Ref)
		}
	}
}

func TestParseVersion5(t *testing.T) {
	lf := parseFixture(t, "deno-graph-v5.deno.lock")

	if lf.Version != "5" {
		t.Errorf("Version = %q, want 5", lf.Version)
	}
	if len(lf.Entries) != 53 {
		t.Errorf("read %d entries, want 53", len(lf.Entries))
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
			what: "the first entry of the file, which the workspace does not name",
			ref:  "jsr:@david/console-static-text@0.3.4",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("jsr:@david/console-static-text@0.3.4"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:1c596f500b075ff3c8bab1d328ca7148a88067fd9a506b16a73eeaf230c229fd",
				Line:      24,
			},
		},
		{
			what: "a direct JSR dependency",
			ref:  "jsr:@std/path@1.1.2",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("jsr:@std/path@1.1.2"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:c0b13b97dfe06546d5e16bf3966b1cadf92e1cc83e56ba5476ad8b498d9e3038",
				Direct:    true,
				Line:      91,
			},
		},
		{
			what: "a peer suffixed npm key, whose version stops at the underscore",
			ref:  "npm:@octokit/plugin-paginate-rest@14.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("npm:@octokit/plugin-paginate-rest@14.0.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha512-fNVRE7ufJiAA3XUrha2omTA39M6IXIc6GIZLvlbsm8QOQCYvpq/LkMNGyFlB1d8hTDzsAXa3OKtybdMAYsV/fw==",
				Line:      239,
			},
		},
		{
			what: "an npm package only a JSR package asks for, so not direct",
			ref:  "npm:octokit@5.0.5",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("npm:octokit@5.0.5"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha512-4+/OFSqOjoyULo7eN7EA97DE0Xydj/PW5aIckxqQIoFjFwqXKuFCvXUJObyJfBF9Khu4RL/jlDRI9FPaMGfPnw==",
				Line:      332,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
}

func TestParseReadsEveryWorkspaceList(t *testing.T) {
	lf := parseFixture(t, "sources.deno.lock")

	if len(lf.Entries) != 7 {
		t.Fatalf("read %d entries, want 7", len(lf.Entries))
	}
	tests := []struct {
		what string
		ref  string
		want lockfile.Entry
	}{
		{
			what: "a JSR package the root of the workspace names",
			ref:  "jsr:@acme/direct@1.2.3",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("jsr:@acme/direct@1.2.3"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:b5c602496a6fa3ec200351d4253576677c198da714d1f4f90a86e3854de53b7a",
				Direct:    true,
				Line:      12,
			},
		},
		{
			what: "an entry the file records no hash for",
			ref:  "jsr:@acme/no-hash@0.1.0",
			want: lockfile.Entry{
				Ref:    model.MustParseRef("jsr:@acme/no-hash@0.1.0"),
				Source: lockfile.SourceRegistry,
				Direct: true,
				Line:   18,
			},
		},
		{
			what: "a package only another package asks for",
			ref:  "jsr:@acme/transitive@4.5.6",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("jsr:@acme/transitive@4.5.6"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:6b5de5b92d1216afb3b7f17eba3ebfc6c710c103cc75e7cc813e5262e018e63a",
				Line:      19,
			},
		},
		{
			what: "a scoped npm key with a peer suffix, asked for by the root",
			ref:  "npm:@prefresh/vite@2.4.11",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("npm:@prefresh/vite@2.4.11"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha512-ROhuZ8gTEGWrNl7LlLeg7Ar5aalecxOoGu4L1QIWZ1gOFHBhoyWRi+UsI7+J1dJJ1nOWyrqysgnEzWepxbXBBQ==",
				Direct:    true,
				Line:      24,
			},
		},
		{
			what: "what a workspace member asks for is direct too",
			ref:  "npm:member-only@3.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("npm:member-only@3.0.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha512-KX6mr4TzISahFxjJcT4MwKcz88PLWGsmp4lyDhy0997yccn9OL6qXgwgdz6NIGH4AOCB9Ip542E7NbjZPN9i3A==",
				Direct:    true,
				Line:      30,
			},
		},
		{
			what: "and so is what a package.json next to the deno.json asks for",
			ref:  "npm:package-json-dep@2.5.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("npm:package-json-dep@2.5.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha512-lApKvL11PGDe9WF41HDp/TjRDi1x4mkIUTD3LlAlKShmGEHX9J4t85uI/CRDm3SqcZIpirTgK/q7AFppag3PUA==",
				Direct:    true,
				Line:      33,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
	// The workspace also names a bare URL import, whose entries are the remote ones
	// this parser drops, so it must not make anything direct and must not complain.
	if len(lf.Dropped) != 1 || !strings.HasPrefix(lf.Dropped[0], "https://deno.land/x/oak@v12.6.1/mod.ts: ") {
		t.Errorf("dropped %v, want only the remote URL", lf.Dropped)
	}
}

func TestParseDropsEntriesItCannotRead(t *testing.T) {
	lf := parseFixture(t, "broken.deno.lock")

	if len(lf.Entries) != 1 || lf.Entries[0].Ref.String() != "jsr:@acme/readable@1.0.0" {
		t.Fatalf("entries = %+v, want the one readable package", lf.Entries)
	}
	if !lf.Entries[0].Direct || lf.Entries[0].Line != 13 {
		t.Errorf("readable package = %+v, want it direct and on line 13", lf.Entries[0])
	}
	want := []string{
		`jsr: key "@acme/no-version" is not a name and a version`,
		`jsr: key "novers" is not a name and a version`,
		"not-an-object@1.0.0: entry is string, not an object",
		`jsr:@acme/never-resolved@2: the workspace asks for it but "specifiers" gives it no version`,
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

// TestParseDropsWrongTypedMembers is the mixed file: one member of "specifiers" and
// three of "workspace" hold a value of the wrong type, and every one of them costs
// only itself. Parse is documented to drop what it cannot make sense of and keep the
// rest, so a file like this must still yield its packages rather than nothing.
func TestParseDropsWrongTypedMembers(t *testing.T) {
	lf := parseFixture(t, "wrong-types.deno.lock")

	if lf.Version != "5" {
		t.Errorf("Version = %q, want 5", lf.Version)
	}
	want := []lockfile.Entry{
		{
			Ref:       model.MustParseRef("jsr:@acme/direct@1.2.3"),
			Source:    lockfile.SourceRegistry,
			Integrity: "sha256:b5c602496a6fa3ec200351d4253576677c198da714d1f4f90a86e3854de53b7a",
			Direct:    true,
			Line:      11,
		},
		{
			// The workspace asks for it, but the specifier that would resolve the
			// request was dropped, so nothing marks the entry direct.
			Ref:       model.MustParseRef("jsr:@acme/wrong-type@1.1.6"),
			Source:    lockfile.SourceRegistry,
			Integrity: "sha256:c672d5fc4d60cc1033c67c250301666000f53bca184a1bb25d3b267fe6fda4ba",
			Line:      14,
		},
		{
			// The member that names it is written after the one that is not an
			// object, so a member dropped must not cost the members around it.
			Ref:       model.MustParseRef("npm:member-only@3.0.0"),
			Source:    lockfile.SourceRegistry,
			Integrity: "sha512-KX6mr4TzISahFxjJcT4MwKcz88PLWGsmp4lyDhy0997yccn9OL6qXgwgdz6NIGH4AOCB9Ip542E7NbjZPN9i3A==",
			Direct:    true,
			Line:      19,
		},
	}
	if len(lf.Entries) != len(want) {
		t.Fatalf("read %d entries, want %d: %+v", len(lf.Entries), len(want), lf.Entries)
	}
	for i, w := range want {
		if got := lf.Entries[i]; got != w {
			t.Errorf("entry %d =\n %+v\nwant\n %+v", i, got, w)
		}
	}

	wantDropped := []string{
		"specifiers: jsr:@acme/wrong-type@1 is array, not a version string",
		`workspace "dependencies": an entry is number, not a requirement string`,
		`workspace "packageJson" "dependencies": the value is string, not a list of requirements`,
		`workspace member "packages/broken": the value is string, not an object`,
		`jsr:@acme/wrong-type@1: the workspace asks for it but "specifiers" gives it no version`,
	}
	if len(lf.Dropped) != len(wantDropped) {
		t.Fatalf("dropped %d reasons, want %d:\n%s", len(lf.Dropped), len(wantDropped), strings.Join(lf.Dropped, "\n"))
	}
	for i, prefix := range wantDropped {
		if !strings.HasPrefix(lf.Dropped[i], prefix) {
			t.Errorf("drop %d = %q, want it to start with %q", i, lf.Dropped[i], prefix)
		}
	}
}

// TestParseStillRefusesWhatItCannotFind pins the other half of the decision above: a
// member of the wrong type is dropped, but a file that is not JSON and a format
// version whose maps are somewhere else are still whole file failures.
func TestParseStillRefusesWhatItCannotFind(t *testing.T) {
	tests := []struct {
		what string
		in   string
	}{
		{what: "a file that is not JSON at all", in: "this is not JSON"},
		{what: "a version below 4", in: `{"version": "3", "packages": {}}`},
		{what: `a "specifiers" that is not an object`, in: `{"version": "5", "specifiers": []}`},
		{what: `a "workspace" that is not an object`, in: `{"version": "5", "workspace": "root"}`},
	}
	for _, tt := range tests {
		lf, err := Parser{}.Parse("deno.lock", strings.NewReader(tt.in))
		if err == nil {
			t.Errorf("%s: Parse accepted it and returned %+v", tt.what, lf)
			continue
		}
		if !strings.Contains(err.Error(), Format) {
			t.Errorf("%s: error = %v, want it to name the file", tt.what, err)
		}
	}
}

// TestParseReadsCRLF proves the line numbers on a Windows checkout: the same file
// with CRLF endings must give the same entries on the same lines. The fixture is
// only a test of anything while it really carries them, and the repository
// normalizes every other file to LF, so that is checked first.
func TestParseReadsCRLF(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "crlf.deno.lock"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Contains(data, []byte("\r\n")) {
		t.Fatal("the fixture has lost its carriage returns, so it tests nothing: see testdata/.gitattributes")
	}
	lf := parseFixture(t, "sources.deno.lock")
	crlf := parseFixture(t, "crlf.deno.lock")

	if len(crlf.Entries) != len(lf.Entries) {
		t.Fatalf("read %d entries from the CRLF file, want %d", len(crlf.Entries), len(lf.Entries))
	}
	for i, want := range lf.Entries {
		if got := crlf.Entries[i]; got != want {
			t.Errorf("entry %d =\n %+v\nwant\n %+v", i, got, want)
		}
	}
}

func TestParseRefusesAFormatVersionItCannotFind(t *testing.T) {
	path := filepath.Join("testdata", "version-3.deno.lock")
	f, err := os.Open(path) // #nosec G304 -- the path is a test fixture in this package
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	_, err = Parser{}.Parse(path, f)
	if err == nil {
		t.Fatal("Parse accepted a version 3 file")
	}
	for _, want := range []string{Format, "version 3", "packages"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

// TestParseReportsATruncatedFile is the "half a file" case: a lockfile cut in the
// middle must come back as an error naming the file, and must not panic.
func TestParseReportsATruncatedFile(t *testing.T) {
	path := filepath.Join("testdata", "truncated.deno.lock")
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

func TestParseRejectsAFileThatIsNotJSON(t *testing.T) {
	_, err := Parser{}.Parse("deno.lock", strings.NewReader("this is not JSON"))
	if err == nil {
		t.Fatal("Parse accepted a file that is not JSON")
	}
	if !strings.Contains(err.Error(), Format) {
		t.Errorf("error = %v, want it to name the file", err)
	}
}

func TestSplitKeyReadsNameAndVersion(t *testing.T) {
	tests := []struct {
		in          string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{in: "keychain@1.5.0", wantName: "keychain", wantVersion: "1.5.0", wantOK: true},
		{in: "@std/path@1.1.6", wantName: "@std/path", wantVersion: "1.1.6", wantOK: true},
		{
			// The peer suffix carries "@" of its own, so the version cannot be found
			// by looking at the last one.
			in:          "@octokit/plugin-paginate-rest@14.0.0_@octokit+core@7.0.7",
			wantName:    "@octokit/plugin-paginate-rest",
			wantVersion: "14.0.0",
			wantOK:      true,
		},
		{in: "vite@7.3.1__@types+node@24.9.2", wantName: "vite", wantVersion: "7.3.1", wantOK: true},
		{in: "under_score@2.0.0", wantName: "under_score", wantVersion: "2.0.0", wantOK: true},
		{in: "@scope/name", wantOK: false},
		{in: "novers", wantOK: false},
		{in: "@1.0.0", wantOK: false},
		{in: "", wantOK: false},
	}
	for _, tt := range tests {
		name, version, ok := splitKey(tt.in)
		if ok != tt.wantOK || name != tt.wantName || version != tt.wantVersion {
			t.Errorf("splitKey(%q) = %q, %q, %v, want %q, %q, %v", tt.in, name, version, ok, tt.wantName, tt.wantVersion, tt.wantOK)
		}
	}
}

func TestFormatVersionRendersWhatTheFileWrote(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{
		{in: nil, want: ""},
		{in: "4", want: "4"},
		{in: "5", want: "5"},
		{in: float64(3), want: "3"},
		{in: true, want: "true"},
	}
	for _, tt := range tests {
		if got := formatVersion(tt.in); got != tt.want {
			t.Errorf("formatVersion(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCheckVersionRefusesOnlyWhatItCannotFind(t *testing.T) {
	tests := []struct {
		version string
		wantErr bool
	}{
		{version: "1", wantErr: true},
		{version: "3", wantErr: true},
		{version: "4"},
		{version: "5"},
		{version: "6"},
		// A version this parser cannot read as a number is let through, because a
		// later Deno numbering its formats differently is more likely readable than
		// not, and an unreadable file then fails where it really goes wrong.
		{version: ""},
		{version: "5.1"},
	}
	for _, tt := range tests {
		err := checkVersion(tt.version)
		if (err != nil) != tt.wantErr {
			t.Errorf("checkVersion(%q) = %v, want an error: %v", tt.version, err, tt.wantErr)
		}
	}
}
