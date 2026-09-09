package pipreq

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

func TestDetectAcceptsTheNamesARequirementsFileIsGiven(t *testing.T) {
	tests := []struct {
		base string
		want bool
	}{
		{base: "requirements.txt", want: true},
		{base: "requirements-dev.txt", want: true},
		{base: "requirements_dev.txt", want: true},
		{base: "requirements.dev.txt", want: true},
		{base: "requirements-prod.txt", want: true},
		// lockfile.For lowercases the name, but a caller with the name as written
		// gets the same answer.
		{base: "REQUIREMENTS.TXT", want: true},
		// A name that carries its parent directory, which is the only way a file in
		// a requirements directory can be recognized at all.
		{base: "requirements/main.txt", want: true},
		{base: "requirements/dev.txt", want: true},
		{base: `requirements\dev.txt`, want: true},
		{base: "project/requirements/deploy.txt", want: true},
		// The base name alone from that layout says nothing, and accepting it would
		// swallow every text file in the repository.
		{base: "main.txt", want: false},
		{base: "notes/main.txt", want: false},
		{base: "requirements/README.md", want: false},
		// The word at the other end, which only the environment words reach. A product's
		// written requirements land on the same shape and are not a dependency set.
		{base: "dev-requirements.txt", want: true},
		{base: "test_requirements.txt", want: true},
		{base: "docs.requirements.txt", want: true},
		{base: "project/prod-requirements.txt", want: true},
		{base: "my-requirements.txt", want: false},
		{base: "system-requirements.txt", want: false},
		{base: "hardware_requirements.txt", want: false},
		{base: "requirementsdev.txt", want: false},
		{base: "devrequirements.txt", want: false},
		{base: "requirementsfoo.txt", want: false},
		{base: "requirements.in", want: false},
		{base: "poetry.lock", want: false},
		{base: "", want: false},
		// A requirements directory holds documentation too, and a README that shows a
		// pinned requirement in an example would otherwise be read as a file that pins
		// it. The words are refused however they are capitalized and whatever they are
		// suffixed with.
		{base: "requirements/README.txt", want: false},
		{base: "requirements/readme.txt", want: false},
		{base: "requirements/readme-first.txt", want: false},
		{base: "requirements/CHANGELOG.txt", want: false},
		{base: "requirements/changelog.old.txt", want: false},
		{base: "requirements/LICENSE.txt", want: false},
		{base: "requirements/NOTICE.txt", want: false},
		{base: "requirements/AUTHORS.txt", want: false},
		{base: `project\requirements\README.txt`, want: false},
		// A word that only begins with one of them is still a requirements file, since
		// the rule is about the word and not about its first letters.
		{base: "requirements/readmes.txt", want: true},
		{base: "requirements/licensing.txt", want: true},
	}
	for _, tt := range tests {
		if got := (Parser{}).Detect(tt.base); got != tt.want {
			t.Errorf("Detect(%q) = %v, want %v", tt.base, got, tt.want)
		}
	}
}

func TestParserIsRegistered(t *testing.T) {
	p, ok := lockfile.For("some/project/requirements.txt")
	if !ok {
		t.Fatal("lockfile.For(requirements.txt) found no parser")
	}
	if p.Name() != Format {
		t.Fatalf("registered parser is %q, want %q", p.Name(), Format)
	}
	if _, ok := lockfile.For("some/project/requirements-dev.txt"); !ok {
		t.Error("lockfile.For(requirements-dev.txt) found no parser")
	}
	if _, ok := lockfile.For("some/project/requirements/main.txt"); !ok {
		t.Error("lockfile.For(requirements/main.txt) found no parser")
	}
	// The walker asks lockfile.For about every file it finds, so a documentation file
	// this parser claims becomes a lockfile and the requirement an example quotes
	// becomes a package a scan reports on.
	for _, path := range []string{
		"some/project/requirements/README.txt",
		"some/project/requirements/CHANGELOG.txt",
		"some/project/requirements/LICENSE.txt",
	} {
		if p, ok := lockfile.For(path); ok {
			t.Errorf("lockfile.For(%s) chose %s, want no parser for a documentation file", path, p.Name())
		}
	}
}

func TestParseAGeneratedFile(t *testing.T) {
	lf := parseFixture(t, "warehouse-main.requirements.txt")

	if lf.Format != Format || lf.Ecosystem != model.PyPI {
		t.Errorf("Format = %q, Ecosystem = %q", lf.Format, lf.Ecosystem)
	}
	if lf.Version != "" {
		t.Errorf("Version = %q, want an empty string: a requirements file declares no format version", lf.Version)
	}
	if len(lf.Entries) != 184 {
		t.Errorf("read %d entries, want 184", len(lf.Entries))
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
			what: "the first requirement of the file, on the line its name sits on",
			ref:  "pypi:alembic@1.18.5",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:alembic@1.18.5"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:06d8ba9d04558022f5395e9317de03d270f3dced49cee01f89fe7a13c26f14bc",
				Line:      7,
			},
		},
		{
			// Twenty six hashes, one per wheel, and the entry keeps the first.
			what: "a requirement whose hash list runs over twenty six physical lines",
			ref:  "pypi:argon2-cffi-bindings@25.1.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:argon2-cffi-bindings@25.1.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:1db89609c06afa1a214a69a462ea741cf735b29a57530478c06eb81dd403de99",
				Line:      31,
			},
		},
		{
			what: "the last requirement, under the comment pip-compile ends the file with",
			ref:  "pypi:setuptools@81.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:setuptools@81.0.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:487b53915f52501f0a79ccfd0c02c165ffe06631443a886740b91af4b7a5845a",
				Line:      2676,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
	// A requirements file is one flat list with no field separating a requirement a
	// person wrote from one pip-compile appended, so nothing may be called direct.
	for _, e := range lf.Entries {
		if e.Direct || e.Dev || e.Optional || e.Bundled {
			t.Errorf("entry %s carries a flag the format does not state: %+v", e.Ref, e)
		}
	}
}

func TestParseReadsEveryShapeOfEntry(t *testing.T) {
	lf := parseFixture(t, "edge-cases.requirements.txt")

	if len(lf.Entries) != 4 {
		t.Fatalf("read %d entries, want 4: %+v", len(lf.Entries), lf.Entries)
	}
	tests := []struct {
		what string
		ref  string
		want lockfile.Entry
	}{
		{
			what: "a pin whose hashes continue over two more lines, and a comment after it",
			ref:  "pypi:requests@2.32.3",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:requests@2.32.3"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:bd0c80ddb748e530fc1c4dec6b66909a820f246d37f72b3461438ce1fcd8a30a",
				Line:      14,
			},
		},
		{
			what: "extras and an environment marker, neither of which changes the pin",
			ref:  "pypi:requests-toolbelt@1.0.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:requests-toolbelt@1.0.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:3e964af9127513d2ccfa9bed549b2cc7b4629bc43cc9f507d22b8d0afabd9292",
				Line:      20,
			},
		},
		{
			what: "a hash given as a separate argument rather than glued to the option",
			ref:  "pypi:six@1.17.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:six@1.17.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:c2730c816acbc0dcf6dfc3824f3af0a90298c916d0c7f22786914e995fdd09ad",
				Line:      24,
			},
		},
		{
			what: "the line under a comment that ends in a backslash, which does not continue",
			ref:  "pypi:flask@3.1.0",
			want: lockfile.Entry{
				Ref:       model.MustParseRef("pypi:flask@3.1.0"),
				Source:    lockfile.SourceRegistry,
				Integrity: "sha256:c30697e239f1b8f6406b32bba73904fbb5a84d85fbdf79b286dcc708ae03f51c",
				Line:      27,
			},
		},
	}
	for _, tt := range tests {
		if got := entryOf(t, lf, tt.ref); got != tt.want {
			t.Errorf("%s: entry %s =\n %+v\nwant\n %+v", tt.what, tt.ref, got, tt.want)
		}
	}
}

// TestParseDropsWhatItCannotEvaluate walks the other half of the edge case file:
// every line that pins something the parser cannot turn into an entry, each with the
// reason the package comment gives for it. The options at the top of the file, the
// blank lines and the comments are not in this list, because they install nothing
// and are ignored rather than dropped.
func TestParseDropsWhatItCannotEvaluate(t *testing.T) {
	lf := parseFixture(t, "edge-cases.requirements.txt")

	want := []struct {
		what   string
		reason string
	}{
		{what: "a comment ends a continuation, leaving the requirement above unguarded", reason: "line 31: urllib3==2.5.0 carries no --hash"},
		{what: "a range", reason: `line 36: "django>=4.2" is not a name and one pinned version`},
		{what: "a compound specifier", reason: `line 39: "jinja2==3.1.4,!=3.1.5" is not a name and one pinned version`},
		{what: "a wildcard", reason: `line 42: "click==8.1.*" is not a name and one pinned version`},
		{what: "arbitrary equality", reason: `line 45: "werkzeug===3.0.1" is not a name and one pinned version`},
		{what: "a bare name", reason: `line 48: "pyyaml" is not a name and one pinned version`},
		{what: "a marker with no pin", reason: `line 51: "tomli" is not a name and one pinned version`},
		{what: "a pin with no hash", reason: "line 54: certifi==2024.8.30 carries no --hash"},
		{what: "a hash with no algorithm, which pip would not accept either", reason: "line 57: packaging==24.2 carries no --hash"},
		{what: "a URL requirement", reason: `line 60: "https://files.example.com/wheels/wheel_only-1.0.0-py3-none-any.whl" is not a name and one pinned version`},
		{what: "a URL requirement with a name in front of it", reason: `line 63: "sqlalchemy @ https://files.example.com/sqlalchemy-2.0.36.tar.gz" is not a name and one pinned version`},
		{what: "an editable install of the project", reason: `line 66: "-e ." is an editable install`},
		{what: "an editable install from a repository", reason: `line 69: "-e git+https://github.com/example/pkg.git#egg=pkg" is an editable install`},
		{what: "an include", reason: `line 72: "-r requirements/main.txt" names another requirements file`},
		{what: "a constraints file", reason: `line 75: "-c constraints.txt" names another requirements file`},
	}
	if len(lf.Dropped) != len(want) {
		t.Fatalf("dropped %d lines, want %d:\n%s", len(lf.Dropped), len(want), strings.Join(lf.Dropped, "\n"))
	}
	for i, tt := range want {
		if !strings.HasPrefix(lf.Dropped[i], tt.reason) {
			t.Errorf("%s: drop %d = %q, want it to start with %q", tt.what, i, lf.Dropped[i], tt.reason)
		}
	}
}

// TestParseReadsCRLF proves the continuations and the line numbers on a Windows
// checkout: the same file with CRLF endings must give the same entries and the same
// reasons. The fixture is only a test of anything while it really carries them, and
// the repository normalizes every other file to LF, so that is checked first.
func TestParseReadsCRLF(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "crlf.requirements.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Contains(data, []byte("\r\n")) {
		t.Fatal("the fixture has lost its carriage returns, so it tests nothing: see testdata/.gitattributes")
	}
	lf := parseFixture(t, "edge-cases.requirements.txt")
	crlf := parseFixture(t, "crlf.requirements.txt")

	if len(crlf.Entries) != len(lf.Entries) {
		t.Fatalf("read %d entries from the CRLF file, want %d", len(crlf.Entries), len(lf.Entries))
	}
	for i, want := range lf.Entries {
		if got := crlf.Entries[i]; got != want {
			t.Errorf("entry %d =\n %+v\nwant\n %+v", i, got, want)
		}
	}
	if strings.Join(crlf.Dropped, "\n") != strings.Join(lf.Dropped, "\n") {
		t.Errorf("the CRLF file dropped\n%s\nwant\n%s", strings.Join(crlf.Dropped, "\n"), strings.Join(lf.Dropped, "\n"))
	}
}

// TestParseReportsATruncatedFile is the "half a file" case. A text format has no
// syntax to fail on, so a file cut in the middle of a requirement comes back as a
// parse with the half requirement dropped and a reason saying what happened, which
// is what the rest of this package does with a line it cannot read.
func TestParseReportsATruncatedFile(t *testing.T) {
	lf := parseFixture(t, "truncated.requirements.txt")

	if len(lf.Entries) != 0 {
		t.Errorf("entries = %+v, want none: the only requirement in the file is cut in half", lf.Entries)
	}
	if len(lf.Dropped) != 1 {
		t.Fatalf("dropped %v, want one reason", lf.Dropped)
	}
	if !strings.HasPrefix(lf.Dropped[0], "line 5: the file ends on a line continuation") {
		t.Errorf("drop = %q, want it to say the file ends on a continuation", lf.Dropped[0])
	}
}

func TestParseReadsAnEmptyFile(t *testing.T) {
	lf, err := Parser{}.Parse("requirements.txt", strings.NewReader(""))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(lf.Entries) != 0 || len(lf.Dropped) != 0 {
		t.Errorf("entries = %+v, dropped = %v, want neither", lf.Entries, lf.Dropped)
	}
}

func TestSplitPinReadsOnlyAnExactVersion(t *testing.T) {
	tests := []struct {
		in          string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{in: "requests==2.32.3", wantName: "requests", wantVersion: "2.32.3", wantOK: true},
		{in: "  requests == 2.32.3  ", wantName: "requests", wantVersion: "2.32.3", wantOK: true},
		{in: "requests[socks]==2.32.3", wantName: "requests", wantVersion: "2.32.3", wantOK: true},
		{in: "requests[socks,use-chardet]==2.32.3", wantName: "requests", wantVersion: "2.32.3", wantOK: true},
		{in: "zope.interface==7.2", wantName: "zope.interface", wantVersion: "7.2", wantOK: true},
		{in: "backports_zoneinfo==0.2.1", wantName: "backports_zoneinfo", wantVersion: "0.2.1", wantOK: true},
		{in: "alembic==1.18.5.post1", wantName: "alembic", wantVersion: "1.18.5.post1", wantOK: true},
		{in: "django>=4.2"},
		{in: "django<5"},
		{in: "django~=4.2.0"},
		{in: "django!=4.2"},
		{in: "django"},
		{in: "django==4.2,!=4.2.1"},
		{in: "django==4.2.*"},
		{in: "django===4.2"},
		{in: "django=="},
		{in: "==4.2"},
		{in: "sqlalchemy @ https://files.example.com/sqlalchemy-2.0.36.tar.gz"},
		{in: "https://files.example.com/wheel_only-1.0.0-py3-none-any.whl"},
		{in: "requests[socks==2.32.3"},
		{in: ""},
	}
	for _, tt := range tests {
		name, version, ok := splitPin(tt.in)
		if ok != tt.wantOK || name != tt.wantName || version != tt.wantVersion {
			t.Errorf("splitPin(%q) = %q, %q, %v, want %q, %q, %v", tt.in, name, version, ok, tt.wantName, tt.wantVersion, tt.wantOK)
		}
	}
}

func TestHashesOfReadsBothSpellings(t *testing.T) {
	tests := []struct {
		what string
		in   []string
		want []string
	}{
		{what: "no options at all", in: nil},
		{what: "glued to the option", in: []string{"--hash=sha256:aa"}, want: []string{"sha256:aa"}},
		{what: "a separate argument", in: []string{"--hash", "sha256:aa"}, want: []string{"sha256:aa"}},
		{
			what: "several, in the order the file lists them",
			in:   []string{"--hash=sha256:aa", "--hash=sha512:bb"},
			want: []string{"sha256:aa", "sha512:bb"},
		},
		{
			what: "an option that only starts the same way is not a hash",
			in:   []string{"--hash-algorithm=sha256"},
		},
		{what: "no algorithm, which pip would not accept", in: []string{"--hash=deadbeef"}},
		{what: "no digest", in: []string{"--hash=sha256:"}},
		{what: "nothing after the option", in: []string{"--hash"}},
		{
			what: "other options are left alone",
			in:   []string{"--no-binary", ":all:", "--hash=sha256:aa"},
			want: []string{"sha256:aa"},
		},
	}
	for _, tt := range tests {
		got := hashesOf(tt.in)
		if strings.Join(got, " ") != strings.Join(tt.want, " ") {
			t.Errorf("%s: hashesOf(%v) = %v, want %v", tt.what, tt.in, got, tt.want)
		}
	}
}

func TestStripCommentFollowsPip(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "requests==2.32.3", want: "requests==2.32.3"},
		{in: "requests==2.32.3 # via -r main.in", want: "requests==2.32.3 "},
		{in: "requests==2.32.3\t# via", want: "requests==2.32.3\t"},
		{in: "# a whole line", want: ""},
		// A "#" that follows something other than whitespace is part of the value,
		// which is what keeps an egg fragment on a URL intact.
		{in: "-e git+https://host/pkg.git#egg=pkg", want: "-e git+https://host/pkg.git#egg=pkg"},
	}
	for _, tt := range tests {
		if got := stripComment(tt.in); got != tt.want {
			t.Errorf("stripComment(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSplitOptionsKeepsTheMarkerWithTheRequirement(t *testing.T) {
	tests := []struct {
		in          string
		wantSpec    string
		wantOptions string
	}{
		{in: "requests==2.32.3", wantSpec: "requests==2.32.3"},
		{
			in:          "requests==2.32.3 --hash=sha256:aa",
			wantSpec:    "requests==2.32.3",
			wantOptions: "--hash=sha256:aa",
		},
		{
			// A marker holds no argument beginning with a dash, so it stays where it
			// belongs however it is spaced.
			in:          `tomli==2.0.1 ; python_version < "3.11" --hash=sha256:aa`,
			wantSpec:    `tomli==2.0.1 ; python_version < "3.11"`,
			wantOptions: "--hash=sha256:aa",
		},
		{in: "", wantSpec: ""},
	}
	for _, tt := range tests {
		spec, options := splitOptions(tt.in)
		if spec != tt.wantSpec || strings.Join(options, " ") != tt.wantOptions {
			t.Errorf("splitOptions(%q) = %q, %v, want %q, %q", tt.in, spec, options, tt.wantSpec, tt.wantOptions)
		}
	}
}
