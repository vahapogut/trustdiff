package yarn

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// parseFixtureC reads a fixture and parses it, failing the test on either error.
func parseFixtureC(t *testing.T, name string) *lockfile.Lockfile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	lf, err := parser{}.Parse(name, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return lf
}

func findC(t *testing.T, lf *lockfile.Lockfile, ref string) lockfile.Entry {
	t.Helper()
	var found []lockfile.Entry
	for _, e := range lf.Entries {
		if e.Ref.String() == ref {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: %d entries, want one; entries: %v", ref, len(found), refsC(lf))
	}
	return found[0]
}

func refsC(lf *lockfile.Lockfile) []string {
	out := make([]string, 0, len(lf.Entries))
	for _, e := range lf.Entries {
		out = append(out, e.Ref.String())
	}
	return out
}

// The yarn.lock Yarn 1 writes is a different file from the one Yarn 2 writes, and
// until now this parser read only the second: React's lockfile, 2394 entries of it,
// came back as "not read" from a scan on 2026-09-12, and so does every repository
// that never migrated. The format is the one Yarn 1 wrote from 2017 on: a key of
// comma separated descriptors, quoted or bare, and two space indented fields whose
// values are quoted.
func TestParseClassicReadsARealYarn1Lockfile(t *testing.T) {
	lf := parseFixtureC(t, "react-v1.yarn.lock")

	if lf.Format != "yarn.lock" || lf.Ecosystem != model.NPM {
		t.Errorf("format = %s/%s, want yarn.lock/npm", lf.Format, lf.Ecosystem)
	}
	if lf.Version != "1" {
		t.Errorf("Version = %q, want 1, which is what the header states", lf.Version)
	}

	// An ordinary registry entry, with the integrity Yarn wrote and the line its key
	// sits on.
	frame := findC(t, lf, "npm:@babel/code-frame@7.12.11")
	if frame.Source != lockfile.SourceRegistry {
		t.Errorf("source = %s, want registry", frame.Source)
	}
	if want := "sha512-Zt1yodBx1UcyiePMSkWnU4hPqhwq7hGi2nFL1LeA3EUl+q2LQx16MISgJ0+z7dnmgvP9QtIleuETGOiOH1RcIw=="; frame.Integrity != want {
		t.Errorf("integrity = %q, want %q", frame.Integrity, want)
	}
	if frame.Line != 5 {
		t.Errorf("line = %d, want 5, the line the key is on", frame.Line)
	}

	// An alias: the key names the alias and the installed package is the one after
	// "npm:". Every lookup a check makes wants the installed name.
	alias := findC(t, lf, "npm:@typescript-eslint/parser@2.34.0")
	if alias.Source != lockfile.SourceRegistry {
		t.Errorf("alias source = %s, want registry", alias.Source)
	}

	// A link: entry is a directory of the repository, and it carries no integrity
	// because there is no artifact to hash.
	link := findC(t, lf, "npm:eslint-plugin-react-internal@0.0.0")
	if link.Source != lockfile.SourcePath {
		t.Errorf("link source = %s, want path", link.Source)
	}
	if link.Integrity != "" {
		t.Errorf("link integrity = %q, want none", link.Integrity)
	}

	// A key with several descriptors is one entry, and a second version of the same
	// package is a second entry.
	findC(t, lf, "npm:@babel/code-frame@7.24.2")

	// Bare descriptors, which Yarn writes wherever no quoting is needed.
	findC(t, lf, "npm:semver@5.7.1")
}

// The shapes React's lockfile does not have. Hand built, which testdata/README.md
// says.
func TestParseClassicReadsTheOtherSources(t *testing.T) {
	lf := parseFixtureC(t, "classic-edge-cases.yarn.lock")

	for _, tc := range []struct {
		ref    string
		source lockfile.Source
	}{
		{"npm:from-git@1.2.3", lockfile.SourceGit},
		{"npm:from-github@2.0.0", lockfile.SourceGit},
		{"npm:from-tarball@3.0.0", lockfile.SourceURL},
		{"npm:from-folder@4.0.0", lockfile.SourcePath},
		{"npm:legacy-sha1@1.0.4", lockfile.SourceRegistry},
	} {
		if got := findC(t, lf, tc.ref).Source; got != tc.source {
			t.Errorf("%s: source = %s, want %s", tc.ref, got, tc.source)
		}
	}

	// Yarn 1 wrote the sha1 of the tarball into the resolved URL before the
	// integrity field existed, and that is the integrity the file states.
	if got := findC(t, lf, "npm:legacy-sha1@1.0.4").Integrity; got != "sha1-2222222222222222222222222222222222222222" {
		t.Errorf("legacy integrity = %q, want the sha1 from the resolved url", got)
	}

	// An entry with no version has nothing to evaluate and is dropped with a reason
	// rather than guessed at.
	for _, e := range lf.Entries {
		if e.Ref.Name == "no-version" {
			t.Errorf("an entry with no version was kept: %+v", e)
		}
	}
	var said bool
	for _, d := range lf.Dropped {
		if bytes.Contains([]byte(d), []byte("no-version")) {
			said = true
		}
	}
	if !said {
		t.Errorf("nothing in the dropped list mentions the entry with no version: %v", lf.Dropped)
	}
}

// The shape this parser used to reject, inline and small, which is what a file
// straight out of Yarn 1 looks like.
func TestParseClassicReadsTheShapeItUsedToReject(t *testing.T) {
	const body = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n" +
		"# yarn lockfile v1\n\n\n" +
		"\"@babel/code-frame@^7.0.0\":\n" +
		"  version \"7.0.0\"\n" +
		"  resolved \"https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.0.0.tgz#06e2ab19bdb535385559aabb5ba59729482800f8\"\n"

	lf, err := parser{}.Parse("yarn.lock", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e := findC(t, lf, "npm:@babel/code-frame@7.0.0")
	if e.Source != lockfile.SourceRegistry {
		t.Errorf("source = %s, want registry", e.Source)
	}
	// The file predates the integrity field, and the sha1 in the resolved URL is
	// the hash it states.
	if want := "sha1-06e2ab19bdb535385559aabb5ba59729482800f8"; e.Integrity != want {
		t.Errorf("integrity = %q, want %q", e.Integrity, want)
	}
}
