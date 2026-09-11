package npm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// The recorded fixtures. testdata/README.md says where each one came from.
const (
	edgeCasesFixture = "testdata/edge-cases-package-lock.json"
	largeFixture     = "testdata/superset-frontend-package-lock.json"
	legacyV2Fixture  = "testdata/minimatch-package-lock.json"
	version1Fixture  = "testdata/rimraf-v1-package-lock.json"
)

// readFixture reads a fixture into memory so a test can parse it more than once
// and can look at the lines a finding would point at.
func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

// parseFixture parses a fixture and fails the test if it does not parse.
func parseFixture(t *testing.T, path string) *lockfile.Lockfile {
	t.Helper()
	lf, err := parser{}.Parse(path, bytes.NewReader(readFixture(t, path)))
	if err != nil {
		t.Fatalf("Parse(%s) = %v, want no error", path, err)
	}
	return lf
}

// parseString parses a lockfile written inline in a test.
func parseString(t *testing.T, body string) (*lockfile.Lockfile, error) {
	t.Helper()
	return parser{}.Parse("package-lock.json", strings.NewReader(body))
}

// only returns the single entry with this ref and fails when there is not
// exactly one, so a test cannot silently assert against the wrong copy of a
// package that the tree holds at several versions.
func only(t *testing.T, lf *lockfile.Lockfile, ref string) lockfile.Entry {
	t.Helper()
	var found []lockfile.Entry
	for _, e := range lf.Entries {
		if e.Ref.String() == ref {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d entries for %s, want exactly 1", len(found), ref)
	}
	return found[0]
}

// keyLine returns the 1-based line the given "packages" key sits on, found by
// looking for the text npm writes, so the expected line is read out of the file
// rather than copied from the parser.
func keyLine(t *testing.T, data []byte, key string) int {
	t.Helper()
	want := `"` + key + `": {`
	for i, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == want {
			return i + 1
		}
	}
	t.Fatalf("key %q is not in the fixture", key)
	return 0
}

func TestParserRegistersItselfAndDetectsTheFileName(t *testing.T) {
	p, ok := lockfile.For(filepath.Join("web", "package-lock.json"))
	if !ok {
		t.Fatal("no parser is registered for package-lock.json")
	}
	if p.Name() != "package-lock.json" {
		t.Errorf("Name() = %q, want package-lock.json", p.Name())
	}
	tests := []struct {
		base string
		want bool
	}{
		{base: "package-lock.json", want: true},
		{base: "package-Lock.json", want: true},
		{base: "npm-shrinkwrap.json", want: false},
		{base: "package.json", want: false},
		{base: "pnpm-lock.yaml", want: false},
		{base: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.base, func(t *testing.T) {
			if got := (parser{}).Detect(tt.base); got != tt.want {
				t.Errorf("Detect(%q) = %v, want %v", tt.base, got, tt.want)
			}
		})
	}
}

func TestParseEdgeCasesReadsEveryField(t *testing.T) {
	lf := parseFixture(t, edgeCasesFixture)

	if lf.Path != edgeCasesFixture {
		t.Errorf("Path = %q, want %q", lf.Path, edgeCasesFixture)
	}
	if lf.Format != "package-lock.json" {
		t.Errorf("Format = %q, want package-lock.json", lf.Format)
	}
	if lf.Ecosystem != model.NPM {
		t.Errorf("Ecosystem = %q, want npm", lf.Ecosystem)
	}
	if lf.Version != "3" {
		t.Errorf("Version = %q, want 3", lf.Version)
	}

	// The entries in file order, which is the order npm writes and the order the
	// parser keeps. The line numbers are checked against the file below.
	want := []lockfile.Entry{
		{
			Ref:       model.MustParseRef("npm:@acme/widgets@2.1.0"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/@acme/widgets/-/widgets-2.1.0.tgz",
			Integrity: "sha512-YhyRfoKQj8x5c+gA6GvgPKqa09bou6bU+v9C2+KouJ/EaeBYOCxSetRuXfdTioMY6fHDF8ggvqZeo0wmVzJjdA==",
			Direct:    true,
			Line:      36,
		},
		{
			// The nested copy: the name is the part after the last node_modules.
			Ref:       model.MustParseRef("npm:left-pad@1.2.0"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz",
			Integrity: "sha512-z5ZxLclrleTKZTuphsPnA7j7dSmsYLmtKARw31e+NiGIIj3Kyc29kE6s2eKJklz4HESPRLuq/UzHsxjjjutpVw==",
			Line:      45,
		},
		{
			Ref:       model.MustParseRef("npm:build-only@5.5.5"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/build-only/-/build-only-5.5.5.tgz",
			Integrity: "sha512-rGk91PO0W4IkwL+QtjphWCw2r+UGYH2U4vbCtbwXZ8aOxHan4rTA2w6JndwwovZtlh/EkSLvJwjfWpjxqiuPoA==",
			Direct:    true,
			Dev:       true,
			Line:      51,
		},
		{
			// A bundled dependency: npm records no location and no hash for it,
			// because its bytes ship inside its parent's tarball.
			Ref:     model.MustParseRef("npm:bundled-helper@3.0.1"),
			Source:  lockfile.SourceUnknown,
			Dev:     true,
			Bundled: true,
			Line:    58,
		},
		{
			Ref:       model.MustParseRef("npm:fsevents-shim@1.0.0"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/fsevents-shim/-/fsevents-shim-1.0.0.tgz",
			Integrity: "sha512-DZMvaREnZPaKO689D56olzv/B76T9f/rysWUHy5RI81c2DfjbbKhPWmUDXF9lbIHX73PlkOR+nck4CIq7m7nPQ==",
			Direct:    true,
			Optional:  true,
			Line:      64,
		},
		{
			Ref:      model.MustParseRef("npm:git-dep@1.2.3"),
			Source:   lockfile.SourceGit,
			Resolved: "git+ssh://git@github.com/example/git-dep.git#0b1ff9be0f3c2e0a2c8ec6a9b0d4a26c8bbf3d51",
			Direct:   true,
			Line:     74,
		},
		{
			Ref:       model.MustParseRef("npm:local-tool@0.9.0"),
			Source:    lockfile.SourcePath,
			Resolved:  "file:vendor/local-tool-0.9.0.tgz",
			Integrity: "sha512-vGvQxcEycf6osE5UaHVbtkCRFRDU5it1HwPuerDOIYd6OSgRZ8Y2gFlvIuc+b9krLcvOolCCCjMYdV26A2X6rg==",
			Direct:    true,
			Dev:       true,
			Line:      79,
		},
		{
			Ref:       model.MustParseRef("npm:left-pad@1.3.0"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
			Integrity: "sha512-5M53BsOqcReBM10CEzSaGC4lddbxUMy9v+iLQ8GPQl2d27nb8yuN8GHr8JhtKZe3H3AIIBvsdZDfCqO8lqGa6Q==",
			Direct:    true,
			Line:      86,
		},
		{
			// Asked for by the workspace member rather than by the root, and
			// installed in the project's own node_modules: direct all the same.
			Ref:       model.MustParseRef("npm:member-only@2.0.0"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/member-only/-/member-only-2.0.0.tgz",
			Integrity: "sha512-Skk4CKZo4/pLlYsxpxzm/W0z2+Er6rKl/d3/PpXZJ+YAQyVpzfVvuTHsHMDKgpVascDW4ylJTeK05gL/QdjjdQ==",
			Direct:    true,
			Dev:       true,
			Line:      92,
		},
		{
			// Installed but reached from nothing in the tree, and still an install.
			Ref:       model.MustParseRef("npm:stray@0.0.1"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/stray/-/stray-0.0.1.tgz",
			Integrity: "sha512-YmqTYJxbHFWGvrLS2H+cmEk3lWuKfsoEvuUFKi62psVTILT4lhSiqfTRkWsRTzYRhc91haF60hVJZel0sD3S3g==",
			Line:      99,
		},
		{
			// devOptional is not dev. npm sets it on a package reached through the dev
			// tree and through an optional edge of something that is not dev, so
			// omitting dev alone leaves it installed. Finding F25 of
			// docs/review-2026-09-10.md.
			Ref:       model.MustParseRef("npm:swc-like@1.1.1"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/swc-like/-/swc-like-1.1.1.tgz",
			Integrity: "sha512-WWvkOIy8dnB8ejd8aXS9SVOwfKHdQ4rWUFU3SXi43BEm2Lsl+MFrQrM8yY8xGxeF6M36S6EsEpiZSLYgc7cgxQ==",
			Optional:  true,
			Line:      105,
		},
		{
			Ref:       model.MustParseRef("npm:tarball-dep@0.4.1"),
			Source:    lockfile.SourceURL,
			Resolved:  "https://files.example.com/tarball-dep-0.4.1.tgz",
			Integrity: "sha512-ko61OmtcWNpYl6/oFTb5+9fZSjadmNPnUkw8wLKmMVqSbnNgTw6dxNk2Ns9+RHTGZG4GJYwWXRPkV0HJrBHyTQ==",
			Direct:    true,
			Line:      112,
		},
		{
			// An alias: the key is what package.json calls the dependency
			// ("widgets-v1": "npm:@acme/widgets@^1"), "name" is the package that is
			// really installed, and the ref has to be the latter or every lookup is
			// made against a package that does not exist. Direct still comes from
			// the alias, which is how the dependency map spells it.
			Ref:       model.MustParseRef("npm:@acme/widgets@1.0.0"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/@acme/widgets/-/widgets-1.0.0.tgz",
			Integrity: "sha512-Gk3hXnvIvCwXfSao3UAEmW1IGuRYSFCmAzGqLwAbYWXGWX/H7K/pyvMiPgbbiffj2Zt5bPxuEuvFAUDGXjh/2w==",
			Direct:    true,
			Line:      118,
		},
		{
			// The workspace member the dropped link points at: the name comes from
			// the entry, not from the directory.
			Ref:    model.MustParseRef("npm:@acme/ui@0.3.0"),
			Source: lockfile.SourcePath,
			Line:   125,
		},
		{
			// A workspace member's own node_modules is not the project's, so this
			// copy of a direct dependency is not itself direct.
			Ref:       model.MustParseRef("npm:left-pad@1.1.0"),
			Source:    lockfile.SourceRegistry,
			Resolved:  "https://registry.npmjs.org/left-pad/-/left-pad-1.1.0.tgz",
			Integrity: "sha512-FkJZPYsAjNRAIi9nRw0OSmLrj965i5VVZTfwOPjp8XENf8yVrh54nQ3kKsInbNi6tdJL7Wt3hIyIDt+W8rkIvg==",
			Dev:       true,
			Line:      136,
		},
	}
	if len(lf.Entries) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(lf.Entries), len(want), lf.Entries)
	}
	for i, w := range want {
		if got := lf.Entries[i]; got != w {
			t.Errorf("entry %d:\n got %+v\nwant %+v", i, got, w)
		}
	}

	wantDropped := []string{
		"node_modules/@acme/ui: a link to packages/ui, not an install",
		"workspaces/bare-member: no version, nothing to evaluate",
	}
	if len(lf.Dropped) != len(wantDropped) {
		t.Fatalf("got %d dropped, want %d: %q", len(lf.Dropped), len(wantDropped), lf.Dropped)
	}
	for i, w := range wantDropped {
		if lf.Dropped[i] != w {
			t.Errorf("dropped %d = %q, want %q", i, lf.Dropped[i], w)
		}
	}
}

func TestParseEdgeCasesLineNumbersPointAtTheKey(t *testing.T) {
	data := readFixture(t, edgeCasesFixture)
	lf := parseFixture(t, edgeCasesFixture)

	// The key each entry came from, in file order.
	keys := []string{
		"node_modules/@acme/widgets",
		"node_modules/@acme/widgets/node_modules/left-pad",
		"node_modules/build-only",
		"node_modules/bundled-helper",
		"node_modules/fsevents-shim",
		"node_modules/git-dep",
		"node_modules/local-tool",
		"node_modules/left-pad",
		"node_modules/member-only",
		"node_modules/stray",
		"node_modules/swc-like",
		"node_modules/tarball-dep",
		"node_modules/widgets-v1",
		"packages/ui",
		"packages/ui/node_modules/left-pad",
	}
	if len(keys) != len(lf.Entries) {
		t.Fatalf("the fixture has %d entries and the test names %d keys", len(lf.Entries), len(keys))
	}
	for i, key := range keys {
		if want, got := keyLine(t, data, key), lf.Entries[i].Line; got != want {
			t.Errorf("%s: Line = %d, want %d", key, got, want)
		}
	}
}

func TestParseLockfileVersion2IgnoresTheLegacyDependenciesTree(t *testing.T) {
	lf := parseFixture(t, legacyV2Fixture)

	if lf.Version != "2" {
		t.Fatalf("Version = %q, want 2", lf.Version)
	}
	// The file holds 412 keys under "packages", the project's own entry included,
	// and a lockfileVersion 1 "dependencies" tree of 233 more names. Reading the
	// legacy tree as well would show up here.
	if want := 411; len(lf.Entries) != want {
		t.Errorf("got %d entries, want %d", len(lf.Entries), want)
	}
	if len(lf.Dropped) != 0 {
		t.Errorf("dropped %q, want nothing dropped", lf.Dropped)
	}

	// The project asks for brace-expansion and, to develop, for tap.
	direct := only(t, lf, "npm:brace-expansion@2.0.1")
	if !direct.Direct || direct.Dev {
		t.Errorf("brace-expansion@2.0.1: Direct = %v, Dev = %v, want true and false", direct.Direct, direct.Dev)
	}
	dev := only(t, lf, "npm:tap@15.1.6")
	if !dev.Direct || !dev.Dev {
		t.Errorf("tap@15.1.6: Direct = %v, Dev = %v, want both true", dev.Direct, dev.Dev)
	}
	// tap bundles its own tree, and npm records neither a location nor a hash for
	// a bundled package: its bytes ship inside tap's tarball, which is why the
	// entry says so rather than leaving the checks to guess.
	bundled := only(t, lf, "npm:@babel/core@7.16.0")
	if bundled.Source != lockfile.SourceUnknown || bundled.Resolved != "" || bundled.Integrity != "" {
		t.Errorf("bundled @babel/core@7.16.0 = %+v, want an unknown source with no resolved and no integrity", bundled)
	}
	if !bundled.Bundled {
		t.Error("bundled @babel/core@7.16.0 is not marked as shipping inside its parent")
	}
	if bundled.Direct {
		t.Error("bundled @babel/core@7.16.0 is marked direct")
	}
}

func TestParseLockfileVersion1IsAnError(t *testing.T) {
	_, err := parser{}.Parse(version1Fixture, bytes.NewReader(readFixture(t, version1Fixture)))
	if err == nil {
		t.Fatal("Parse of a lockfileVersion 1 file returned no error")
	}
	for _, want := range []string{"lockfileVersion 1", `"packages"`, "npm 7"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestParseLargeLockfile(t *testing.T) {
	data := readFixture(t, largeFixture)
	lf := parseFixture(t, largeFixture)

	if lf.Version != "3" {
		t.Errorf("Version = %q, want 3", lf.Version)
	}
	// The performance target of a 2000 entry lockfile is measured against this file.
	if len(lf.Entries) < 2000 {
		t.Fatalf("got %d entries, want at least 2000", len(lf.Entries))
	}
	// Every dropped line in this file is one of the workspace links.
	if want := 25; len(lf.Dropped) != want {
		t.Errorf("got %d dropped, want %d: %q", len(lf.Dropped), want, lf.Dropped)
	}
	for _, d := range lf.Dropped {
		if !strings.Contains(d, "a link to") {
			t.Errorf("dropped %q, want only workspace links", d)
		}
	}

	tests := []struct {
		name string
		key  string
		ref  string
		want lockfile.Entry
	}{
		{
			// Superset's root package.json does not ask for core-js; one of its
			// workspace members does, which makes it a direct dependency of the
			// workspace the same way it does in the other three ecosystems.
			name: "install from the registry a member asks for",
			key:  "node_modules/core-js",
			ref:  "npm:core-js@3.50.0",
			want: lockfile.Entry{
				Source:    lockfile.SourceRegistry,
				Resolved:  "https://registry.npmjs.org/core-js/-/core-js-3.50.0.tgz",
				Integrity: "sha512-BRWgOLKkFeCgRudR6zrs8p9XJZcE14grzKMMssoYrk6krtuEZ7MTKPIY5RzOnqsEKIR9kst7wNzphttraT+Yqw==",
				Direct:    true,
			},
		},
		{
			name: "install from git",
			key:  "node_modules/dom-to-image",
			ref:  "npm:dom-to-image@2.6.0",
			want: lockfile.Entry{
				Source:   lockfile.SourceGit,
				Resolved: "git+ssh://git@github.com/dmapper/dom-to-image.git#a7c386a8ea813930f05449ac71ab4be0c262dff3",
			},
		},
		{
			name: "install from a tarball that is not a registry",
			key:  "node_modules/xlsx",
			ref:  "npm:xlsx@0.20.3",
			want: lockfile.Entry{
				Source:    lockfile.SourceURL,
				Resolved:  "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz",
				Integrity: "sha512-oLDq3jw7AcLqKWH2AhCpVTZl8mf6X2YReP+Neh0SJUzV/BdZYjth94tG5toiMB1PPrYtxOCfaoUCkvtuH+3AJA==",
				Direct:    true,
			},
		},
		{
			// npm marks this one devOptional, which is not dev: Superset reaches it
			// through its dev tree and through an optional edge of something that is
			// not dev, so an install that omits dev still installs it.
			name: "direct dependency npm marks devOptional",
			key:  "node_modules/@swc/core",
			ref:  "npm:@swc/core@1.16.1",
			want: lockfile.Entry{
				Source:    lockfile.SourceRegistry,
				Resolved:  "https://registry.npmjs.org/@swc/core/-/core-1.16.1.tgz",
				Integrity: "sha512-nUaeu91O5QZKrQdaDCHd402ogUIoNOOjpkZNq0UomWK0G6gDaGmLhvddF1/3BXf5O8aLyo6ZPY/aMDWvaJQ/hg==",
				Direct:    true,
				Optional:  true,
			},
		},
		{
			name: "workspace member keeps its declared name",
			key:  "packages/superset-core",
			ref:  "npm:@apache-superset/core@0.1.0",
			want: lockfile.Entry{Source: lockfile.SourcePath},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := only(t, lf, tt.ref)
			want := tt.want
			want.Ref = model.MustParseRef(tt.ref)
			want.Line = keyLine(t, data, tt.key)
			if got != want {
				t.Errorf("%s:\n got %+v\nwant %+v", tt.key, got, want)
			}
		})
	}

	// The entries keep the file's order, so their lines only ever go forward.
	prev := 0
	for i, e := range lf.Entries {
		if e.Line <= prev {
			t.Fatalf("entry %d (%s) is on line %d, after line %d", i, e.Ref, e.Line, prev)
		}
		prev = e.Line
	}
}

func TestParseLargeLockfileStaysWellUnderASecond(t *testing.T) {
	data := readFixture(t, largeFixture)
	// The best of three runs, so a busy machine costs a rerun and not a red build.
	best := time.Duration(0)
	var entries int
	for i := 0; i < 3; i++ {
		start := time.Now()
		lf, err := parser{}.Parse(largeFixture, bytes.NewReader(data))
		took := time.Since(start)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		entries = len(lf.Entries)
		if best == 0 || took < best {
			best = took
		}
	}
	const budget = 500 * time.Millisecond
	t.Logf("parsed %d entries from %d bytes in %s", entries, len(data), best)
	if best > budget {
		t.Errorf("parsing %d entries took %s, want under %s", entries, best, budget)
	}
}

func TestParseReportsWhatItCannotRead(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "empty file", body: "", want: "lockfile"},
		{name: "not an object", body: `["package-lock.json"]`, want: "want an object"},
		{name: "packages is a list", body: `{"lockfileVersion":3,"packages":[]}`, want: `"packages"`},
		{name: "lockfileVersion is a string", body: `{"lockfileVersion":"3","packages":{}}`, want: "lockfileVersion"},
		{name: "truncated entry", body: `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"`, want: "unexpected EOF"},
		{name: "project entry is not an object", body: `{"lockfileVersion":3,"packages":{"":7}}`, want: "the project entry"},
		{name: "no packages at all", body: `{"lockfileVersion":3,"name":"x"}`, want: "lockfileVersion 3 has no"},
		{name: "no version and no packages", body: `{"name":"x"}`, want: "no lockfileVersion"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lf, err := parseString(t, tt.body)
			if err == nil {
				t.Fatalf("Parse returned %+v, want an error", lf)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestParseDropsOneUnreadableEntryRatherThanTheFile(t *testing.T) {
	lf, err := parseString(t, `{
		"lockfileVersion": 3,
		"packages": {
			"": {"dependencies": {"good": "^1.0.0"}},
			"node_modules/broken": "1.0.0",
			"node_modules/good": {"version": "1.0.0"}
		}
	}`)
	if err != nil {
		t.Fatalf("Parse = %v, want the readable entry", err)
	}
	if len(lf.Entries) != 1 || lf.Entries[0].Ref.Name != "good" {
		t.Fatalf("entries = %+v, want only good", lf.Entries)
	}
	if !lf.Entries[0].Direct {
		t.Error("good is not marked direct")
	}
	if len(lf.Dropped) != 1 || !strings.Contains(lf.Dropped[0], "node_modules/broken") {
		t.Fatalf("dropped = %q, want the broken entry with a reason", lf.Dropped)
	}
}

// TestParseMergesARepeatedPackagesObject reads a file that states "packages"
// twice. npm writes the key once, so such a file was not written by npm, but JSON
// allows it and readers disagree about which of the two wins, so every entry either
// object names has to survive the parse rather than a whole object's worth of
// installs disappearing without an entry and without a reason. The project entry is
// merged with it, because either object may carry one.
func TestParseMergesARepeatedPackagesObject(t *testing.T) {
	lf, err := parseString(t, `{
		"lockfileVersion": 3,
		"packages": {
			"": {"dependencies": {"a": "^1.0.0"}},
			"node_modules/a": {"version": "1.0.0"}
		},
		"packages": {
			"": {"devDependencies": {"b": "^2.0.0"}},
			"node_modules/b": {"version": "2.0.0", "dev": true}
		}
	}`)
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}
	if len(lf.Entries) != 2 {
		t.Fatalf("entries = %+v, want both a and b", lf.Entries)
	}
	if len(lf.Dropped) != 0 {
		t.Errorf("dropped %v, want nothing dropped: every entry of both objects is read", lf.Dropped)
	}
	a, b := only(t, lf, "npm:a@1.0.0"), only(t, lf, "npm:b@2.0.0")
	if !a.Direct || a.Dev {
		t.Errorf("a = %+v, want a direct dependency that is not a development one", a)
	}
	// b is asked for by the project entry of the second object, which is what says
	// the two project entries were merged rather than one of them read.
	if !b.Direct || !b.Dev {
		t.Errorf("b = %+v, want a direct development dependency", b)
	}
}

func TestParseFindsTheProjectEntryWhereverItSits(t *testing.T) {
	// npm writes the project first, but nothing in JSON says it has to be there.
	lf, err := parseString(t, `{
		"packages": {
			"node_modules/first": {"version": "1.0.0"},
			"node_modules/second": {"version": "2.0.0"},
			"": {"optionalDependencies": {"second": "^2.0.0"}}
		},
		"lockfileVersion": 3
	}`)
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}
	if lf.Version != "3" {
		t.Errorf("Version = %q, want 3", lf.Version)
	}
	if len(lf.Entries) != 2 {
		t.Fatalf("entries = %+v, want two", lf.Entries)
	}
	if lf.Entries[0].Direct {
		t.Error("first is marked direct although the project does not ask for it")
	}
	// Direct comes from the project entry, Optional only from the entry's own flag.
	if !lf.Entries[1].Direct || lf.Entries[1].Optional {
		t.Errorf("second = %+v, want a direct entry that is not itself marked optional", lf.Entries[1])
	}
}

func TestSourceOf(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		resolved string
		// file is what the rest of the lockfile resolves from, which is how a host
		// the project installs through is told from one entry's own host. It
		// defaults to the entry alone, a file of one package.
		file []string
		want lockfile.Source
	}{
		{name: "public registry", key: "node_modules/a", resolved: "https://registry.npmjs.org/a/-/a-1.0.0.tgz", want: lockfile.SourceRegistry},
		{name: "scoped name on the public registry", key: "node_modules/@s/a", resolved: "https://registry.npmjs.org/@s/a/-/a-1.0.0.tgz", want: lockfile.SourceRegistry},
		{name: "public registry over plain http", key: "node_modules/a", resolved: "http://registry.npmjs.org/a/-/a-1.0.0.tgz", want: lockfile.SourceRegistry},
		{name: "registry mirror", key: "node_modules/a", resolved: "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz", want: lockfile.SourceRegistry},
		{name: "private registry", key: "node_modules/a", resolved: "https://artifacts.example.com/api/npm/npm-all/a/-/a-1.0.0.tgz", want: lockfile.SourceRegistry},
		{name: "github packages", key: "node_modules/@s/a", resolved: "https://npm.pkg.github.com/download/@s/a/1.0.0/0f1e2d", want: lockfile.SourceRegistry},
		{name: "tarball on the web", key: "node_modules/a", resolved: "https://cdn.example.com/a-1.0.0.tgz", want: lockfile.SourceURL},
		{name: "release tarball", key: "node_modules/a", resolved: "https://github.com/o/r/releases/download/v1.0.0/a-1.0.0.tgz", want: lockfile.SourceURL},
		{name: "git over https", key: "node_modules/a", resolved: "git+https://github.com/o/r.git#0f1e2d", want: lockfile.SourceGit},
		{name: "git over ssh", key: "node_modules/a", resolved: "git+ssh://git@github.com/o/r.git#0f1e2d", want: lockfile.SourceGit},
		{name: "git protocol", key: "node_modules/a", resolved: "git://github.com/o/r.git#0f1e2d", want: lockfile.SourceGit},
		{name: "scp style remote", key: "node_modules/a", resolved: "git@github.com:o/r.git#0f1e2d", want: lockfile.SourceGit},
		{name: "remote ending in .git", key: "node_modules/a", resolved: "https://gitlab.example.com/o/r.git#0f1e2d", want: lockfile.SourceGit},
		{name: "local tarball", key: "node_modules/a", resolved: "file:vendor/a-1.0.0.tgz", want: lockfile.SourcePath},
		{name: "relative path", key: "node_modules/a", resolved: "../sibling", want: lockfile.SourcePath},
		{name: "bundled dependency", key: "node_modules/b/node_modules/a", resolved: "", want: lockfile.SourceUnknown},
		{name: "workspace member", key: "packages/ui", resolved: "", want: lockfile.SourcePath},
		{name: "scheme we do not know", key: "node_modules/a", resolved: "ftp://files.example.com/a-1.0.0.tgz", want: lockfile.SourceUnknown},
		// The host is compared whole, so a name that only ends in the registry's is
		// not the registry.
		{name: "lookalike host", key: "node_modules/a", resolved: "https://registry.npmjs.org.example.com/a-1.0.0.tgz", want: lockfile.SourceURL},
		{
			// The tarball layout is a shape anybody can serve, so on its own it
			// does not make a host a registry: this is the substitution the gate
			// exists to catch, and it has to be reported rather than pass silently.
			name:     "lookalike host serving the registry layout",
			key:      "node_modules/a",
			resolved: "https://registry.npmjs.org.example.com/a/-/a-1.0.0.tgz",
			file: []string{
				"https://registry.npmjs.org/b/-/b-1.0.0.tgz",
				"https://registry.npmjs.org/c/-/c-1.0.0.tgz",
				"https://registry.npmjs.org/d/-/d-1.0.0.tgz",
				"https://registry.npmjs.org.example.com/a/-/a-1.0.0.tgz",
			},
			want: lockfile.SourceURL,
		},
		{
			// A project that installs everything through one private registry keeps
			// every entry, which is what a mirror or an Artifactory looks like.
			name:     "a file that installs everything from one private host",
			key:      "node_modules/a",
			resolved: "https://artifacts.example.com/api/npm/npm-all/a/-/a-1.0.0.tgz",
			file: []string{
				"https://artifacts.example.com/api/npm/npm-all/a/-/a-1.0.0.tgz",
				"https://artifacts.example.com/api/npm/npm-all/b/-/b-1.0.0.tgz",
				"https://artifacts.example.com/api/npm/npm-all/c/-/c-1.0.0.tgz",
			},
			want: lockfile.SourceRegistry,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := tt.file
			if file == nil {
				file = []string{tt.resolved}
			}
			locks := make([]locked, 0, len(file))
			for _, resolved := range file {
				locks = append(locks, locked{key: "node_modules/x", pkg: jsonPackage{Resolved: resolved}})
			}
			if got := sourceOf(tt.key, tt.resolved, countRegistryHosts(locks)); got != tt.want {
				t.Errorf("sourceOf(%q, %q) = %q, want %q", tt.key, tt.resolved, got, tt.want)
			}
		})
	}
}

func TestInstallPath(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{name: "top level", key: "node_modules/left-pad", want: "left-pad"},
		{name: "scoped", key: "node_modules/@types/node", want: "@types/node"},
		{name: "nested", key: "node_modules/a/node_modules/b", want: "b"},
		{name: "nested scoped", key: "node_modules/a/node_modules/@types/node", want: "@types/node"},
		{name: "inside a workspace", key: "packages/ui/node_modules/left-pad", want: "left-pad"},
		{name: "an alias is the name package.json wrote", key: "node_modules/d3v3", want: "d3v3"},
		{name: "workspace member", key: "workspaces/libnpmaccess", want: "libnpmaccess"},
		{name: "no path at all", key: "solo", want: "solo"},
		{name: "path ending in node_modules", key: "node_modules/", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := installPath(tt.key); got != tt.want {
				t.Errorf("installPath(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestParseRecordsAnAliasUnderTheInstalledName(t *testing.T) {
	// The recorded Superset lockfile carries eight of these; this is the one the
	// npm documentation uses. The key is the alias, and what is installed, looked
	// up and reported is d3.
	lf, err := parseString(t, `{
		"lockfileVersion": 3,
		"packages": {
			"": {"dependencies": {"d3v3": "npm:d3@^3"}},
			"node_modules/d3v3": {
				"name": "d3",
				"version": "3.5.17",
				"resolved": "https://registry.npmjs.org/d3/-/d3-3.5.17.tgz",
				"integrity": "sha512-alias"
			}
		}
	}`)
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}
	if len(lf.Entries) != 1 {
		t.Fatalf("entries = %+v, want one", lf.Entries)
	}
	got := lf.Entries[0]
	if got.Ref.String() != "npm:d3@3.5.17" {
		t.Errorf("Ref = %s, want npm:d3@3.5.17", got.Ref)
	}
	if !got.Direct {
		t.Error("the alias is in the project's dependencies, so the entry is direct")
	}
}

func TestParseLargeLockfileReadsItsAliases(t *testing.T) {
	// Superset aliases eight packages, d3v3 and string-width-cjs among them. Each
	// one has to reach the checks under the name it really installs.
	lf := parseFixture(t, largeFixture)
	for _, tt := range []struct{ alias, ref string }{
		{alias: "d3v3", ref: "npm:d3@3.5.17"},
		{alias: "string-width-cjs", ref: "npm:string-width@4.2.3"},
	} {
		installed := 0
		for _, e := range lf.Entries {
			if e.Ref.String() == tt.ref {
				installed++
			}
			if e.Ref.Name == tt.alias {
				t.Errorf("%s is recorded under the alias, which is not a package on the registry", e.Ref)
			}
		}
		if installed == 0 {
			t.Errorf("no entry for %s, which is what the %s alias installs", tt.ref, tt.alias)
		}
	}
}

func TestParseCountsAWorkspaceMembersDependenciesAsDirect(t *testing.T) {
	// The root asks for nothing; the member asks for left-pad, and npm installs it
	// in the project's own node_modules. What a member declares the project
	// declares, which is what the cargo, pnpm and uv parsers already report.
	lf, err := parseString(t, `{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "root", "workspaces": ["packages/ui"]},
			"node_modules/@acme/ui": {"resolved": "packages/ui", "link": true},
			"node_modules/left-pad": {
				"version": "1.3.0",
				"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
				"integrity": "sha512-pad"
			},
			"packages/ui": {
				"name": "@acme/ui",
				"version": "0.1.0",
				"dependencies": {"left-pad": "^1.3.0"}
			}
		}
	}`)
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}
	leftPad := only(t, lf, "npm:left-pad@1.3.0")
	if !leftPad.Direct {
		t.Errorf("left-pad = %+v, want a direct dependency of the workspace", leftPad)
	}
}

func TestParseReportsAHostTheRestOfTheFileDoesNotInstallFrom(t *testing.T) {
	// One entry of an otherwise ordinary lockfile is repointed at a host of the
	// author's choosing, with a hash of their own tarball. Nothing about the URL
	// says it is not a registry, so only the rest of the file can say so.
	lf, err := parseString(t, `{
		"lockfileVersion": 3,
		"packages": {
			"": {"dependencies": {"left-pad": "^1.3.0"}},
			"node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-a"},
			"node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz", "integrity": "sha512-b"},
			"node_modules/c": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/c/-/c-1.0.0.tgz", "integrity": "sha512-c"},
			"node_modules/left-pad": {
				"version": "1.3.0",
				"resolved": "https://evil.example.com/left-pad/-/left-pad-1.3.0.tgz",
				"integrity": "sha512-theirs"
			}
		}
	}`)
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}
	substituted := only(t, lf, "npm:left-pad@1.3.0")
	if substituted.Source != lockfile.SourceURL {
		t.Errorf("left-pad = %+v, want the substituted host reported as a url", substituted)
	}
	for _, ref := range []string{"npm:a@1.0.0", "npm:b@1.0.0", "npm:c@1.0.0"} {
		if got := only(t, lf, ref); got.Source != lockfile.SourceRegistry {
			t.Errorf("%s = %+v, want a registry install", ref, got)
		}
	}
}

func TestTopLevel(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{key: "node_modules/left-pad", want: true},
		{key: "node_modules/@types/node", want: true},
		{key: "node_modules/a/node_modules/b", want: false},
		{key: "packages/ui/node_modules/left-pad", want: false},
		{key: "packages/ui", want: false},
		{key: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := topLevel(tt.key); got != tt.want {
				t.Errorf("topLevel(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestParseDropsAnEntryWithNoName(t *testing.T) {
	lf, err := parseString(t, `{"lockfileVersion":3,"packages":{"node_modules/":{"version":"1.0.0"}}}`)
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}
	if len(lf.Entries) != 0 {
		t.Fatalf("entries = %+v, want none", lf.Entries)
	}
	if len(lf.Dropped) != 1 || !strings.Contains(lf.Dropped[0], "no package name") {
		t.Fatalf("dropped = %q, want a reason naming the missing name", lf.Dropped)
	}
}

func BenchmarkParse(b *testing.B) {
	data, err := os.ReadFile(largeFixture)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := (parser{}).Parse(largeFixture, bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}
