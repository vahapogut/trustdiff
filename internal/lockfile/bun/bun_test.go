package bun

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// The integrity values of the hand-built fixture, named so that a table of
// expected entries stays readable. Each is the sha512 of "<name>@<version>" in
// base64, which testdata/README.md explains.
const (
	widgetsSum     = "sha512-m+qzHo/bBErLUZrD/WlDqK2XbPaVJvFHl7ywqAhx6JDv1SszPOsNU41oVEaQssZ5gCNpB+5r0WmqpeyMky9aUQ=="
	devOnlySum     = "sha512-Z0J6MkCprEa3FkQirRq2TLPhR0pYs6N73AReJI2cs0Z7inQNjY3Agtkd+h8cfmxganPBoKetnBB3m39U7dgBOg=="
	tarballSum     = "sha512-GUhtD8luPx3nMmLqW2fXYOeNFWjogGOeK3gqMxQz5nrCf9QzRlUnmfD8qloEtQkuXQLSRn51uEbuLj12lqwS8Q=="
	nativeOnlySum  = "sha512-6gCv9hjxLAhAPpg3ubQPWkn8sWsRyDFowQIHMc5jtGCDMWdojIKK01d0HG275Wm51Mu+Zw2LAxeiJmsG+JrITQ=="
	otherToolSum   = "sha512-v1O+3o0jBO4Ibhkhzz7mu7zwF3a0RsSM7ca5WEwo1Ta9T7aO1xu8yH4jxAszn82gcCbJoRlBVggBrEE+QOvIvg=="
	privateSum     = "sha512-kewA8YR8Wl502jx3tWQQbS1ZIyfQ6I37PK6rvU3cKyGXuaaY4jrbSYXMlTyiukWMC9BknX4WtTFyLt7UFbycoQ=="
	substitutedSum = "sha512-Ze9uGlqiIPdi6kdRZcntZlYYF6cy7DKleq+64+YMDHSF5777i8zP5njUxRRQYdFK2zn+ECsxE1DHLW1a6NtiIA=="
	thirdToolSum   = "sha512-eeOVZ2p75ui7sgbPDWZt7/MWZQ0UgDEvt/JZfJsQQHetuUvzACPTpzuz1RZA110Fv746aUm2Vz7WAV0cWrvb8g=="
	transitive5Sum = "sha512-y4r2v9hIpqGrZB+h0yWljm1bZRHkS/5rw+2lBEMedLOKlQrxHvHEAp1zVgmFeMQBKAmbps2yeO44uP6Cb6vR5Q=="
	transitive4Sum = "sha512-3cnl8R4/g5kop+P94F1j1N+myI9Cll35JY+txcToUSA8A/kzFW62hPtmuXeBNnbvYeEo+aqDAx4cB+frMqIARw=="
	isPositiveSum  = "sha512-xxzPGZ4P2uN6rROUa5N9Z7zTX6ERuE0hs6GUOc/cKBLF2NqKc16UwqHMt3tFg4CO6EBTE5UecUasg+3jZx3Ckg=="
	isNegativeSum  = "sha512-8ND1j3y9/HP94TOvGzr69/FgbkX2ruOldhLEsTWwcJVfo4oRjwemJmJxt7RJkKYH8tz7vYBP9JcKQY8CLuJ90Q=="

	gitLocator     = "git+ssh://git@example.test/example/ssh-dep.git#4f1d2c6f6b0e2f2f3c9f0f1a2b3c4d5e6f708192"
	githubLocator  = "github:example/gh-dep#9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c"
	tarballLocator = "https://files.example.test/from-tarball-2.0.0.tgz"
	privateURL     = "https://npm.example.test/artifactory/api/npm/npm-all/private-tool/-/private-tool-2.0.0.tgz"
	otherURL       = "https://npm.example.test/artifactory/api/npm/npm-all/other-tool/-/other-tool-3.0.0.tgz"
	thirdURL       = "https://npm.example.test/artifactory/api/npm/npm-all/third-tool/-/third-tool-4.0.0.tgz"
	elsewhereURL   = "https://elsewhere.example.test/substituted/-/substituted-1.2.3.tgz"
)

// ref is a short spelling of an npm package reference for the tables below.
func ref(name, version string) model.PackageRef {
	return model.PackageRef{Ecosystem: model.NPM, Name: name, Version: version}
}

// parseFile parses one committed fixture and checks what every parse must get
// right: the path it was given, the format, the ecosystem, and that it read the
// file whole rather than dropping part of it.
func parseFile(t *testing.T, name string) *lockfile.Lockfile {
	t.Helper()
	path := filepath.Join("testdata", name)
	f, err := os.Open(path) // #nosec G304 -- the path is a fixture name from the test itself
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close fixture: %v", err)
		}
	}()
	lf, err := parser{}.Parse(path, f)
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	if lf.Path != path || lf.Format != formatName || lf.Ecosystem != model.NPM {
		t.Errorf("Parse(%s) = %s/%s/%s, want the path, %s and npm", name, lf.Path, lf.Format, lf.Ecosystem, formatName)
	}
	if len(lf.Dropped) != 0 {
		t.Errorf("Parse(%s) dropped entries: %v", name, lf.Dropped)
	}
	return lf
}

// checkEntries compares a whole parse against the expected entries, in file order.
func checkEntries(t *testing.T, lf *lockfile.Lockfile, want []lockfile.Entry) {
	t.Helper()
	if len(lf.Entries) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(lf.Entries), len(want), lf.Entries)
	}
	for i, got := range lf.Entries {
		if got != want[i] {
			t.Errorf("entry %d:\n got %+v\nwant %+v", i, got, want[i])
		}
	}
}

// TestParseEveryShapeOfEntry reads the hand-built file that collects every shape a
// packages entry can take, with the comments and trailing commas that make the
// format JSONC rather than JSON.
func TestParseEveryShapeOfEntry(t *testing.T) {
	lf := parseFile(t, "edge-cases.bun.lock")
	if lf.Version != "1" {
		t.Errorf("Version = %q, want 1", lf.Version)
	}
	checkEntries(t, lf, []lockfile.Entry{
		{Ref: ref("@acme/widgets", "1.4.2"), Source: lockfile.SourceRegistry, Integrity: widgetsSum, Direct: true, Line: 45},
		{Ref: ref("dev-only-tool", "3.2.0"), Source: lockfile.SourceRegistry, Integrity: devOnlySum, Direct: true, Dev: true, Line: 47},
		// A git resolution records no version anywhere, so the locator stands where
		// a version would, and the element after its info object is bun's checkout
		// tag rather than a hash, which is why the integrity stays empty.
		{Ref: ref("from-git", gitLocator), Source: lockfile.SourceGit, Resolved: gitLocator, Direct: true, Line: 51},
		{Ref: ref("from-github", githubLocator), Source: lockfile.SourceGit, Resolved: githubLocator, Direct: true, Line: 53},
		// A tarball, whose array has no registry element, so its hash is the third
		// item and not the fourth.
		{Ref: ref("from-tarball", tarballLocator), Source: lockfile.SourceURL, Resolved: tarballLocator, Integrity: tarballSum, Direct: true, Line: 55},
		{Ref: ref("local-folder", "file:./vendor/local-folder"), Source: lockfile.SourcePath, Resolved: "file:./vendor/local-folder", Direct: true, Line: 57},
		{Ref: ref("local-link", "link:./vendor/local-link"), Source: lockfile.SourcePath, Resolved: "link:./vendor/local-link", Direct: true, Line: 59},
		// A workspace member's array holds its resolution and nothing else, so its
		// version comes from the "workspaces" entry of the same name.
		{Ref: ref("member", "0.4.0"), Source: lockfile.SourcePath, Resolved: "workspace:packages/member", Direct: true, Line: 61},
		{Ref: ref("native-only", "2.1.0"), Source: lockfile.SourceRegistry, Integrity: nativeOnlySum, Direct: true, Optional: true, Line: 63},
		// A registry entry whose hash the file leaves empty.
		{Ref: ref("no-hash", "1.0.0"), Source: lockfile.SourceRegistry, Direct: true, Line: 66},
		// Three entries agree on one private registry, so it is the registry this
		// project installs through and each of them is a registry install.
		{Ref: ref("other-tool", "3.0.0"), Source: lockfile.SourceRegistry, Resolved: otherURL, Integrity: otherToolSum, Direct: true, Line: 68},
		{Ref: ref("private-tool", "2.0.0"), Source: lockfile.SourceRegistry, Resolved: privateURL, Integrity: privateSum, Direct: true, Line: 70},
		// The same layout on a host nothing else in the file installs from, which
		// is what TD013 exists to show.
		{Ref: ref("substituted", "1.2.3"), Source: lockfile.SourceURL, Resolved: elsewhereURL, Integrity: substitutedSum, Direct: true, Line: 74},
		{Ref: ref("third-tool", "4.0.0"), Source: lockfile.SourceRegistry, Resolved: thirdURL, Integrity: thirdToolSum, Direct: true, Line: 76},
		// Asked for by the workspace member, which is a project of the repository
		// like the root, so it is direct too.
		{Ref: ref("transitive", "5.4.0"), Source: lockfile.SourceRegistry, Integrity: transitive5Sum, Direct: true, Line: 78},
		// An alias: the key is "widgets-v1" and the resolution names the package
		// that is really installed, which is what the ref has to carry.
		{Ref: ref("@acme/widgets", "1.4.2"), Source: lockfile.SourceRegistry, Integrity: widgetsSum, Direct: true, Line: 82},
		// A package that ships inside its parent's tarball, so it has no hash.
		{Ref: ref("bundled-child", "1.0.0"), Source: lockfile.SourceRegistry, Bundled: true, Line: 85},
		// A copy nested under another package is there because that package asked
		// for it, however the root spells the same name.
		{Ref: ref("transitive", "4.9.0"), Source: lockfile.SourceRegistry, Integrity: transitive4Sum, Line: 88},
	})
}

// TestParseReadsCarriageReturns reads a file written with Windows line endings,
// which is what a repository that commits them holds. The fixture is only a test
// of anything while it really carries them, and the repository normalizes every
// other file to LF, so that is checked first.
func TestParseReadsCarriageReturns(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "crlf.bun.lock"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Contains(data, []byte("\r\n")) {
		t.Fatal("the fixture has lost its carriage returns, so it tests nothing: see testdata/.gitattributes")
	}
	lf := parseFile(t, "crlf.bun.lock")
	checkEntries(t, lf, []lockfile.Entry{
		{Ref: ref("is-negative", "2.1.0"), Source: lockfile.SourceRegistry, Integrity: isNegativeSum, Line: 13},
		{Ref: ref("is-positive", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: isPositiveSum, Direct: true, Line: 15},
	})
}

// TestRealLockfiles reads the two recorded lockfiles and asserts the whole-file
// counts, so that a change in the format is caught here.
func TestRealLockfiles(t *testing.T) {
	tests := []struct {
		file     string
		version  string
		entries  int
		direct   int
		dev      int
		optional int
		noHash   int
		sources  map[lockfile.Source]int
		first    int
		last     int
	}{
		{
			file:    "bun-v1.bun.lock",
			version: "1",
			entries: 60,
			direct:  11, // the root's ten devDependencies and the one its member asks for
			dev:     10,
			noHash:  1, // the workspace member, which is a directory and not a download
			sources: map[lockfile.Source]int{
				lockfile.SourceRegistry: 59,
				lockfile.SourcePath:     1,
			},
			first: 32,  // @esbuild/aix-ppc64, the first key of the packages object
			last:  151, // undici-types, the last
		},
		{
			file:    "elysia-v1.bun.lock",
			version: "1",
			entries: 291,
			direct:  23,
			dev:     19,
			sources: map[lockfile.Source]int{lockfile.SourceRegistry: 291},
			first:   52,
			last:    632,
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			lf := parseFile(t, tt.file)
			if lf.Version != tt.version {
				t.Errorf("Version = %q, want %q", lf.Version, tt.version)
			}
			if len(lf.Entries) != tt.entries {
				t.Fatalf("got %d entries, want %d", len(lf.Entries), tt.entries)
			}
			var direct, dev, optional, noHash int
			sources := make(map[lockfile.Source]int)
			for _, e := range lf.Entries {
				sources[e.Source]++
				if e.Direct {
					direct++
				}
				if e.Dev {
					dev++
				}
				if e.Optional {
					optional++
				}
				if e.Integrity == "" {
					noHash++
				}
				// Every entry of a real file sits on a line a finding can point at,
				// and every download of a healthy project states a location or the
				// default registry it came from.
				if e.Line == 0 {
					t.Errorf("%s has no line", e.Ref)
				}
			}
			if direct != tt.direct || dev != tt.dev || optional != tt.optional || noHash != tt.noHash {
				t.Errorf("direct/dev/optional/hashless = %d/%d/%d/%d, want %d/%d/%d/%d",
					direct, dev, optional, noHash, tt.direct, tt.dev, tt.optional, tt.noHash)
			}
			if len(sources) != len(tt.sources) {
				t.Errorf("sources = %v, want %v", sources, tt.sources)
			}
			for source, want := range tt.sources {
				if sources[source] != want {
					t.Errorf("%d entries from %s, want %d", sources[source], source, want)
				}
			}
			if got := lf.Entries[0].Line; got != tt.first {
				t.Errorf("first entry on line %d, want %d", got, tt.first)
			}
			if got := lf.Entries[len(lf.Entries)-1].Line; got != tt.last {
				t.Errorf("last entry on line %d, want %d", got, tt.last)
			}
		})
	}
}

// TestEntriesOfTheRealLockfiles names the entries whose shape the parser has to
// get right, and checks each against the line it really sits on in the file.
func TestEntriesOfTheRealLockfiles(t *testing.T) {
	tests := []struct {
		file string
		want []lockfile.Entry
	}{
		{
			file: "bun-v1.bun.lock",
			want: []lockfile.Entry{
				// A workspace member, whose array holds its resolution alone. Its
				// "workspaces" entry states no version, so the locator stands where
				// a version would, and the root does not depend on it.
				{Ref: ref("bun-types", "workspace:packages/bun-types"), Source: lockfile.SourcePath, Resolved: "workspace:packages/bun-types", Line: 127},
				// Asked for by the member rather than by the root, which makes it
				// direct but not a development dependency of the repository.
				{
					Ref:       ref("@types/node", "26.2.0"),
					Source:    lockfile.SourceRegistry,
					Integrity: "sha512-5IviulTZeRNp2vAJ514cc/HUlY5nZ9fCbq9DMyC52BrhFZACo3nI0R7qBxhQmo/d27NFe96ur/b7Wwxklda+kg==",
					Direct:    true,
					Line:      125,
				},
				{
					Ref:       ref("typescript", "6.0.2"),
					Source:    lockfile.SourceRegistry,
					Integrity: "sha512-bGdAIrZ0wiGDo5l8c++HWtbaNCWTS4UTv7RaTH/ThVIgjkveJt83m74bBHMJkuCbslY8ixgLBVZJIOiQlQTjfQ==",
					Direct:    true,
					Dev:       true,
					Line:      149,
				},
			},
		},
		{
			file: "elysia-v1.bun.lock",
			want: []lockfile.Entry{
				// A copy nested two levels down, whose key is a path and not a name.
				{
					Ref:       ref("brace-expansion", "2.0.2"),
					Source:    lockfile.SourceRegistry,
					Integrity: "sha512-Jt0vHyM+jmUBqojB7E1NIYadt0vI0Qxjxd2TErW94wDz+E2LAm5vKMXXwg6ZZBTHPuUlDgQHKXvjGBdfcF1ZDQ==",
					Line:      632,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			lf := parseFile(t, tt.file)
			for _, want := range tt.want {
				// Matched by line rather than by name: a lockfile holds the same
				// package version under more than one install path, and each copy
				// is an entry of its own.
				found := false
				for _, got := range lf.Entries {
					if got.Line != want.Line {
						continue
					}
					found = true
					if got != want {
						t.Errorf("line %d:\n got %+v\nwant %+v", want.Line, got, want)
					}
				}
				if !found {
					t.Errorf("no entry on line %d, where %s should be", want.Line, want.Ref)
				}
				if line := fileLine(t, tt.file, want.Line); !strings.Contains(line, want.Ref.Name) {
					t.Errorf("line %d of %s is %q, which does not name %s", want.Line, tt.file, line, want.Ref.Name)
				}
			}
		})
	}
}

// fileLine returns one line of a fixture, 1-based.
func fileLine(t *testing.T, name string, line int) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- the path is a fixture name from the test itself
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if line < 1 || line > len(lines) {
		t.Fatalf("line %d is outside %s", line, name)
	}
	return lines[line-1]
}

// TestDirectDependenciesOfTheRealLockfile names the entries the workspaces reach,
// because the direct flag decides which findings a pull request has to answer for.
func TestDirectDependenciesOfTheRealLockfile(t *testing.T) {
	want := []string{
		"@lezer/common@1.5.2",
		"@lezer/cpp@1.1.6",
		"@types/node@26.2.0", // the one dependency the workspace member declares
		"esbuild@0.21.5",
		"oxlint@1.70.0",
		"prettier@3.6.2",
		"prettier-plugin-organize-imports@4.3.0",
		"react@18.3.1",
		"react-dom@18.3.1",
		"source-map-js@1.2.1",
		"typescript@6.0.2",
	}
	var got []string
	for _, e := range parseFile(t, "bun-v1.bun.lock").Entries {
		if e.Direct {
			got = append(got, e.Ref.Name+"@"+e.Ref.Version)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("direct dependencies:\n got %v\nwant %v", got, want)
	}
}

func TestRegisteredForItsFileName(t *testing.T) {
	p, ok := lockfile.For("some/project/bun.lock")
	if !ok || p.Name() != formatName {
		t.Fatalf("For(bun.lock) = %v, %v, want the %s parser", p, ok, formatName)
	}
	// bun.lockb is the binary lockfile bun wrote before this one, which is not
	// this format and must not be claimed.
	if _, ok := lockfile.For("some/project/bun.lockb"); ok {
		t.Error("the bun parser claimed bun.lockb")
	}
	lf, err := lockfile.Parse("some/project/bun.lock", strings.NewReader(`{"lockfileVersion": 1}`))
	if err != nil {
		t.Fatalf("Parse through the registry: %v", err)
	}
	if lf.Format != formatName || len(lf.Entries) != 0 {
		t.Errorf("Parse = %+v, want the %s format and no entry", lf, formatName)
	}
}

func TestParseRejectsFilesItCannotRead(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "no lockfileVersion", body: `{"packages": {}}`, want: "states no lockfileVersion"},
		{name: "empty file", body: "", want: "EOF"},
		{name: "a list where the object should be", body: `[{"lockfileVersion": 1}]`, want: "want an object"},
		{name: "not json at all", body: `{"lockfileVersion": 1, "packages": <>}`, want: "invalid character"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser{}.Parse("bun.lock", strings.NewReader(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error = %v, want one containing %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), formatName) {
				t.Errorf("Parse error = %v, want it to name the file", err)
			}
		})
	}
}

// TestParseReportsATruncatedFile reads a file that stops in the middle of an
// entry, which is what a half written or half transferred lockfile looks like. It
// has to be reported rather than panic or read as an empty file.
func TestParseReportsATruncatedFile(t *testing.T) {
	path := filepath.Join("testdata", "truncated.bun.lock")
	f, err := os.Open(path) // #nosec G304 -- the path is a fixture name from the test itself
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()
	_, err = parser{}.Parse(path, f)
	if err == nil || !strings.Contains(err.Error(), "unexpected EOF") || !strings.Contains(err.Error(), formatName) {
		t.Fatalf("Parse error = %v, want an end of file error naming %s", err, formatName)
	}
}

func TestParseDropsUnreadableEntriesAndKeepsTheRest(t *testing.T) {
	const head = `{"lockfileVersion": 1, `
	tests := []struct {
		name    string
		body    string
		want    []lockfile.Entry
		dropped []string
	}{
		{
			name: "entries that are not the array this format writes",
			body: head + `"packages": {
				"a-string": "1.0.0",
				"an-object": {"version": "1.0.0"},
				"empty": [],
				"is-positive": ["is-positive@1.0.0", "", {}, "sha512-x"]
			}}`,
			want: []lockfile.Entry{
				{Ref: ref("is-positive", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: "sha512-x", Line: 5},
			},
			dropped: []string{
				`"a-string" on line 2 is string, not the array this format writes`,
				`"an-object" on line 3 is object, not the array this format writes`,
				`"empty" on line 4 is an empty array`,
			},
		},
		{
			name: "an array that does not start with a resolution string",
			body: head + `"packages": {
				"odd": [{"name": "odd"}, {}],
				"nameless": ["@scope", {}]
			}}`,
			dropped: []string{
				`"odd" on line 2 does not start with a resolution string`,
				`"nameless" on line 3 resolves to "@scope", which names no package version`,
			},
		},
		{
			name: "a workspace that is not an object",
			body: head + `"workspaces": {"": "root"}, "packages": {
				"is-positive": ["is-positive@1.0.0", "", {}, "sha512-x"]
			}}`,
			want: []lockfile.Entry{
				{Ref: ref("is-positive", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: "sha512-x", Line: 2},
			},
			dropped: []string{"the workspace at the root of the repository on line 1 is string, not an object"},
		},
		{
			name: "the root package of an isolated install is the project, not a package",
			body: head + `"packages": {
				"my-app": ["my-app@root:", {"bin": {"my-app": "cli.js"}}],
				"is-positive": ["is-positive@1.0.0", "", {}, "sha512-x"]
			}}`,
			want: []lockfile.Entry{
				{Ref: ref("is-positive", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: "sha512-x", Line: 3},
			},
		},
		{
			name: "an info object this parser cannot read costs the bundled flag and nothing else",
			body: head + `"packages": {
				"is-positive": ["is-positive@1.0.0", "", "not an object", "sha512-x"]
			}}`,
			want: []lockfile.Entry{
				{Ref: ref("is-positive", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: "sha512-x", Line: 2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lf, err := parser{}.Parse("bun.lock", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(lf.Entries) != len(tt.want) {
				t.Fatalf("got %d entries, want %d: %+v", len(lf.Entries), len(tt.want), lf.Entries)
			}
			for i, got := range lf.Entries {
				if got != tt.want[i] {
					t.Errorf("entry %d:\n got %+v\nwant %+v", i, got, tt.want[i])
				}
			}
			if len(lf.Dropped) != len(tt.dropped) {
				t.Fatalf("dropped %v, want %d reasons", lf.Dropped, len(tt.dropped))
			}
			for i, want := range tt.dropped {
				if !strings.Contains(lf.Dropped[i], want) {
					t.Errorf("dropped[%d] = %q, want one containing %q", i, lf.Dropped[i], want)
				}
			}
		})
	}
}

// TestParseMergesARepeatedTopLevelObject reads a file that states "packages" or
// "workspaces" twice. Bun writes each key once, so such a file was not written by
// bun, but JSON allows it and readers disagree about which of the two wins, so
// every entry either object names has to survive the parse: a whole object's worth
// of packages that vanished without an entry and without a reason would be a
// lockfile this tool reported nothing about.
func TestParseMergesARepeatedTopLevelObject(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []lockfile.Entry
	}{
		{
			name: "the packages object twice",
			body: `{"lockfileVersion": 1,
"packages": {"a": ["a@1.0.0", "", {}, "sha512-AAAA"]},
"packages": {"b": ["b@2.0.0", "", {}, "sha512-BBBB"]}}`,
			want: []lockfile.Entry{
				{Ref: ref("a", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: "sha512-AAAA", Line: 2},
				{Ref: ref("b", "2.0.0"), Source: lockfile.SourceRegistry, Integrity: "sha512-BBBB", Line: 3},
			},
		},
		{
			// The second object decides Direct for what it asks for, which is what
			// says the workspaces were merged rather than one of them read.
			name: "the workspaces object twice",
			body: `{"lockfileVersion": 1,
"workspaces": {"": {"dependencies": {"a": "^1.0.0"}}},
"workspaces": {"packages/member": {"name": "member", "dependencies": {"b": "^2.0.0"}}},
"packages": {"a": ["a@1.0.0", "", {}, "sha512-AAAA"], "b": ["b@2.0.0", "", {}, "sha512-BBBB"]}}`,
			want: []lockfile.Entry{
				{Ref: ref("a", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: "sha512-AAAA", Direct: true, Line: 4},
				{Ref: ref("b", "2.0.0"), Source: lockfile.SourceRegistry, Integrity: "sha512-BBBB", Direct: true, Line: 4},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lf, err := parser{}.Parse("bun.lock", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			checkEntries(t, lf, tt.want)
			if len(lf.Dropped) != 0 {
				t.Errorf("dropped %v, want nothing dropped: every entry of both objects is read", lf.Dropped)
			}
		})
	}
}

// TestParseDropsAResolutionBunDoesNotWrite pins what happens to a resolution whose
// protocol is none of the ones the shape table lists. Bun's own reader refuses such
// a file ("Unexpected resolution"), so nothing here says which package version is
// installed, and an entry that named the alias as the package and the whole
// resolution as its version would report on a package that does not exist.
func TestParseDropsAResolutionBunDoesNotWrite(t *testing.T) {
	lf, err := parser{}.Parse("bun.lock", strings.NewReader(`{"lockfileVersion": 1, "packages": {
		"widgets-v1": ["widgets-v1@npm:@acme/widgets@1.4.2", "", {}, "sha512-AAAA"],
		"from-jsr": ["from-jsr@jsr:@std/path@1.0.0", {}],
		"widgets": ["@acme/widgets@1.4.2", "", {}, "sha512-AAAA"]
	}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// The alias bun really writes, whose key is the alias and whose resolution names
	// the package that is installed, is read as it always was.
	checkEntries(t, lf, []lockfile.Entry{
		{Ref: ref("@acme/widgets", "1.4.2"), Source: lockfile.SourceRegistry, Integrity: "sha512-AAAA", Line: 4},
	})
	want := []string{
		`"widgets-v1" on line 2`,
		`"from-jsr" on line 3`,
	}
	if len(lf.Dropped) != len(want) {
		t.Fatalf("dropped %v, want %d reasons", lf.Dropped, len(want))
	}
	for i, w := range want {
		if !strings.Contains(lf.Dropped[i], w) {
			t.Errorf("dropped[%d] = %q, want one containing %q", i, lf.Dropped[i], w)
		}
	}
	// The reason names the protocol, which is the whole of what a reader has to
	// look at to see why the entry could not be read.
	if !strings.Contains(lf.Dropped[0], `"npm:"`) || !strings.Contains(lf.Dropped[1], `"jsr:"`) {
		t.Errorf("dropped = %q, want each reason to name the protocol it could not read", lf.Dropped)
	}
}

// failingReader stands in for a file that cannot be read to the end.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errUnreadable }

var errUnreadable = errors.New("disk went away")

func TestParseWrapsAReadError(t *testing.T) {
	_, err := parser{}.Parse("bun.lock", failingReader{})
	if !errors.Is(err, errUnreadable) || !strings.Contains(err.Error(), formatName) {
		t.Fatalf("Parse error = %v, want the read error wrapped with the format name", err)
	}
}

// TestBlankJSONC checks that the comments and the trailing commas are replaced by
// spaces rather than removed, because an offset in the copy has to be the same
// offset in the file for the line numbers to be the file's own.
func TestBlankJSONC(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		// The newline ends a line comment rather than belonging to it, so it stays.
		{name: "a line comment", text: "{ // hi\n\"a\": 1 }", want: "{      \n\"a\": 1 }"},
		// A block comment goes whole, the newlines inside it included: the line
		// numbers are read off the real file, not off this copy.
		{name: "a block comment", text: "{ /* hi\nthere */ \"a\": 1 }", want: "{                \"a\": 1 }"},
		{name: "a trailing comma in an object", text: "{\"a\": 1,\n}", want: "{\"a\": 1 \n}"},
		{name: "a trailing comma in an array", text: "[1, 2,]", want: "[1, 2 ]"},
		{name: "a comma that is not trailing stays", text: "[1, 2]", want: "[1, 2]"},
		// A "//" inside a string is part of a URL, not the start of a comment.
		{name: "a url in a string", text: `{"a": "https://x/y"}`, want: `{"a": "https://x/y"}`},
		// A quote inside a comment cannot open a string.
		{name: "a quote in a comment", text: "{ // \"a\n\"b\": 1 }", want: "{      \n\"b\": 1 }"},
		// An unterminated comment or string runs to the end and takes nothing else with it.
		{name: "an unterminated block comment", text: "{ /* hi", want: "{      "},
		{name: "an unterminated string", text: `{"a`, want: `{"a`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(blankJSONC([]byte(tt.text)))
			if got != tt.want {
				t.Errorf("blankJSONC(%q) =\n %q\nwant %q", tt.text, got, tt.want)
			}
			if len(got) != len(tt.text) {
				t.Errorf("blankJSONC changed the length from %d to %d", len(tt.text), len(got))
			}
		})
	}
}

func TestSplitLocator(t *testing.T) {
	tests := []struct {
		resolution string
		name       string
		locator    string
	}{
		{resolution: "typescript@6.0.2", name: "typescript", locator: "6.0.2"},
		{resolution: "@types/node@26.2.0", name: "@types/node", locator: "26.2.0"},
		{resolution: "dep@git+ssh://git@example.test/o/r.git#abc", name: "dep", locator: "git+ssh://git@example.test/o/r.git#abc"},
		{resolution: "dep@workspace:packages/ui", name: "dep", locator: "workspace:packages/ui"},
		{resolution: "dep@root:", name: "dep", locator: "root:"},
		// Text that names no package version at all.
		{resolution: "@scope"},
		{resolution: "bare-name", name: "bare-name"},
		{resolution: ""},
	}
	for _, tt := range tests {
		t.Run(tt.resolution, func(t *testing.T) {
			name, locator := splitLocator(tt.resolution)
			if name != tt.name || locator != tt.locator {
				t.Errorf("splitLocator(%q) = %q, %q, want %q, %q", tt.resolution, name, locator, tt.name, tt.locator)
			}
		})
	}
}

func TestSourceOf(t *testing.T) {
	tests := []struct {
		name     string
		locator  string
		registry string
		want     lockfile.Source
	}{
		{name: "the registry the project configures", locator: "1.2.3", want: lockfile.SourceRegistry},
		{name: "a known registry", locator: "1.2.3", registry: "https://registry.npmjs.org/a/-/a-1.2.3.tgz", want: lockfile.SourceRegistry},
		{name: "github packages", locator: "1.2.3", registry: "https://npm.pkg.github.com/download/a/1.2.3/abc", want: lockfile.SourceRegistry},
		{name: "a host nothing else installs from", locator: "1.2.3", registry: "https://elsewhere.example.test/a/-/a-1.2.3.tgz", want: lockfile.SourceURL},
		{name: "a registry element that is not a url", locator: "1.2.3", registry: "not a url at all", want: lockfile.SourceUnknown},
		{name: "a workspace", locator: "workspace:packages/ui", want: lockfile.SourcePath},
		{name: "a link", locator: "link:../thing", want: lockfile.SourcePath},
		{name: "a folder", locator: "file:./vendor/thing", want: lockfile.SourcePath},
		{name: "the root package", locator: "root:", want: lockfile.SourcePath},
		{name: "git over ssh", locator: "git+ssh://git@example.test/o/r.git#abc", want: lockfile.SourceGit},
		{name: "git over https", locator: "git+https://example.test/o/r.git#abc", want: lockfile.SourceGit},
		{name: "the git protocol", locator: "git://example.test/o/r#abc", want: lockfile.SourceGit},
		{name: "a github shorthand", locator: "github:owner/repo#abc", want: lockfile.SourceGit},
		{name: "a plain https repository", locator: "https://example.test/o/r.git#abc", want: lockfile.SourceGit},
		{name: "a tarball", locator: "https://files.example.test/t.tgz", want: lockfile.SourceURL},
		{name: "a protocol nothing here knows", locator: "jsr:@std/path@1.0.0", want: lockfile.SourceUnknown},
	}
	// A count that knows the public registry and nothing else, which is what a
	// file whose entries all state the default registry produces.
	hosts := lockfile.NPMRegistryHosts()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sourceOf(tt.locator, tt.registry, hosts); got != tt.want {
				t.Errorf("sourceOf(%q, %q) = %q, want %q", tt.locator, tt.registry, got, tt.want)
			}
		})
	}
}

func TestLastNameAndTopLevel(t *testing.T) {
	tests := []struct {
		key      string
		last     string
		topLevel bool
	}{
		{key: "chalk", last: "chalk", topLevel: true},
		{key: "@lezer/cpp", last: "@lezer/cpp", topLevel: true},
		{key: "boxen/chalk", last: "chalk"},
		{key: "boxen/@types/node", last: "@types/node"},
		{key: "eslint-plugin-sonarjs/minimatch/brace-expansion", last: "brace-expansion"},
		{key: "@scope/parent/@scope/child", last: "@scope/child"},
		{key: ""},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := lastName(tt.key); got != tt.last {
				t.Errorf("lastName(%q) = %q, want %q", tt.key, got, tt.last)
			}
			if got := topLevel(tt.key); got != tt.topLevel {
				t.Errorf("topLevel(%q) = %v, want %v", tt.key, got, tt.topLevel)
			}
		})
	}
}
