package pnpm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

// The integrity hashes of the hand-built fixtures, named so that a table of
// expected entries stays readable.
const (
	widgetHash     = "sha512-HnlASVRufHWu42SsFb/wmVczoHWjpeaEaEHuz9xTN/cwoZEOtBYpx29Hu22TvFLxhXazSm0AJ6pgHHUHrKFrQg=="
	reactHash      = "sha512-2+1d312Gv/F0ka3L+WanxnvPQ93+m+j2HLOWk54rzWk/lAPxKcimaVSC+kRml1k+lqAEalcc0tQie4/Wubz/Zg=="
	transitiveHash = "sha512-DuQ34ChJIQneevsn5BAsdpA8u8ZVi6cvSWzVSLxgPWGKjtPyPKWGcvG1smB0vhkagrJ9wRyPje6iuHmScFc+uA=="
	optionalHash   = "sha512-5liwl07oS8ExViVjO+6p6zsoEvFtP17kRj85mVzG49kNlRvWDRlZ3LYYgi+ulIJK/3Q9+pnFfzZ8BrWbAObY4Q=="
	sharedHash     = "sha512-driVjsG9unzaLc5wqO/yr3C1ysFKkxFIBcPmZKYcntmzF+JocqeIe+FwxQTFDNz7oDhSxhcrReY4qkqLJ+NhLQ=="
	styledHash     = "sha512-iSg/gkwbnNIW3MZ9+8AcQFI9CeACI/jwi4fBsWyWW0luNKKYesgjtnzBBN/k+89Xy4gEv7Bcspx7ChsK5vLEjA=="
	devOnlyHash    = "sha512-A1mWZSuCbYyjm0rmQYzUF/calG4IHQtZVvTW6saMNI6p3bfv1fsku3qHHOZxZaNfmeWGHJBrt4zUNiXZb3q53A=="

	isPositive1Hash = "sha512-xxzPGZ4P2uN6rROUa5N9Z7zTX6ERuE0hs6GUOc/cKBLF2NqKc16UwqHMt3tFg4CO6EBTE5UecUasg+3jZx3Ckg=="
	isPositive3Hash = "sha512-8ND1j3y9/HP94TOvGzr69/FgbkX2ruOldhLEsTWwcJVfo4oRjwemJmJxt7RJkKYH8tz7vYBP9JcKQY8CLuJ90Q=="

	gitDepRemote = "git+ssh://git@git.example.test/example/git-dep.git#4f1d2c6f6b0e2f2f3c9f0f1a2b3c4d5e6f708192"
	tarballURL   = "https://example.test/tarball-dep-1.4.0.tgz"
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

func TestParseVersion9(t *testing.T) {
	lf := parseFile(t, "exotic-v9.yaml")
	if lf.Version != "9.0" {
		t.Errorf("Version = %q, want 9.0", lf.Version)
	}
	checkEntries(t, lf, []lockfile.Entry{
		// A linked directory keeps the key's "file:" version, because a version 9
		// entry for a directory states no version of its own.
		{Ref: ref("@scope/local-tool", "file:packages/local-tool"), Source: lockfile.SourcePath, Resolved: "packages/local-tool", Direct: true, Dev: true, Line: 52},
		// The importer resolved this to "2.1.0(react@18.3.1)" while the key carries
		// no peer suffix, which is the version 9 spelling of the same package.
		{Ref: ref("@scope/widget", "2.1.0"), Source: lockfile.SourceRegistry, Integrity: widgetHash, Direct: true, Line: 55},
		{Ref: ref("dev-only", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: devOnlyHash, Direct: true, Dev: true, Line: 61},
		// The key states the git URL, so the entry states its name and version.
		{Ref: ref("git-dep", "3.0.0"), Source: lockfile.SourceGit, Resolved: gitDepRemote, Direct: true, Dev: true, Line: 64},
		// No importer names it, and version 9 keeps the dev and optional flags in
		// the snapshots map, which is not read.
		{Ref: ref("only-transitive", "1.2.3"), Source: lockfile.SourceRegistry, Integrity: transitiveHash, Line: 69},
		{Ref: ref("optional-dep", "0.5.0"), Source: lockfile.SourceRegistry, Integrity: optionalHash, Direct: true, Optional: true, Line: 72},
		{Ref: ref("react", "18.3.1"), Source: lockfile.SourceRegistry, Integrity: reactHash, Direct: true, Line: 75},
		// A development dependency of the root project and a runtime dependency of
		// the other importer, so not a development dependency of the workspace.
		{Ref: ref("shared-tool", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: sharedHash, Direct: true, Line: 79},
		{Ref: ref("styled-thing", "5.3.11"), Source: lockfile.SourceRegistry, Integrity: styledHash, Line: 82},
		{Ref: ref("tarball-dep", "1.4.0"), Source: lockfile.SourceURL, Resolved: tarballURL, Direct: true, Line: 87},
	})
}

func TestParseVersion6(t *testing.T) {
	lf := parseFile(t, "exotic-v6.yaml")
	if lf.Version != "6.0" {
		t.Errorf("Version = %q, want 6.0", lf.Version)
	}
	checkEntries(t, lf, []lockfile.Entry{
		// The version 6 key carries the peer suffix and the leading slash; both are
		// cut, so the entry names the same package as its version 9 twin.
		{Ref: ref("@scope/widget", "2.1.0"), Source: lockfile.SourceRegistry, Integrity: widgetHash, Direct: true, Line: 36},
		// Version 6 states the development flag on the package itself, so a
		// transitive entry has it where the version 9 file does not.
		{Ref: ref("only-transitive", "1.2.3"), Source: lockfile.SourceRegistry, Integrity: transitiveHash, Dev: true, Line: 46},
		{Ref: ref("optional-dep", "0.5.0"), Source: lockfile.SourceRegistry, Integrity: optionalHash, Direct: true, Optional: true, Line: 50},
		{Ref: ref("react", "18.3.1"), Source: lockfile.SourceRegistry, Integrity: reactHash, Direct: true, Line: 56},
		{Ref: ref("styled-thing", "5.3.11"), Source: lockfile.SourceRegistry, Integrity: styledHash, Line: 61},
		// The key of a directory names no package, so the entry states the scoped
		// name and the version.
		{Ref: ref("@scope/local-tool", "0.1.0"), Source: lockfile.SourcePath, Resolved: "packages/local-tool", Direct: true, Dev: true, Line: 69},
		{Ref: ref("git-dep", "3.0.0"), Source: lockfile.SourceGit, Resolved: gitDepRemote, Direct: true, Dev: true, Line: 75},
		{Ref: ref("tarball-dep", "1.4.0"), Source: lockfile.SourceURL, Resolved: tarballURL, Direct: true, Line: 81},
	})
}

// TestWorkspaceImportersMarkDirect reads the lockfile of a workspace whose two
// packages depend on the same version, in both formats.
func TestWorkspaceImportersMarkDirect(t *testing.T) {
	for _, name := range []string{"workspace-v9.yaml", "workspace-v6.yaml"} {
		t.Run(name, func(t *testing.T) {
			lf := parseFile(t, name)
			checkEntries(t, lf, []lockfile.Entry{
				{Ref: ref("is-positive", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: isPositive1Hash, Direct: true, Line: 21},
			})
		})
	}
}

// TestGitProtocolDependency reads a dependency written as "github:kevva/is-negative#master",
// which pnpm resolves to a tarball on the git host and not to a git checkout. Its
// key states the URL, so the entry states the name and the version.
func TestGitProtocolDependency(t *testing.T) {
	tests := []struct {
		file string
		want []lockfile.Entry
	}{
		{
			file: "git-protocol-v9.yaml",
			want: []lockfile.Entry{
				{
					Ref:      ref("is-negative", "2.1.0"),
					Source:   lockfile.SourceURL,
					Resolved: "https://codeload.github.com/kevva/is-negative/tar.gz/1d7e288222b53a0cab90a331f1865220ec29560c",
					Direct:   true,
					Line:     17,
				},
			},
		},
		{
			file: "git-protocol-v6.yaml",
			want: []lockfile.Entry{
				{Ref: ref("is-positive", "3.1.0"), Source: lockfile.SourceRegistry, Integrity: isPositive3Hash, Line: 14},
				{
					Ref:      ref("is-negative", "2.0.0"),
					Source:   lockfile.SourceURL,
					Resolved: "https://codeload.github.com/kevva/is-negative/tar.gz/219c424611ff4a2af15f7deeff4f93c62558c43d",
					Direct:   true,
					Line:     19,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			checkEntries(t, parseFile(t, tt.file), tt.want)
		})
	}
}

// TestRealLockfiles reads the same project's lockfile in both formats and asserts
// the whole-file counts and the line of individual entries against the committed
// files, so that a change in either format is caught here.
func TestRealLockfiles(t *testing.T) {
	tests := []struct {
		file      string
		version   string
		entries   int
		direct    int
		dev       int
		optional  int
		firstLine int
		lastLine  int
		lines     map[string]int
	}{
		{
			file:      "pathe-v9.yaml",
			version:   "9.0",
			entries:   222,
			direct:    9, // the nine devDependencies of the single importer
			dev:       9, // version 9 states nothing about transitive entries
			optional:  0,
			firstLine: 41,   // @babel/generator@8.0.0, the first key of the packages map
			lastLine:  1257, // wsl-utils@0.1.0, the last one before the snapshots map
			lines: map[string]int{
				"@vitest/coverage-v8@4.1.9": 680, // the importer resolved it to 4.1.9(vitest@4.1.9)
				"typescript@6.0.3":          1157,
				"vitest@4.1.9":              1211,
			},
		},
		{
			file:      "pathe-v6.yaml",
			version:   "6.0",
			entries:   564,
			direct:    10,  // the ten devDependencies at the top level, no importers map
			dev:       564, // version 6 marks every package it installed for development
			optional:  46,
			firstLine: 37,   // /@ampproject/remapping@2.2.0
			lastLine:  4367, // /yocto-queue@1.0.0
			lines: map[string]int{
				"@esbuild/android-arm@0.15.18": 258,
				"typescript@5.0.4":             4044,
				"vitest@0.31.0":                4208,
			},
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
			var direct, dev, optional int
			lines := make(map[string]int, len(lf.Entries))
			for _, e := range lf.Entries {
				if e.Direct {
					direct++
				}
				if e.Dev {
					dev++
				}
				if e.Optional {
					optional++
				}
				// Every package of a healthy public project comes from the registry
				// with a hash, and a finding must be able to point at its line.
				if e.Source != lockfile.SourceRegistry || e.Integrity == "" || e.Line == 0 {
					t.Errorf("%s: source %q, integrity %q, line %d", e.Ref, e.Source, e.Integrity, e.Line)
				}
				lines[e.Ref.Name+"@"+e.Ref.Version] = e.Line
			}
			if direct != tt.direct || dev != tt.dev || optional != tt.optional {
				t.Errorf("direct/dev/optional = %d/%d/%d, want %d/%d/%d", direct, dev, optional, tt.direct, tt.dev, tt.optional)
			}
			if got := lf.Entries[0].Line; got != tt.firstLine {
				t.Errorf("first entry on line %d, want %d", got, tt.firstLine)
			}
			if got := lf.Entries[len(lf.Entries)-1].Line; got != tt.lastLine {
				t.Errorf("last entry on line %d, want %d", got, tt.lastLine)
			}
			for pkg, want := range tt.lines {
				if lines[pkg] != want {
					t.Errorf("%s on line %d, want %d", pkg, lines[pkg], want)
				}
			}
		})
	}
}

// TestDirectDependenciesOfTheRealLockfiles names the entries the importers reach,
// because the direct flag decides which findings a pull request has to answer for.
func TestDirectDependenciesOfTheRealLockfiles(t *testing.T) {
	tests := []struct {
		file string
		want []string
	}{
		{
			file: "pathe-v9.yaml",
			want: []string{
				"@types/node@26.1.0",
				"@typescript/native-preview@7.0.0-dev.20260705.1",
				"@vitest/coverage-v8@4.1.9",
				"changelogen@0.6.2",
				"obuild@0.4.37",
				"oxfmt@0.57.0",
				"oxlint@1.72.0",
				"typescript@6.0.3",
				"vitest@4.1.9",
			},
		},
		{
			file: "pathe-v6.yaml",
			want: []string{
				"@types/node@18.16.3",
				"@vitest/coverage-c8@0.31.0",
				"eslint-config-unjs@0.1.0",
				"eslint@8.39.0",
				"jiti@1.18.2",
				"prettier@2.8.8",
				"standard-version@9.5.0",
				"typescript@5.0.4",
				"unbuild@1.2.1",
				"vitest@0.31.0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			var got []string
			for _, e := range parseFile(t, tt.file).Entries {
				if e.Direct {
					got = append(got, e.Ref.Name+"@"+e.Ref.Version)
				}
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("direct dependencies:\n got %v\nwant %v", got, tt.want)
			}
		})
	}
}

func TestRegisteredForItsFileName(t *testing.T) {
	p, ok := lockfile.For("some/project/pnpm-lock.yaml")
	if !ok || p.Name() != formatName {
		t.Fatalf("For(pnpm-lock.yaml) = %v, %v, want the %s parser", p, ok, formatName)
	}
	if _, ok := lockfile.For("some/project/package-lock.json"); ok {
		t.Error("the pnpm parser claimed package-lock.json")
	}
	lf, err := lockfile.Parse("some/project/pnpm-lock.yaml", strings.NewReader("lockfileVersion: '9.0'\n"))
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
		{
			name: "version 5 keys packages differently",
			body: "lockfileVersion: 5.4\npackages:\n  /is-positive/1.0.0:\n    resolution: {integrity: sha512-x}\n",
			want: "lockfileVersion 5.4 is not supported",
		},
		{
			name: "not yaml at all",
			body: "lockfileVersion: '9.0'\n\tpackages:\n",
			want: "not valid yaml",
		},
		{
			name: "a list where the mapping should be",
			body: "- lockfileVersion: '9.0'\n",
			want: "want a mapping",
		},
		{
			name: "empty file",
			body: "",
			want: "want a mapping",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser{}.Parse("pnpm-lock.yaml", strings.NewReader(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestParseDropsUnreadableEntriesAndKeepsTheRest(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    []lockfile.Entry
		dropped []string
	}{
		{
			name: "a packages map that is not a mapping",
			body: "lockfileVersion: '9.0'\npackages: none\n",
			dropped: []string{
				"packages on line 2 is not a mapping",
			},
		},
		{
			name: "an entry with no metadata and an entry with no version",
			body: "lockfileVersion: '9.0'\n" +
				"packages:\n" +
				"  broken@1.0.0:\n" +
				"  is-positive@3.1.0:\n" +
				"    resolution: {integrity: sha512-x}\n" +
				"  file:packages/thing:\n" +
				"    resolution: {directory: packages/thing, type: directory}\n",
			want: []lockfile.Entry{
				{Ref: ref("is-positive", "3.1.0"), Source: lockfile.SourceRegistry, Integrity: "sha512-x", Line: 4},
			},
			dropped: []string{
				`package "broken@1.0.0" on line 3 has no metadata`,
				`package "file:packages/thing" on line 6 names no package version`,
			},
		},
		{
			name: "an entry whose resolution says nothing",
			body: "lockfileVersion: '9.0'\npackages:\n  mystery@1.0.0: {}\n",
			want: []lockfile.Entry{
				{Ref: ref("mystery", "1.0.0"), Source: lockfile.SourceUnknown, Line: 3},
			},
		},
		{
			name: "an importer entry linked to a directory names no package",
			body: "lockfileVersion: '9.0'\n" +
				"importers:\n" +
				"  .:\n" +
				"    dependencies:\n" +
				"      sibling:\n" +
				"        specifier: workspace:*\n" +
				"        version: link:../sibling\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lf, err := parser{}.Parse("pnpm-lock.yaml", strings.NewReader(tt.body))
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

// failingReader stands in for a file that cannot be read to the end.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errUnreadable }

var errUnreadable = errors.New("disk went away")

func TestParseWrapsAReadError(t *testing.T) {
	_, err := parser{}.Parse("pnpm-lock.yaml", failingReader{})
	if !errors.Is(err, errUnreadable) || !strings.Contains(err.Error(), formatName) {
		t.Fatalf("Parse error = %v, want the read error wrapped with the format name", err)
	}
}

func TestSplitKey(t *testing.T) {
	tests := []struct {
		key     string
		name    string
		version string
	}{
		{key: "vitest@4.1.9", name: "vitest", version: "4.1.9"},
		{key: "/vitest@4.1.9", name: "vitest", version: "4.1.9"},
		{key: "@vitest/coverage-v8@4.1.9", name: "@vitest/coverage-v8", version: "4.1.9"},
		{key: "/@vitest/coverage-v8@4.1.9", name: "@vitest/coverage-v8", version: "4.1.9"},
		// The peer dependencies pnpm appends, including the nested form.
		{key: "/@babel/helper-compilation-targets@7.21.4(@babel/core@7.21.4)", name: "@babel/helper-compilation-targets", version: "7.21.4"},
		{key: "@vitest/mocker@4.1.9(vite@8.1.3(@types/node@26.1.0)(jiti@2.7.0))", name: "@vitest/mocker", version: "4.1.9"},
		// A key that states an origin rather than a version keeps it as written,
		// unless the entry states a name and a version of its own.
		{key: "@vitejs/test-dep-cjs@file:packages/test-dep/cjs", name: "@vitejs/test-dep-cjs", version: "file:packages/test-dep/cjs"},
		// Keys that name no package version at all.
		{key: "github.com/kevva/is-negative/219c424611ff4a2af15f7deeff4f93c62558c43d"},
		{key: "file:packages/local-tool"},
		{key: "@scope/name"},
		{key: ""},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			name, version := splitKey(tt.key)
			if name != tt.name || version != tt.version {
				t.Errorf("splitKey(%q) = %q, %q, want %q, %q", tt.key, name, version, tt.name, tt.version)
			}
		})
	}
}

func TestPackageKeys(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    []string
	}{
		{name: "vitest", version: "4.1.9", want: []string{"vitest@4.1.9"}},
		// An importer records the peer suffix even where the packages key has none.
		{name: "@vitest/coverage-v8", version: "4.1.9(vitest@4.1.9)", want: []string{"@vitest/coverage-v8@4.1.9"}},
		// An alias records the real package as the version, with the leading slash
		// of a version 6 file.
		{name: "positive", version: "is-positive@1.0.0", want: []string{"positive@is-positive@1.0.0", "is-positive@1.0.0"}},
		{name: "positive", version: "/is-positive@1.0.0", want: []string{"positive@is-positive@1.0.0", "is-positive@1.0.0"}},
		// A version 6 file records a git host key as the version.
		{
			name:    "is-negative",
			version: "github.com/kevva/is-negative/219c424611ff4a2af15f7deeff4f93c62558c43d",
			want: []string{
				"is-negative@github.com/kevva/is-negative/219c424611ff4a2af15f7deeff4f93c62558c43d",
				"github.com/kevva/is-negative/219c424611ff4a2af15f7deeff4f93c62558c43d",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name+"@"+tt.version, func(t *testing.T) {
			got := packageKeys(tt.name, tt.version)
			if strings.Join(got, " ") != strings.Join(tt.want, " ") {
				t.Errorf("packageKeys(%q, %q) = %v, want %v", tt.name, tt.version, got, tt.want)
			}
		})
	}
}
