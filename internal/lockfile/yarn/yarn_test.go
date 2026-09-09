package yarn

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

// The checksums of the hand-built fixture, named so that a table of expected
// entries stays readable. Each is the sha512 of "<name>@<version>" in hex, with the
// cache key a Yarn 4 file prefixes it with, which testdata/README.md explains.
const (
	widgetsSum      = "10c0/9beab31e8fdb044acb519ac3fd6943a8ad976cf69526f14797bcb0a80871e890efd52b333ceb0d538d68544690b2c67980236907ee6bd169aaa5ec8c932f5a51"
	devOnlySum      = "10c0/67427a3240a9ac46b7164422ad1ab64cb3e1474a58b3a37bdc045e248d9cb3467b8a740d8d8dc082d91dfa1f1c7e6c606a73c1a0a7ad9c10779b7f54edd8013a"
	fromGitSum      = "10c0/25f16b249a8a7939884c1ccd03303fec39afa01644bdaa149fe956af608bef19d5d14cdb8041df32197041c6a8ca69b4f4738e5c99e8ad837eb54c76841b6e92"
	fromGitSSHSum   = "10c0/e9238b3d90bfe68a52072c385e2c79411b71df94337ed5ef105c885cfad042b12e69564071ee2dd9904462578bfd3f4db93824212d1d6a934c5ec6ba409a80da"
	fromTarballSum  = "10c0/19486d0fc96e3f1de73262ea5b67d760e78d1568e880639e2b782a331433e67ac27fd43346552799f0fcaa5a04b5092e5d02d2467e75b846ee2e3d7696ac12f1"
	generatedSum    = "10c0/dd0c38cfcf655a9cf8cac5c5af7c5d710b7374ed224f0ac2ea442ee95fb550ec37e5ef40c1d60eea4e3fa977d952c711d965041ed713ad39a8b4acca37c0822f"
	localFolderSum  = "10c0/3293e25c8c1c8a047ff7687659b40b9c1720bd9221b7f9eccd1c6c3907fcf04de9ce65a1134d31d1e3f362241da2bd3d55fc0b724e567bfe04cee43c35b6f45e"
	localPortalSum  = "10c0/edef383e6d0a7290e7c15be049efa9ee810a0a2479f5a8cd2dd3d2dff010078d99ff9be06b45287286249473e2c1fedc1c85e7b33857e75ffeef5a8f837a47e3"
	nativeOnlySum   = "10c0/ea00aff618f12c08403e9837b9b40f5a49fcb16b11c83168c1020731ce63b460833167688c828ad357741c6dbbe569b9d4cbbe670d8b0317a2266b06f89ac84d"
	patchedGitSum   = "10c0/a0c0628d986499f94605f668e056c5fb1dfa924d5ecd47415c9e782fb3a4d208e6a27e79eded7f58a3d4d085ef3679fc626879b5bdae8384c24da88cdd87b968"
	patchedToolSum  = "10c0/0993bb885a581af5237c4ec2b2cb01249369bb9584d225a14a357d6cba0279501f6d21798d5779f5675b66f5c14d2e82ef938f4787a04d6b40bd9679e2ee3048"
	isPositiveSum   = "10c0/a1b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
	isNegativeSum   = "10c0/0e6b1f24b4f6cff2b37b1e9f7b3e91b6b7c2b6e7d2a5ff3fbb5c6f0e6d1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4"
	gitSSHRemote    = "git+ssh://git@example.test/example/ssh-dep.git#commit=4f1d2c6f6b0e2f2f3c9f0f1a2b3c4d5e6f708192"
	gitHTTPSRemote  = "https://github.com/example/from-git.git#commit=9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c"
	tarballURL      = "https://files.example.test/from-tarball-2.0.0.tgz"
	execResolution  = "exec:./generate.js#./generate.js::hash=1a2b3c&locator=edge-cases%40workspace%3A."
	patchOfRegistry = "patch:patched-tool@npm%3A4.0.1#./.yarn/patches/patched-tool-npm-4.0.1.patch::version=4.0.1&hash=9a8b7c"
	patchOfGit      = "patch:patched-git@https%3A//github.com/example/patched-git.git%23commit%3D0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c#./.yarn/patches/patched-git.patch::version=1.1.0&hash=5c1d2e"
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

// TestParseEveryShapeOfEntry reads the hand-built file that collects every shape
// one entry can take, in the spelling Yarn 4 writes them.
func TestParseEveryShapeOfEntry(t *testing.T) {
	lf := parseFile(t, "edge-cases.yarn.lock")
	if lf.Version != "8" {
		t.Errorf("Version = %q, want 8", lf.Version)
	}
	checkEntries(t, lf, []lockfile.Entry{
		{Ref: ref("@acme/widgets", "1.4.2"), Source: lockfile.SourceRegistry, Integrity: widgetsSum, Direct: true, Line: 8},
		// The one dependency the root states in a devDependencies map. A real Yarn
		// folds those into "dependencies", so this is the shape read for the day it
		// stops doing so, and nothing else in the file is a development dependency.
		{Ref: ref("dev-only-tool", "3.2.0"), Source: lockfile.SourceRegistry, Integrity: devOnlySum, Direct: true, Dev: true, Line: 15},
		{Ref: ref("from-git-ssh", "1.0.0"), Source: lockfile.SourceGit, Resolved: gitSSHRemote, Integrity: fromGitSSHSum, Direct: true, Line: 47},
		// A git dependency over https, which is a repository and not a download
		// because the path ends in ".git" and the fragment names the commit.
		{Ref: ref("from-git", "3.1.0"), Source: lockfile.SourceGit, Resolved: gitHTTPSRemote, Integrity: fromGitSum, Direct: true, Line: 54},
		{Ref: ref("from-tarball", "2.0.0"), Source: lockfile.SourceURL, Resolved: tarballURL, Integrity: fromTarballSum, Direct: true, Line: 61},
		// A protocol a plugin adds. Guessing at it would be worse than saying so.
		{Ref: ref("generated", "0.0.0"), Source: lockfile.SourceUnknown, Resolved: execResolution, Integrity: generatedSum, Direct: true, Line: 68},
		// The four ways a package can be a directory of the repository.
		{Ref: ref("local-folder", "1.0.0"), Source: lockfile.SourcePath, Resolved: "file:./vendor/local-folder::locator=edge-cases%40workspace%3A.", Integrity: localFolderSum, Direct: true, Line: 75},
		{Ref: ref("local-link", "0.0.0-use.local"), Source: lockfile.SourcePath, Resolved: "link:./vendor/local-link::locator=edge-cases%40workspace%3A.", Direct: true, Line: 82},
		{Ref: ref("local-portal", "2.5.0"), Source: lockfile.SourcePath, Resolved: "portal:./vendor/local-portal::locator=edge-cases%40workspace%3A.", Integrity: localPortalSum, Direct: true, Line: 88},
		{Ref: ref("member", "0.0.0-use.local"), Source: lockfile.SourcePath, Resolved: "workspace:packages/member", Direct: true, Line: 95},
		// The root marks it optional in dependenciesMeta, which is where Yarn keeps
		// the optionalDependencies it folded into the dependency map.
		{Ref: ref("native-only", "2.1.0"), Source: lockfile.SourceRegistry, Integrity: nativeOnlySum, Direct: true, Optional: true, Line: 103},
		// A patch of a git dependency: the source is read out of the locator inside
		// the patch, and the entry is not bundled, because the repository the patch
		// names is fetched and carries a checksum of its own. Calling it bundled
		// would hide the remote from the check that reports an exotic source.
		{Ref: ref("patched-git", "1.1.0"), Source: lockfile.SourceGit, Resolved: patchOfGit, Integrity: patchedGitSum, Direct: true, Line: 111},
		// A patch of a registry package, which is bundled: what the patch is built
		// from is the registry tarball this same entry pins.
		{Ref: ref("patched-tool", "4.0.1"), Source: lockfile.SourceRegistry, Resolved: patchOfRegistry, Integrity: patchedToolSum, Direct: true, Bundled: true, Line: 118},
		// A registry entry that carries no checksum, which is what TD014 reports,
		// and which the workspace member asks for rather than the root.
		{Ref: ref("transitive", "5.4.0"), Source: lockfile.SourceRegistry, Direct: true, Line: 125},
		// An alias: the key is "widgets-v1" and the resolution names the package
		// that is really installed, which is what the ref has to carry.
		{Ref: ref("@acme/widgets", "1.4.2"), Source: lockfile.SourceRegistry, Integrity: widgetsSum, Direct: true, Line: 131},
	})
}

// TestParseReadsCarriageReturns reads a file written with Windows line endings,
// which is what a repository that commits them holds. The fixture is only a test
// of anything while it really carries them, and the repository normalizes every
// other file to LF, so that is checked first.
func TestParseReadsCarriageReturns(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "crlf.yarn.lock"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Contains(data, []byte("\r\n")) {
		t.Fatal("the fixture has lost its carriage returns, so it tests nothing: see testdata/.gitattributes")
	}
	lf := parseFile(t, "crlf.yarn.lock")
	checkEntries(t, lf, []lockfile.Entry{
		{Ref: ref("is-negative", "2.1.0"), Source: lockfile.SourceRegistry, Integrity: isNegativeSum, Line: 16},
		{Ref: ref("is-positive", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: isPositiveSum, Direct: true, Line: 23},
	})
}

// TestRealLockfiles reads the two recorded lockfiles and asserts the whole-file
// counts, so that a change in either format version is caught here.
func TestRealLockfiles(t *testing.T) {
	tests := []struct {
		file     string
		version  string
		entries  int
		direct   int
		dev      int
		optional int
		bundled  int
		sources  map[lockfile.Source]int
		first    int
		last     int
	}{
		{
			file:    "slate-v8.yarn.lock",
			version: "8",
			entries: 339,
			// The root asks for typescript, whose entry is keyed by the builtin patch
			// of it, so the twentieth is only direct once a patch key is unwrapped.
			direct:   20,
			dev:      0, // a yarn.lock states nothing about which dependency is a development one
			optional: 0,
			bundled:  5, // the builtin patches of fsevents, resolve and typescript, each of a registry package
			sources: map[lockfile.Source]int{
				lockfile.SourceRegistry: 334,
				lockfile.SourcePath:     5, // the five workspace members, the root aside
			},
			first: 8,    // @aashutoshrathi/word-wrap@npm:^1.2.3, the first key of the file
			last:  3595, // yargs@npm:^17.3.1, the last
		},
		{
			file:     "babel-v6.yarn.lock",
			version:  "6",
			entries:  279,
			direct:   34, // the builtin patch of typescript among them, as in Slate's file
			dev:      0,
			optional: 2, // the two the root's dependenciesMeta marks so
			bundled:  4,
			sources: map[lockfile.Source]int{
				lockfile.SourceRegistry: 250,
				lockfile.SourcePath:     16, // 14 workspace members and two link: entries
				lockfile.SourceUnknown:  13, // the "condition:" protocol a Babel plugin adds
			},
			first: 8,
			last:  2962,
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
			var direct, dev, optional, bundled int
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
				if e.Bundled {
					bundled++
				}
				// Every entry of a real file sits on a line a finding can point at.
				if e.Line == 0 {
					t.Errorf("%s has no line", e.Ref)
				}
			}
			if direct != tt.direct || dev != tt.dev || optional != tt.optional || bundled != tt.bundled {
				t.Errorf("direct/dev/optional/bundled = %d/%d/%d/%d, want %d/%d/%d/%d",
					direct, dev, optional, bundled, tt.direct, tt.dev, tt.optional, tt.bundled)
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
			file: "slate-v8.yarn.lock",
			want: []lockfile.Entry{
				// A workspace member, which stays in the entries with the path it
				// lives at and is direct because the root asks for it.
				{Ref: ref("slate-react", "0.0.0-use.local"), Source: lockfile.SourcePath, Resolved: "workspace:packages/slate-react", Direct: true, Line: 3150},
				// A builtin patch that carries no checksum of its own. It is the
				// only entry fsevents has, so dropping it would lose the package.
				{
					Ref:      ref("fsevents", "2.3.2"),
					Source:   lockfile.SourceRegistry,
					Resolved: "patch:fsevents@npm%3A2.3.2#optional!builtin<compat/fsevents>::version=2.3.2&hash=df0bf1",
					Bundled:  true,
					Line:     1679,
				},
				// The root declares typescript at "npm:5.2.2" and Yarn keyed its
				// entry by the builtin patch of that descriptor, so the entry is
				// direct only once the patch is unwrapped to what it patches.
				{
					Ref:       ref("typescript", "5.2.2"),
					Source:    lockfile.SourceRegistry,
					Resolved:  "patch:typescript@npm%3A5.2.2#optional!builtin<compat/typescript>::version=5.2.2&hash=f3b441",
					Integrity: "f79cc2ba802c94c2b78dbb00d767a10adb67368ae764709737dc277273ec148aa4558033a03ce901406b35fddf4eac46dabc94a1e1d12d2587e2b9cfe5707b4a",
					Direct:    true,
					Bundled:   true,
					Line:      3429,
				},
				// An alias: the key is "react-is-18" and the ref carries react-is,
				// which is the package that is really installed.
				{
					Ref:       ref("react-is", "18.3.1"),
					Source:    lockfile.SourceRegistry,
					Integrity: "d5f60c87d285af24b1e1e7eaeb123ec256c3c8bdea7061ab3932e3e14685708221bf234ec50b21e10dd07f008f1b966a2730a0ce4ff67905b3872ff2042aec22",
					Line:      2758,
				},
			},
		},
		{
			file: "babel-v6.yarn.lock",
			want: []lockfile.Entry{
				// A version 6 file writes a range without its "npm:" protocol where
				// a version 8 file writes it with one, and mixes the two spellings
				// on one key, so a descriptor has to be matched under both.
				{
					Ref:       ref("@ampproject/remapping", "2.2.0"),
					Source:    lockfile.SourceRegistry,
					Integrity: "d74d170d06468913921d72430259424b7e4c826b5a7d39ff839a29d547efb97dc577caa8ba3fb5cf023624e9af9d09651afc3d4112a45e2050328abc9b3a2292",
					Direct:    true,
					Line:      8,
				},
				// A "link:" entry, which points at a directory that need not exist.
				// Unlike npm, no second entry names the same package, so it stays.
				{
					Ref:      ref("@types/babel__core", "0.0.0-use.local"),
					Source:   lockfile.SourcePath,
					Resolved: "link:./nope::locator=babel%40workspace%3A.",
					Line:     672,
				},
				// The "condition:" protocol a Babel plugin adds, which resolves to
				// one of two packages depending on an environment variable.
				{
					Ref:       ref("eslint-visitor-keys", "0.0.0-condition-f0c342"),
					Source:    lockfile.SourceUnknown,
					Resolved:  "condition:BABEL_8_BREAKING?^3.3.0:^2.1.0#f0c342",
					Integrity: "a7191f76d5f69e2ff4b01c7cd319cd07432e0e1d29b9b3cdc63ae0d3f8619cfaf211c65cd0ed68a7a91b23eb80483a898a80a55661277b72d1c95c8de631e51a",
					Direct:    true,
					Line:      1392,
				},
				// The one entry fsevents 1 has, a builtin patch with no checksum.
				{
					Ref:      ref("fsevents", "1.2.13"),
					Source:   lockfile.SourceRegistry,
					Resolved: "patch:fsevents@npm%3A1.2.13#~builtin<compat/fsevents>::version=1.2.13&hash=18f3a7",
					Bundled:  true,
					Line:     1539,
				},
				// The same builtin patch of typescript in the spelling a version 6
				// file writes, where the descriptor inside the patch carries no
				// "npm:" protocol either.
				{
					Ref:       ref("typescript", "4.9.3"),
					Source:    lockfile.SourceRegistry,
					Resolved:  "patch:typescript@npm%3A4.9.3#~builtin<compat/typescript>::version=4.9.3&hash=701156",
					Integrity: "ef65c22622d864497d0a0c5db693523329b3284c15fe632e93ad9aa059e8dc38ef3bd767d6f26b1e5ecf9446f49bd0f6c4e5714a2eeaf352805dc002479843d1",
					Direct:    true,
					Bundled:   true,
					Line:      2768,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			lf := parseFile(t, tt.file)
			for _, want := range tt.want {
				// Matched by line rather than by name: a lockfile holds the same
				// package version under more than one key, a patch of it and the
				// entry it patches among them, and each is an entry of its own.
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

// TestDirectDependenciesOfTheRealLockfiles names the entries the workspaces reach,
// because the direct flag decides which findings a pull request has to answer for.
func TestDirectDependenciesOfTheRealLockfiles(t *testing.T) {
	// Yarn keeps no record of the root's dependencies other than the root's own
	// workspace entry, so this list is what that entry and the members' entries
	// together ask for, out of the entries the fixture still holds.
	//
	// It is read out of the fixture and not out of a parse, which is how the entry
	// keyed by a patch was missing from it before: take the six blocks whose
	// resolution range starts with "workspace:" (lines 3013, 3038, 3052, 3064, 3150
	// and 3184), collect every descriptor their dependencies and devDependencies
	// name, and for each one find the entry whose key lists that descriptor, under
	// either spelling of it and through any patch wrapping it. The entry's
	// resolution names the package and the version below, and the order is the
	// order the fixture lists those entries in.
	want := []string{
		"@babel/plugin-external-helpers@7.22.5",
		"@babel/preset-env@7.23.2",
		"@types/is-hotkey@0.1.8",
		"@types/jest@29.5.6",
		"@types/lodash@4.14.200",
		"@types/react@18.2.41",
		"@typescript-eslint/parser@6.8.0",
		"prismjs@1.29.0",
		"react-values@0.3.3",
		"rimraf@5.0.5",
		"rollup-plugin-json@4.0.0",
		"rollup-plugin-terser@7.0.2",
		"scroll-into-view-if-needed@3.1.0",
		"slate-dom@0.0.0-use.local",
		"slate-history@0.0.0-use.local",
		"slate-hyperscript@0.0.0-use.local",
		"slate-react@0.0.0-use.local",
		"slate@0.0.0-use.local",
		"tiny-invariant@1.3.1",
		// Declared as typescript: "npm:5.2.2" on line 3146 and keyed on line 3429 by
		// the builtin patch of that descriptor rather than by the descriptor itself.
		"typescript@5.2.2",
	}
	var got []string
	for _, e := range parseFile(t, "slate-v8.yarn.lock").Entries {
		if e.Direct {
			got = append(got, e.Ref.Name+"@"+e.Ref.Version)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("direct dependencies:\n got %v\nwant %v", got, want)
	}
}

// TestOptionalAndDevNeedEveryWorkspaceToSaySo builds what a monorepo writes when
// one workspace marks a package optional and another simply requires it: one key
// listing both descriptors. An install may leave out only what nothing requires,
// so which of the two descriptors Yarn sorted first has to decide nothing.
func TestOptionalAndDevNeedEveryWorkspaceToSaySo(t *testing.T) {
	// The root declares fsevents at ^2.3.2 and the member at ^2.3.3, which is the
	// pair of descriptors the shared entry is keyed by.
	file := func(rootSection, rootMeta, memberSection string) string {
		return "__metadata:\n  version: 8\n" +
			"\"fsevents@npm:^2.3.2, fsevents@npm:^2.3.3\":\n" +
			"  version: 2.3.3\n" +
			"  resolution: \"fsevents@npm:2.3.3\"\n" +
			"\"member@workspace:*, member@workspace:packages/member\":\n" +
			"  version: 0.0.0-use.local\n" +
			"  resolution: \"member@workspace:packages/member\"\n" +
			"  " + memberSection + ":\n" +
			"    fsevents: \"npm:^2.3.3\"\n" +
			"\"root@workspace:.\":\n" +
			"  version: 0.0.0-use.local\n" +
			"  resolution: \"root@workspace:.\"\n" +
			"  " + rootSection + ":\n" +
			"    fsevents: \"npm:^2.3.2\"\n" +
			"    member: \"workspace:*\"\n" +
			rootMeta
	}
	const marksItOptional = "  dependenciesMeta:\n    fsevents:\n      optional: true\n"
	tests := []struct {
		name string
		body string
		want lockfile.Entry
	}{
		{
			name: "the root marks it optional and the member requires it",
			body: file("dependencies", marksItOptional, "dependencies"),
			want: lockfile.Entry{Ref: ref("fsevents", "2.3.3"), Source: lockfile.SourceRegistry, Direct: true, Line: 3},
		},
		{
			name: "every workspace that names it marks it optional",
			body: file("dependencies", marksItOptional, "optionalDependencies"),
			want: lockfile.Entry{Ref: ref("fsevents", "2.3.3"), Source: lockfile.SourceRegistry, Direct: true, Optional: true, Line: 3},
		},
		{
			name: "the root needs it only to develop and the member at runtime",
			body: file("devDependencies", "", "dependencies"),
			want: lockfile.Entry{Ref: ref("fsevents", "2.3.3"), Source: lockfile.SourceRegistry, Direct: true, Line: 3},
		},
		{
			name: "every workspace that names it needs it only to develop",
			body: file("devDependencies", "", "devDependencies"),
			want: lockfile.Entry{Ref: ref("fsevents", "2.3.3"), Source: lockfile.SourceRegistry, Direct: true, Dev: true, Line: 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lf, err := parser{}.Parse("yarn.lock", strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(lf.Entries) == 0 {
				t.Fatalf("no entries: %v", lf.Dropped)
			}
			if got := lf.Entries[0]; got != tt.want {
				t.Errorf("fsevents:\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestRegisteredForItsFileName(t *testing.T) {
	p, ok := lockfile.For("some/project/yarn.lock")
	if !ok || p.Name() != formatName {
		t.Fatalf("For(yarn.lock) = %v, %v, want the %s parser", p, ok, formatName)
	}
	if _, ok := lockfile.For("some/project/package-lock.json"); ok {
		t.Error("the yarn parser claimed package-lock.json")
	}
	lf, err := lockfile.Parse("some/project/yarn.lock", strings.NewReader("__metadata:\n  version: 8\n"))
	if err != nil {
		t.Fatalf("Parse through the registry: %v", err)
	}
	if lf.Format != formatName || len(lf.Entries) != 0 {
		t.Errorf("Parse = %+v, want the %s format and no entry", lf, formatName)
	}
}

func TestParseRejectsFilesItCannotRead(t *testing.T) {
	// A yarn.lock written by Yarn 1, which is a format of its own that only looks
	// like yaml, in the shape Yarn 1 wrote it.
	const yarnOne = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n" +
		"# yarn lockfile v1\n\n\n" +
		"\"@babel/code-frame@^7.0.0\":\n" +
		"  version \"7.0.0\"\n" +
		"  resolved \"https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.0.0.tgz#06e2ab19bdb535385559aabb5ba59729482800f8\"\n"
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "a yarn 1 lockfile", body: yarnOne, want: "this is the yarn.lock Yarn 1 wrote"},
		{name: "empty file", body: "", want: "Yarn 1 wrote"},
		{name: "a list where the mapping should be", body: "- __metadata:\n    version: 8\n", want: "want a mapping"},
		{name: "no metadata block", body: "\"is-positive@npm:^1.0.0\":\n  version: 1.0.0\n", want: "Yarn 1 wrote"},
		{name: "not yaml at all", body: "__metadata:\n  version: 8\n\t bad: true\n", want: "not valid yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parser{}.Parse("yarn.lock", strings.NewReader(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error = %v, want one containing %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), formatName) {
				t.Errorf("Parse error = %v, want it to name the file", err)
			}
		})
	}
}

// TestParseReportsATruncatedFile reads a file that stops in the middle of a quoted
// value, which is what a half written or half transferred lockfile looks like. It
// has to be reported rather than panic or read as an empty file.
func TestParseReportsATruncatedFile(t *testing.T) {
	path := filepath.Join("testdata", "truncated.yarn.lock")
	f, err := os.Open(path) // #nosec G304 -- the path is a fixture name from the test itself
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()
	_, err = parser{}.Parse(path, f)
	if err == nil || !strings.Contains(err.Error(), "not valid yaml") || !strings.Contains(err.Error(), formatName) {
		t.Fatalf("Parse error = %v, want a yaml error naming %s", err, formatName)
	}
}

func TestParseDropsUnreadableEntriesAndKeepsTheRest(t *testing.T) {
	const head = "__metadata:\n  version: 8\n"
	tests := []struct {
		name    string
		body    string
		want    []lockfile.Entry
		dropped []string
	}{
		{
			name: "an entry with no metadata",
			body: head +
				"\"broken@npm:^1.0.0\":\n" +
				"\"is-positive@npm:^1.0.0\":\n" +
				"  version: 1.0.0\n" +
				"  resolution: \"is-positive@npm:1.0.0\"\n" +
				"  checksum: 10c0/abcdef\n",
			want: []lockfile.Entry{
				{Ref: ref("is-positive", "1.0.0"), Source: lockfile.SourceRegistry, Integrity: "10c0/abcdef", Line: 4},
			},
			dropped: []string{`"broken@npm:^1.0.0" on line 3 has no metadata`},
		},
		{
			name: "an entry with no version, which is what a file cut at a line boundary ends with",
			body: head +
				"\"is-positive@npm:^1.0.0\":\n" +
				"  version: 1.0.0\n" +
				"  resolution: \"is-positive@npm:1.0.0\"\n" +
				"\"half-written@npm:^2.0.0\":\n" +
				"  resolution: \"half-written@npm:2.0.0\"\n",
			want: []lockfile.Entry{
				{Ref: ref("is-positive", "1.0.0"), Source: lockfile.SourceRegistry, Line: 3},
			},
			dropped: []string{`"half-written@npm:^2.0.0" on line 6 has no version`},
		},
		{
			name: "an entry whose key names no package and that states no resolution",
			body: head +
				"\"@scope\":\n" +
				"  version: 1.0.0\n",
			dropped: []string{`"@scope" on line 3 names no package`},
		},
		{
			name: "an entry that states no resolution is read through its key",
			body: head +
				"\"mystery@npm:^1.0.0\":\n" +
				"  version: 1.2.3\n",
			want: []lockfile.Entry{
				{Ref: ref("mystery", "1.2.3"), Source: lockfile.SourceRegistry, Line: 3},
			},
		},
		{
			name: "a resolution reached through a yaml alias reads as what the anchor says",
			body: head +
				"\"anchor@npm:^1.0.0\":\n" +
				"  version: 1.0.0\n" +
				"  resolution: &remote \"anchor@https://files.example.test/anchor-1.0.0.tgz\"\n" +
				"\"copy@npm:^1.0.0\":\n" +
				"  version: 1.0.0\n" +
				"  resolution: *remote\n",
			want: []lockfile.Entry{
				{Ref: ref("anchor", "1.0.0"), Source: lockfile.SourceURL, Resolved: "https://files.example.test/anchor-1.0.0.tgz", Line: 3},
				{Ref: ref("anchor", "1.0.0"), Source: lockfile.SourceURL, Resolved: "https://files.example.test/anchor-1.0.0.tgz", Line: 6},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lf, err := parser{}.Parse("yarn.lock", strings.NewReader(tt.body))
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
	_, err := parser{}.Parse("yarn.lock", failingReader{})
	if !errors.Is(err, errUnreadable) || !strings.Contains(err.Error(), formatName) {
		t.Fatalf("Parse error = %v, want the read error wrapped with the format name", err)
	}
}

func TestSplitDescriptor(t *testing.T) {
	tests := []struct {
		descriptor string
		name       string
		rang       string
	}{
		{descriptor: "typescript@npm:^5.2.2", name: "typescript", rang: "npm:^5.2.2"},
		{descriptor: "@types/node@npm:^20.8.7", name: "@types/node", rang: "npm:^20.8.7"},
		// A version 6 file leaves the protocol off the range.
		{descriptor: "resolve@^1.10.1", name: "resolve", rang: "^1.10.1"},
		// An alias, where the range names another package. Splitting at the last
		// "@" instead would read the package as "string-width" at the range "^4.2.0".
		{descriptor: "string-width-cjs@npm:string-width@^4.2.0", name: "string-width-cjs", rang: "npm:string-width@^4.2.0"},
		{descriptor: "widgets@npm:@acme/widgets@^1.0.0", name: "widgets", rang: "npm:@acme/widgets@^1.0.0"},
		{descriptor: "@babel-baseline/core@npm:@babel/core@7.18.5", name: "@babel-baseline/core", rang: "npm:@babel/core@7.18.5"},
		// The protocols whose range holds an "@" of its own.
		{descriptor: "dep@git+ssh://git@example.test/o/r.git#commit=abc", name: "dep", rang: "git+ssh://git@example.test/o/r.git#commit=abc"},
		{descriptor: "dep@patch:dep@npm%3A1.0.0#./p.patch", name: "dep", rang: "patch:dep@npm%3A1.0.0#./p.patch"},
		// Text that names no range at all.
		{descriptor: "@scope/name", name: "@scope/name"},
		{descriptor: "bare-name", name: "bare-name"},
		// A scope with no name after it is not a package Yarn can write.
		{descriptor: "@scope"},
		{descriptor: "@"},
		{descriptor: ""},
	}
	for _, tt := range tests {
		t.Run(tt.descriptor, func(t *testing.T) {
			name, rang := splitDescriptor(tt.descriptor)
			if name != tt.name || rang != tt.rang {
				t.Errorf("splitDescriptor(%q) = %q, %q, want %q, %q", tt.descriptor, name, rang, tt.name, tt.rang)
			}
		})
	}
}

func TestSourceOf(t *testing.T) {
	tests := []struct {
		rang string
		want lockfile.Source
	}{
		{rang: "npm:1.2.3", want: lockfile.SourceRegistry},
		// A version 6 file writes a bare version for a package it did resolve.
		{rang: "1.2.3", want: lockfile.SourceRegistry},
		{rang: "workspace:packages/ui", want: lockfile.SourcePath},
		{rang: "link:./vendor/thing", want: lockfile.SourcePath},
		{rang: "portal:./vendor/thing", want: lockfile.SourcePath},
		{rang: "file:./vendor/thing", want: lockfile.SourcePath},
		{rang: "git+ssh://git@example.test/o/r.git#commit=abc", want: lockfile.SourceGit},
		{rang: "git@example.test:o/r.git#commit=abc", want: lockfile.SourceUnknown}, // not a spelling Yarn writes
		{rang: "git://example.test/o/r#commit=abc", want: lockfile.SourceGit},
		{rang: "ssh://git@example.test/o/r#commit=abc", want: lockfile.SourceGit},
		{rang: "github:owner/repo#commit=abc", want: lockfile.SourceGit},
		{rang: "gitlab:owner/repo#commit=abc", want: lockfile.SourceGit},
		{rang: "bitbucket:owner/repo#commit=abc", want: lockfile.SourceGit},
		// An http range is a repository when the path says so or when the fragment
		// carries the commit Yarn resolved, and a download otherwise.
		{rang: "https://github.com/o/r.git#commit=abc", want: lockfile.SourceGit},
		{rang: "https://example.test/o/r#commit=abcdef", want: lockfile.SourceGit},
		{rang: "https://files.example.test/thing-1.0.0.tgz", want: lockfile.SourceURL},
		{rang: "http://files.example.test/thing-1.0.0.tgz", want: lockfile.SourceURL},
		// A patch takes the source of what it patches, however deeply nested.
		{rang: "patch:thing@npm%3A1.0.0#./p.patch", want: lockfile.SourceRegistry},
		{rang: "patch:thing@https%3A//files.example.test/t.tgz#./p.patch", want: lockfile.SourceURL},
		{rang: "patch:thing@workspace%3Apackages/ui#./p.patch", want: lockfile.SourcePath},
		{rang: "patch:thing@patch%3Athing@npm%253A1.0.0%23./a.patch#./b.patch", want: lockfile.SourceRegistry},
		{rang: "exec:./generate.js", want: lockfile.SourceUnknown},
		{rang: "condition:BABEL_8_BREAKING?^3.3.0:^2.1.0#f0c342", want: lockfile.SourceUnknown},
		{rang: "", want: lockfile.SourceUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.rang, func(t *testing.T) {
			if got := sourceOf(tt.rang, 0); got != tt.want {
				t.Errorf("sourceOf(%q) = %q, want %q", tt.rang, got, tt.want)
			}
		})
	}
}

// TestSourceOfStopsFollowingPatches builds a patch of a patch of a patch, deeper
// than the parser follows, and checks that it costs an unknown source rather than
// the process: a lockfile in a pull request is text somebody else wrote.
func TestSourceOfStopsFollowingPatches(t *testing.T) {
	// Wrapping a locator in a patch escapes the characters that would otherwise end
	// it, which is how Yarn writes a patch of something that is itself patched.
	escape := strings.NewReplacer("%", "%25", ":", "%3A", "#", "%23")
	wrap := func(inner string) string { return "patch:thing@" + escape.Replace(inner) }

	rang := "npm:1.0.0"
	for range maxPatchDepth - 1 {
		rang = wrap(rang)
	}
	if got := sourceOf(rang, 0); got != lockfile.SourceRegistry {
		t.Errorf("%d patches deep = %q, want the registry the innermost locator names", maxPatchDepth-1, got)
	}
	if got := sourceOf(wrap(wrap(rang)), 0); got != lockfile.SourceUnknown {
		t.Errorf("%d patches deep = %q, want unknown", maxPatchDepth+1, got)
	}
}

// TestBundledIsOnlyAPatchOfARegistryPackage checks the one thing Bundled says
// about a yarn entry: that nothing of its own is fetched for it, which holds for a
// patch of a package the registry serves and for no other patch. A patch of a
// remote is a fetch of that remote, and an entry called bundled is one the exotic
// source and missing checksum checks say nothing about.
func TestBundledIsOnlyAPatchOfARegistryPackage(t *testing.T) {
	tests := []struct {
		rang string
		want bool
	}{
		{rang: "patch:thing@npm%3A1.0.0#./p.patch", want: true},
		// A version 6 file writes the patched descriptor without its protocol.
		{rang: "patch:thing@1.0.0#~builtin<compat/thing>", want: true},
		{rang: "patch:thing@patch%3Athing@npm%253A1.0.0%23./a.patch#./b.patch", want: true},
		// A patch of a repository, of a download, of a directory and of a protocol
		// a plugin adds: each fetches what the locator inside the patch names, and
		// each has to keep the source that says so.
		{rang: "patch:thing@https%3A//github.com/o/r.git%23commit%3Dabc#./p.patch"},
		{rang: "patch:thing@https%3A//files.example.test/t.tgz#./p.patch"},
		{rang: "patch:thing@workspace%3Apackages/ui#./p.patch"},
		{rang: "patch:thing@exec%3A./generate.js#./p.patch"},
		// Anything that is not a patch is fetched as itself.
		{rang: "npm:1.2.3"},
		{rang: "https://files.example.test/t.tgz"},
		{rang: ""},
	}
	for _, tt := range tests {
		t.Run(tt.rang, func(t *testing.T) {
			if got := bundled(tt.rang); got != tt.want {
				t.Errorf("bundled(%q) = %v, want %v", tt.rang, got, tt.want)
			}
		})
	}
}

func TestResolvedOf(t *testing.T) {
	tests := []struct {
		rang string
		want string
	}{
		// A registry install states no location: Yarn keeps the registry it
		// installs from in .yarnrc.yml and never in the lockfile.
		{rang: "npm:1.2.3"},
		{rang: "1.2.3"},
		{rang: ""},
		{rang: "workspace:packages/ui", want: "workspace:packages/ui"},
		{rang: "https://files.example.test/t.tgz", want: "https://files.example.test/t.tgz"},
	}
	for _, tt := range tests {
		t.Run(tt.rang, func(t *testing.T) {
			if got := resolvedOf(tt.rang); got != tt.want {
				t.Errorf("resolvedOf(%q) = %q, want %q", tt.rang, got, tt.want)
			}
		})
	}
}
