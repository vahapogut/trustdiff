package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestDetectMonorepo checks the whole answer for the committed fixture: which
// managers, in which directories, with which files, on which evidence and from
// which source their version came. The fixture is a monorepo on purpose, because
// the mistake a detector makes is reporting one manager for a tree that has four,
// and because every interesting version path is in it at once: a packageManager
// pin at the root, a lockfile marker in a workspace member, and a manager whose
// version nothing in the repository states.
func TestDetectMonorepo(t *testing.T) {
	managers, notes, err := Detect(context.Background(), filepath.Join("testdata", "monorepo"), DetectOptions{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// Nothing in the fixture is unreadable, so a note here means the walk tripped
	// over something it should have understood.
	if len(notes) != 0 {
		t.Errorf("notes = %v, want none", notes)
	}

	checkManagers(t, managers, []Manager{{
		ID:       Actions,
		Root:     ".",
		Evidence: []string{"the workflows in .github/workflows"},
		Files:    []string{".github/workflows/ci.yml"},
	}, {
		// bunfig.toml is what proves Bun. package.json is listed because Bun reads
		// it, not because it says anything about Bun, and the root pin names pnpm,
		// so Bun's version stays unknown.
		ID:       Bun,
		Root:     ".",
		Evidence: []string{"bunfig.toml"},
		Files:    []string{"bunfig.toml", "package.json"},
	}, {
		ID:       Cargo,
		Root:     "tools/rs",
		Evidence: []string{"Cargo.toml"},
		Files:    []string{"tools/rs/Cargo.toml"},
	}, {
		ID:       Deno,
		Root:     ".",
		Evidence: []string{"deno.jsonc"},
		Files:    []string{"deno.jsonc"},
	}, {
		// The bot's file lives in .github and the repository it updates is the one
		// that directory belongs to, so its root is the repository and not .github.
		ID:       Dependabot,
		Root:     ".",
		Evidence: []string{".github/dependabot.yml"},
		Files:    []string{".github/dependabot.yml"},
	}, {
		// A workspace member with its own lockfile is its own manager, and the root
		// pin names pnpm, so nothing pins this npm and the lockfile marker answers
		// as the floor it is.
		ID:            NPM,
		Root:          "apps/web",
		Version:       "7.0.0",
		VersionSource: "lockfileVersion 3 of apps/web/package-lock.json, which no npm older than 7.0.0 writes",
		Evidence:      []string{".npmrc", "package-lock.json"},
		Files:         []string{"apps/web/.npmrc", "apps/web/package-lock.json"},
	}, {
		// The pin beats the lockfile marker beside it: pnpm-lock.yaml says 9.0,
		// which would make this pnpm 9 or later, and the pin says which one.
		ID:            PNPM,
		Root:          ".",
		Version:       "11.2.0",
		VersionSource: "the packageManager field of package.json",
		Evidence:      []string{"pnpm-lock.yaml", "pnpm-workspace.yaml", "the packageManager field of package.json"},
		Files:         []string{"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"},
	}, {
		// uv.lock states version 1, which every uv that has ever written a lockfile
		// states, so it identifies no uv and the version stays empty rather than
		// being guessed at.
		ID:       UV,
		Root:     "services/api",
		Evidence: []string{"the [tool.uv] table of pyproject.toml", "uv.lock"},
		Files:    []string{"services/api/pyproject.toml", "services/api/uv.lock"},
	}})
}

// TestDetectVersions walks the version resolution one case at a time: what each
// marker means, which mappings are deliberately absent, and what beats what.
func TestDetectVersions(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		id      ManagerID
		root    string
		version string
		// source is compared exactly when it is set, because the sentence is what a
		// reader of the scorecard is told about how much the version is worth.
		source string
	}{{
		name:    "npm lockfileVersion 3",
		files:   map[string]string{"package-lock.json": `{"lockfileVersion": 3}`},
		id:      NPM,
		version: "7.0.0",
		source:  "lockfileVersion 3 of package-lock.json, which no npm older than 7.0.0 writes",
	}, {
		name:    "npm lockfileVersion 1",
		files:   map[string]string{"package-lock.json": `{"lockfileVersion": 1}`},
		id:      NPM,
		version: "5.0.0",
	}, {
		name:    "pnpm lockfileVersion 9.0",
		files:   map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\n"},
		id:      PNPM,
		version: "9.0.0",
		source:  "lockfileVersion 9.0 of pnpm-lock.yaml, which no pnpm older than 9.0.0 writes",
	}, {
		name:    "pnpm lockfileVersion 6.0",
		files:   map[string]string{"pnpm-lock.yaml": "lockfileVersion: '6.0'\n"},
		id:      PNPM,
		version: "8.0.0",
	}, {
		// pnpm's 5.x lockfiles belong to versions older than every setting doctor
		// checks and are deliberately not mapped.
		name:    "pnpm lockfileVersion 5.4 is not mapped",
		files:   map[string]string{"pnpm-lock.yaml": "lockfileVersion: 5.4\n"},
		id:      PNPM,
		version: "",
	}, {
		// A lockfile checked out on Windows without an eol setting has CRLF endings
		// and is still the same lockfile.
		name:    "pnpm lockfileVersion with Windows line endings",
		files:   map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\r\n\r\nimporters:\r\n"},
		id:      PNPM,
		version: "9.0.0",
	}, {
		name:    "bun text lockfile",
		files:   map[string]string{"bun.lock": "{\n  \"lockfileVersion\": 0,\n  \"workspaces\": {}\n}\n"},
		id:      Bun,
		version: "1.1.39",
	}, {
		// Every uv writes version 1, so the marker says a lockfile is a uv lockfile
		// and nothing else.
		name:    "uv lockfile version identifies no uv",
		files:   map[string]string{"uv.lock": "version = 1\nrevision = 3\n"},
		id:      UV,
		version: "",
	}, {
		name:    "cargo lockfile version 4",
		files:   map[string]string{"Cargo.lock": "version = 4\n\n[[package]]\nname = \"rs\"\nversion = \"0.1.0\"\n"},
		id:      Cargo,
		version: "1.78.0",
		source:  "version 4 of Cargo.lock, which no cargo older than 1.78.0 writes",
	}, {
		// Version 2 is not mapped, and the quoted version inside the package entry
		// must not be mistaken for the format's own.
		name:    "cargo lockfile version 2 is not mapped",
		files:   map[string]string{"Cargo.lock": "version = 2\n\n[[package]]\nname = \"rs\"\nversion = \"9.9.9\"\n"},
		id:      Cargo,
		version: "",
	}, {
		name: "yarn from yarnPath",
		files: map[string]string{
			".yarnrc.yml":                    "yarnPath: .yarn/releases/yarn-4.15.0.cjs\nnodeLinker: node-modules\n",
			".yarn/releases/yarn-4.15.0.cjs": "// a Yarn release\n",
		},
		id:      Yarn,
		version: "4.15.0",
		source:  "the yarnPath of .yarnrc.yml",
	}, {
		name:    "yarn from the committed release alone",
		files:   map[string]string{".yarn/releases/yarn-4.9.1.cjs": "// a Yarn release\n"},
		id:      Yarn,
		version: "4.9.1",
		source:  "the release committed at .yarn/releases/yarn-4.9.1.cjs",
	}, {
		name: "the pin beats the lockfile marker",
		files: map[string]string{
			"package.json":      `{"packageManager": "npm@10.9.0"}`,
			"package-lock.json": `{"lockfileVersion": 3}`,
		},
		id:      NPM,
		version: "10.9.0",
		source:  "the packageManager field of package.json",
	}, {
		// corepack runs a workspace member without a pin under the pin above it, so
		// the search for one runs upward from the manager's own directory.
		name: "a member inherits the pin above it",
		files: map[string]string{
			"package.json":            `{"packageManager": "pnpm@11.2.0+sha512.abc"}`,
			"apps/web/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
		},
		id:      PNPM,
		root:    "apps/web",
		version: "11.2.0",
		source:  "the packageManager field of package.json",
	}, {
		// A pin naming another manager is not this one's answer, and the search
		// carries on past it rather than stopping there.
		name: "a pin for another manager does not answer",
		files: map[string]string{
			"package.json":         `{"packageManager": "pnpm@11.2.0"}`,
			"apps/web/bunfig.toml": "[install]\n",
		},
		id:      Bun,
		root:    "apps/web",
		version: "",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.root
			if root == "" {
				root = "."
			}
			managers, notes, err := Detect(context.Background(), writeDetectFixture(t, tc.files), DetectOptions{})
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(notes) != 0 {
				t.Errorf("notes = %v, want none", notes)
			}
			m := findManager(t, managers, tc.id, root)
			if m.Version != tc.version {
				t.Errorf("Version = %q, want %q (source %q)", m.Version, tc.version, m.VersionSource)
			}
			if tc.source != "" && m.VersionSource != tc.source {
				t.Errorf("VersionSource = %q, want %q", m.VersionSource, tc.source)
			}
			if tc.version == "" && m.VersionSource != "" {
				t.Errorf("VersionSource = %q, want none beside an unknown version", m.VersionSource)
			}
		})
	}
}

// TestDetectEvidence checks the evidence that comes from inside a file rather
// than from its name, which is the part a file's existence cannot decide.
func TestDetectEvidence(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		id    ManagerID
		// evidence is the line the manager must have counted on.
		evidence string
	}{{
		name:     "a packageManager field naming yarn",
		files:    map[string]string{"package.json": `{"packageManager": "yarn@4.15.0"}`},
		id:       Yarn,
		evidence: "the packageManager field of package.json",
	}, {
		name:     "a renovate key in package.json",
		files:    map[string]string{"package.json": `{"renovate": {"extends": ["config:recommended"]}}`},
		id:       Renovate,
		evidence: "the renovate key of package.json",
	}, {
		name:     "a poetry table in pyproject.toml",
		files:    map[string]string{"pyproject.toml": "[tool.poetry]\nname = \"api\"\n"},
		id:       Poetry,
		evidence: "the [tool.poetry] table of pyproject.toml",
	}, {
		name:     "a requirements file with a suffix",
		files:    map[string]string{"requirements-dev.txt": "ruff==0.14.0\n"},
		id:       Pip,
		evidence: "requirements-dev.txt",
	}, {
		name:     "a renovate configuration file",
		files:    map[string]string{".renovaterc.json": `{"extends": ["config:recommended"]}`},
		id:       Renovate,
		evidence: ".renovaterc.json",
	}, {
		name:     "a dependabot configuration in .github",
		files:    map[string]string{".github/dependabot.yaml": "version: 2\n"},
		id:       Dependabot,
		evidence: ".github/dependabot.yaml",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			managers, _, err := Detect(context.Background(), writeDetectFixture(t, tc.files), DetectOptions{})
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			m := findManager(t, managers, tc.id, ".")
			if !slices.Contains(m.Evidence, tc.evidence) {
				t.Errorf("Evidence = %v, want it to include %q", m.Evidence, tc.evidence)
			}
		})
	}
}

// TestDetectIgnoresInstalledCopies checks that the walk does not report the
// package managers of somebody else's packages. A node_modules holds hundreds of
// package.json files and the odd lockfile, and none of them is the repository's.
func TestDetectIgnoresInstalledCopies(t *testing.T) {
	managers, _, err := Detect(context.Background(), writeDetectFixture(t, map[string]string{
		"package.json":                       `{"packageManager": "pnpm@11.2.0"}`,
		"node_modules/left-pad/package.json": `{"packageManager": "yarn@1.22.22"}`,
		"node_modules/left-pad/yarn.lock":    "# yarn lockfile v1\n",
		"vendor/thing/Cargo.toml":            "[package]\nname = \"thing\"\n",
	}), DetectOptions{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(managers) != 1 || managers[0].ID != PNPM || managers[0].Root != "." {
		t.Fatalf("detected %s, want pnpm at the root alone", spellManagers(managers))
	}
}

// TestDetectNotesWhatItCannotRead checks that a manifest nobody can parse is a
// note and not a failure: the rest of the repository is still detected, and the
// scan says out loud that it could not use the file.
func TestDetectNotesWhatItCannotRead(t *testing.T) {
	managers, notes, err := Detect(context.Background(), writeDetectFixture(t, map[string]string{
		"package.json":   "{ this is not json",
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	}), DetectOptions{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	m := findManager(t, managers, PNPM, ".")
	if m.Version != "9.0.0" {
		t.Errorf("Version = %q, want the lockfile marker to still answer", m.Version)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "package.json could not be read") {
		t.Fatalf("notes = %v, want one naming package.json", notes)
	}
}

// TestDetectNotesADirectoryItCannotRead checks that a subtree the walk is
// refused is reported rather than passed over in silence, and that the rest of
// the repository is still detected.
//
// The test is skipped where removing a directory's permissions does not stop a
// walk, which is what happens on Windows, where a mode of zero is not a refusal,
// and where the test runs as a user who is allowed everything.
func TestDetectNotesADirectoryItCannotRead(t *testing.T) {
	root := writeDetectFixture(t, map[string]string{
		"package.json":           `{"packageManager": "pnpm@11.2.0"}`,
		"private/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	closed := filepath.Join(root, "private")
	if err := os.Chmod(closed, 0); err != nil {
		t.Skipf("a directory cannot be closed on %s: %v", runtime.GOOS, err)
	}
	// Put the permissions back, or the temporary directory cannot be cleaned up.
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })

	managers, notes, err := Detect(context.Background(), root, DetectOptions{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(notes) == 0 {
		t.Skipf("%s walks a directory whose permissions were removed", runtime.GOOS)
	}
	if !strings.Contains(notes[0], "private could not be read") {
		t.Errorf("notes = %v, want one naming the directory that was refused", notes)
	}
	findManager(t, managers, PNPM, ".")
}

// TestDetectRejectsWhatIsNotADirectory checks the one thing that is an error
// rather than a note: being pointed at something that cannot be walked at all.
func TestDetectRejectsWhatIsNotADirectory(t *testing.T) {
	root := writeDetectFixture(t, map[string]string{"package.json": "{}"})
	if _, _, err := Detect(context.Background(), filepath.Join(root, "package.json"), DetectOptions{}); err == nil {
		t.Fatal("Detect on a file returned no error")
	}
	if _, _, err := Detect(context.Background(), filepath.Join(root, "nowhere"), DetectOptions{}); err == nil {
		t.Fatal("Detect on a missing directory returned no error")
	}
}

// TestDetectStopsWhenCanceled checks that cancellation is an error rather than a
// note: an answer assembled from half a tree would look like a repository that
// uses fewer package managers than it does, which is the one wrong answer this
// package must never give quietly.
func TestDetectStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Detect(ctx, filepath.Join("testdata", "monorepo"), DetectOptions{}); err == nil {
		t.Fatal("Detect with a canceled context returned no error")
	}
}

// TestDetectAsksTheBinaryLast checks the last resort: a repository that states no
// version anywhere, a package manager on PATH, and permission to run it.
//
// The stub is a program written by this test into a directory of its own that is
// put at the front of PATH, so nothing installed on the machine running the test
// decides the answer and nothing reaches the network.
func TestDetectAsksTheBinaryLast(t *testing.T) {
	stubs := stubManagerOnPath(t, "cargo", "cargo 1.99.0 (0000000 2026-01-01)")

	// Cargo.toml with no Cargo.lock beside it: the manager is certain and its
	// version is stated nowhere in the repository.
	root := writeDetectFixture(t, map[string]string{"Cargo.toml": "[package]\nname = \"rs\"\n"})
	managers, notes, err := Detect(context.Background(), root, DetectOptions{RunBinaries: true})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(notes) != 0 {
		t.Errorf("notes = %v, want none", notes)
	}
	m := findManager(t, managers, Cargo, ".")
	if m.Version != "1.99.0" {
		t.Errorf("Version = %q, want the version the stub printed", m.Version)
	}
	if !strings.Contains(m.VersionSource, "cargo --version") || !strings.Contains(m.VersionSource, "binary") {
		t.Errorf("VersionSource = %q, want it to say the binary answered", m.VersionSource)
	}
	// The stub records every run, which is what the companion test below reads.
	// Checking it here too proves the recording works, so that a passing companion
	// means the binary was not run rather than that the record was never written.
	if !stubRan(stubs) {
		t.Error("the stub answered without recording that it ran")
	}
}

// TestDetectDoesNotAskTheBinaryWhenFilesAnswer is the other half of the same
// rule, and the one that matters: a repository that pins its package manager is
// never a reason to run one. The stub records every run, so this fails if
// detection reaches for the machine when the files have already spoken.
func TestDetectDoesNotAskTheBinaryWhenFilesAnswer(t *testing.T) {
	stubs := stubManagerOnPath(t, "pnpm", "99.99.99")

	root := writeDetectFixture(t, map[string]string{
		"package.json":   `{"packageManager": "pnpm@11.2.0+sha512.abc"}`,
		"pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
	})
	managers, notes, err := Detect(context.Background(), root, DetectOptions{RunBinaries: true})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(notes) != 0 {
		t.Errorf("notes = %v, want none", notes)
	}
	m := findManager(t, managers, PNPM, ".")
	if m.Version != "11.2.0" || m.VersionSource != "the packageManager field of package.json" {
		t.Errorf("Version = %q from %q, want 11.2.0 from the pin", m.Version, m.VersionSource)
	}
	if stubRan(stubs) {
		t.Error("detection ran pnpm although the repository had already said which pnpm it uses")
	}
}

// TestParsePackageManager reads corepack's spelling of a pin, hash and all.
func TestParsePackageManager(t *testing.T) {
	cases := []struct {
		field   string
		id      ManagerID
		version string
		ok      bool
	}{
		{"pnpm@11.2.0", PNPM, "11.2.0", true},
		{"pnpm@11.2.0+sha512.f1e2d3c4b5a6", PNPM, "11.2.0", true},
		{" yarn@4.15.0 ", Yarn, "4.15.0", true},
		{"npm@11.0.0-beta.2", NPM, "11.0.0-beta.2", true},
		{"bun@1.2.4", Bun, "1.2.4", true},
		// A manager without a version is still a manager: the field says which one
		// installs this repository, and the version comes from somewhere else.
		{"pnpm", PNPM, "", true},
		{"deno@2.5.3", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		id, version, ok := parsePackageManager(tc.field)
		if id != tc.id || version != tc.version || ok != tc.ok {
			t.Errorf("parsePackageManager(%q) = %q, %q, %v, want %q, %q, %v", tc.field, id, version, ok, tc.id, tc.version, tc.ok)
		}
	}
}

// writeRepo builds a repository out of a map of slash separated paths, and
// returns the directory it was written into.
func writeDetectFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("make %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

// stubDir writes a program named after a package manager into a directory of its
// own, puts that directory at the front of PATH, and returns it. The stub prints
// what it is told to print and records that it was run, which is how one test
// proves the binary answered and another proves it was never asked.
//
// The test is skipped rather than failed where a stub cannot be made executable,
// because what it is checking is detection's behavior and not the platform's.
func stubManagerOnPath(t *testing.T, name, prints string) string {
	t.Helper()
	dir := t.TempDir()

	file, body := name, ""
	if runtime.GOOS == "windows" {
		file += ".cmd"
		body = "@echo off\r\necho ran > \"%~dp0" + stubRanName + "\"\r\necho " + prints + "\r\n"
	} else {
		body = "#!/bin/sh\necho ran > \"$(dirname \"$0\")/" + stubRanName + "\"\necho '" + prints + "'\n"
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0o755); err != nil {
		t.Skipf("a stub executable cannot be written on %s: %v", runtime.GOOS, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("a stub named %s is not executable on %s: %v", name, runtime.GOOS, err)
	}
	return dir
}

// stubRanName is the file a stub writes beside itself when it runs.
const stubRanName = "ran.txt"

// ran reports whether the stub in a directory was run.
func stubRan(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, stubRanName))
	return err == nil
}

// findManager returns the one manager with this id in this directory, and fails
// the test with the whole list when there is none.
func findManager(t *testing.T, managers []Manager, id ManagerID, root string) Manager {
	t.Helper()
	for _, m := range managers {
		if m.ID == id && m.Root == root {
			return m
		}
	}
	t.Fatalf("no %s at %q among %s", id, root, spellManagers(managers))
	return Manager{}
}

// checkManagers compares a whole answer, manager by manager, in the order Detect
// returned them.
func checkManagers(t *testing.T, got, want []Manager) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("detected %d managers, want %d\n got %s\nwant %s", len(got), len(want), spellManagers(got), spellManagers(want))
	}
	for i := range got {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("manager %d:\n got %s\nwant %s", i, spellManager(&got[i]), spellManager(&want[i]))
		}
	}
}

// spellManager writes a manager on one line, for a failure message.
func spellManager(m *Manager) string {
	return fmt.Sprintf("%s at %q version %q from %q, evidence %v, files %v", m.ID, m.Root, m.Version, m.VersionSource, m.Evidence, m.Files)
}

// spellManagers writes a list of managers, for a failure message.
func spellManagers(managers []Manager) string {
	if len(managers) == 0 {
		return "no managers"
	}
	lines := make([]string, 0, len(managers))
	for _, m := range managers {
		lines = append(lines, spellManager(&m))
	}
	return "\n\t" + strings.Join(lines, "\n\t")
}
