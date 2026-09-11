package doctor

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// A workflow that prints an example of a uses: line is not a workflow that runs
// it. The first version of this scanner read every line beginning with uses:, so a
// run: | block holding documentation was reported as an unpinned action.
func TestActionsScannerReadsStepsAndNotScripts(t *testing.T) {
	workflow := `name: ci
on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: explain
        run: |
          uses: evil/action@v1
          echo "that line is documentation"
      - uses: docker://ghcr.io/example/image@sha256:0000000000000000000000000000000000000000000000000000000000000000
      - uses: ./.github/actions/local
`
	results := scanUses("ci.yml", workflow, &Params{})
	if len(results) != 1 || results[0].Status != StatusSet {
		for _, r := range results {
			t.Logf("%s %s %s", r.Status, r.Current, r.Detail)
		}
		t.Fatalf("results = %d, want one line saying the file is clean", len(results))
	}
	if !strings.Contains(results[0].Detail, "3") {
		t.Errorf("the line does not count the three references it judged: %s", results[0].Detail)
	}
}

// A container image on a tag is not pinned. A tag on an image moves the way a tag
// on an action does, and the first version of this called every docker://
// reference pinned whatever followed the colon.
func TestActionsScannerWantsAnImageDigest(t *testing.T) {
	workflow := `jobs:
  a:
    steps:
      - uses: docker://alpine:latest
`
	results := scanUses("ci.yml", workflow, &Params{})
	if len(results) != 1 || results[0].Status != StatusWrong {
		t.Fatalf("results = %+v, want the tagged image reported", results)
	}
	if !strings.Contains(results[0].Detail, "digest") {
		t.Errorf("the reason does not say what to write instead: %s", results[0].Detail)
	}
}

// A Dependabot block is judged against the wait its own ecosystem is entitled to,
// and a cooldown that names only the semver kinds is judged like one that is
// absent, because GitHub's own three day default covers both.
func TestDependabotScannerJudgesEachBlockByItsEcosystem(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/dependabot.yml", `version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      semver-major-days: 30
`)
	m := &Manager{ID: Dependabot, Root: ".", Files: []string{".github/dependabot.yml"}}
	params := Params{
		Cooldown: 24 * time.Hour,
		Cooldowns: map[model.Ecosystem]time.Duration{
			model.NPM:   24 * time.Hour,
			model.Cargo: 7 * 24 * time.Hour,
		},
	}
	results, err := (dependabotScanner{}).Scan(root, m, &params)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want one per update block", len(results))
	}
	// crates.io waits a week in this policy, and GitHub's default of three days is
	// not that, so the cargo block is short.
	if results[0].Status != StatusMissing || !strings.Contains(results[0].Detail, "1 week") {
		t.Errorf("the cargo block = %s (%s), want missing against the 1 week its ecosystem asks for", results[0].Status, results[0].Detail)
	}
	// npm waits a day here, which the default already covers, and the block that
	// names only semver-major-days must be judged the same way as one with no
	// cooldown at all.
	if results[1].Status != StatusSet {
		t.Errorf("the npm block = %s (%s), want set: the default covers a one day policy", results[1].Status, results[1].Detail)
	}
	if results[1].Line == 0 {
		t.Error("the npm block has no line to point at")
	}
}

// A file the scanner cannot read is reported, not skipped.
func TestDependabotScannerReportsAFileItCannotRead(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/dependabot.yml", "version: 2\nupdates: [\n")
	m := &Manager{ID: Dependabot, Root: ".", Files: []string{".github/dependabot.yml"}}
	results, err := (dependabotScanner{}).Scan(root, m, &Params{Cooldown: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != StatusUnreadable {
		t.Fatalf("results = %+v, want the file reported as unreadable", results)
	}
}

// A composite action is a file of steps that runs inside the job of whoever calls
// it, so an unpinned reference in one has the access of every caller. The scanner
// read the workflows and nothing else until F25 of docs/review-2026-09-10.md.
func TestActionsScannerReadsACompositeAction(t *testing.T) {
	root := t.TempDir()
	write(t, root, "action.yml", `name: setup
runs:
  using: composite
  steps:
    - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
    - uses: evil/action@v1
`)
	m := &Manager{ID: Actions, Root: ".", Files: []string{"action.yml"}}
	results, err := (actionsScanner{}).Scan(root, m, &Params{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != StatusWrong {
		t.Fatalf("results = %+v, want the tagged reference reported", results)
	}
	if results[0].File != "action.yml" || results[0].Line != 6 {
		t.Errorf("the finding points at %s:%d, want action.yml:6", results[0].File, results[0].Line)
	}
}

// This repository publishes a composite action, and its own self-test runs doctor
// --ci over this tree, so the file has to pass the rule it now falls under. The
// workflows are judged here too, which is the same promise the self-test makes.
func TestThisRepositorysOwnActionIsPinned(t *testing.T) {
	root := filepath.Join("..", "..")
	managers, _, err := Detect(context.Background(), root, DetectOptions{BinaryTimeout: noBinaryTimeout})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	m := findManager(t, managers, Actions, ".")
	if !slices.Contains(m.Files, "action.yml") {
		t.Fatalf("Files = %v, want this repository's own action.yml among them", m.Files)
	}
	results, err := (actionsScanner{}).Scan(root, &m, &Params{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Status != StatusSet {
			t.Errorf("%s:%d is %s: %s", r.File, r.Line, r.Status, r.Detail)
		}
	}
}

// A workflow that is a symbolic link is not read, for the reason every other file
// this tool opens is not: a repository decides what its files are.
func TestActionsScannerRefusesASymbolicLink(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret.yml")
	if err := os.WriteFile(secret, []byte("uses: evil/action@v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(link), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("this machine does not allow creating a symbolic link: %v", err)
	}
	m := &Manager{ID: Actions, Root: ".", Files: []string{".github/workflows/ci.yml"}}
	results, err := (actionsScanner{}).Scan(root, m, &Params{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != StatusUnreadable {
		t.Fatalf("results = %+v, want the link reported as unreadable", results)
	}
}
