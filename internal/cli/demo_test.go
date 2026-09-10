package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vahapogut/trustdiff/internal/httpcache"
)

// The demo of testdata/demo-repo is the M2 acceptance criterion, and docs/demo-repo.md
// prints its report verbatim, so it is worth as much as a test and it is run as one
// here: nothing else in the tree evaluates those fixtures, and a seeded cache entry
// that stops matching turns the two findings into skipped checks without a single
// signal going red.
//
// The run is the one "make demo" makes: the same files, the same policy, the pinned
// clock and the seeded cache copied into a directory of this test's own, so it needs
// no network and reads no developer's cache.
const (
	demoNow      = "2026-09-09T12:00:00Z"
	demoBase     = "testdata/demo-repo/base/package-lock.json"
	demoHead     = "testdata/demo-repo/head/package-lock.json"
	demoPolicy   = "testdata/demo-repo/.trustdiff.yaml"
	demoCache    = "testdata/demo-repo/cache"
	demoLine     = 32
	demoSkipped  = 11
	demoSubjects = 1
)

// demoRun moves to the repository root, where the paths above are the ones the demo
// and the documentation name, and seeds the cache. It skips rather than fails where
// the demo cannot run at all: diff needs the repository, so a source tree without
// git or without .git is not a failure of the fixtures.
func demoRun(t *testing.T, format string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skipf("no git repository at the module root: %v", err)
	}
	chdir(t, root)

	cache := t.TempDir()
	entries, err := os.ReadDir(demoCache)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(demoCache, e.Name())) // #nosec G304 -- a fixture of this repository.
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cache, e.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(nowEnv, demoNow)
	t.Setenv(httpcache.EnvDir, cache)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no user-level policy

	code, stdout, stderr := run(t, "diff", "--base-file", demoBase, demoHead,
		"--policy", demoPolicy, "--offline", "--format", format)
	if code != ExitOK {
		t.Fatalf("the demo exited %d, want 0 (stderr %q)\n%s", code, stderr, stdout)
	}
	return stdout
}

// The SARIF document is the shape the acceptance criterion is stated in: two
// results, TD001 and TD006, both warnings, both on the line the pull request added.
func TestDemoRepositoryIsTheAcceptanceScenario(t *testing.T) {
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	stdout := demoRun(t, "sarif")
	if err := json.Unmarshal([]byte(stdout), &log); err != nil {
		t.Fatalf("the demo did not write a SARIF document: %v\n%s", err, stdout)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1\n%s", len(log.Runs), stdout)
	}
	results := log.Runs[0].Results
	ids := make([]string, 0, len(results))
	for _, r := range results {
		ids = append(ids, r.RuleID)
	}
	slices.Sort(ids)
	if want := []string{"TD001", "TD006"}; !slices.Equal(ids, want) {
		t.Fatalf("rule ids = %v, want %v: the demo is the acceptance scenario, so a check that "+
			"starts or stops answering here has to be agreed and documented in docs/demo-repo.md\n%s",
			ids, want, stdout)
	}
	for _, r := range results {
		if r.Level != "warning" {
			t.Errorf("%s level = %q, want warning", r.RuleID, r.Level)
		}
		if len(r.Locations) != 1 {
			t.Fatalf("%s has %d locations, want 1", r.RuleID, len(r.Locations))
		}
		loc := r.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI != demoHead {
			t.Errorf("%s uri = %q, want %q", r.RuleID, loc.ArtifactLocation.URI, demoHead)
		}
		if loc.Region.StartLine != demoLine {
			t.Errorf("%s startLine = %d, want %d", r.RuleID, loc.Region.StartLine, demoLine)
		}
	}
}

// The skipped checks are half of what the demo shows, so they are counted too: a
// check that starts answering where it used to say why it could not fails here
// rather than quietly changing the report the documentation prints.
func TestDemoRepositoryCounts(t *testing.T) {
	rep := decodeReport(t, demoRun(t, "json"))
	if rep.Summary.Subjects != demoSubjects {
		t.Errorf("subjects = %d, want %d", rep.Summary.Subjects, demoSubjects)
	}
	want := map[string]int{"block": 0, "warn": 2, "info": 0}
	for level, n := range want {
		if rep.Summary.Findings[level] != n {
			t.Errorf("%s findings = %d, want %d", level, rep.Summary.Findings[level], n)
		}
	}
	if rep.Summary.Skipped != demoSkipped {
		t.Errorf("skipped checks = %d, want %d: docs/demo-repo.md prints this count",
			rep.Summary.Skipped, demoSkipped)
	}
}
