package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// repoFile reads a file from the root of the repository, the way
// internal/report/sarif_test.go reads docs/checks.md for the same kind of
// assertion: a file that has to keep up with the code is worth failing a test over
// when it does not.
func repoFile(t *testing.T, elem ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, elem...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(elem...), err)
	}
	return data
}

// actionSelfTest is the shape of .github/workflows/action-selftest.yml this test
// reads. Only the keys it asserts on are decoded, so an unrelated addition to the
// workflow does not have to be mirrored here.
type actionSelfTest struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Strategy    struct {
			Matrix struct {
				OS      []string `yaml:"os"`
				Verify  []string `yaml:"verify"`
				Include []struct {
					Verify  string `yaml:"verify"`
					Version string `yaml:"version"`
				} `yaml:"include"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
		Steps []struct {
			Name string            `yaml:"name"`
			Uses string            `yaml:"uses"`
			With map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// TestActionSelfTestRunsTheLocalActionEverywhere is finding F21 of
// docs/review-2026-09-10.md. action.yml is the component that runs with other
// people's tokens, and no workflow had ever executed it on any runner: not the
// Windows zip branch, where the bash on that image is Git for Windows and its GNU
// tar cannot read a zip, and not the cosign route, whose certificate identity is
// built from a string. This reads the workflow rather than trusting that it is
// still there, because a matrix is one line away from covering one runner.
func TestActionSelfTestRunsTheLocalActionEverywhere(t *testing.T) {
	var wf actionSelfTest
	if err := yaml.Unmarshal(repoFile(t, ".github", "workflows", "action-selftest.yml"), &wf); err != nil {
		t.Fatalf("parse the workflow: %v", err)
	}
	job, ok := wf.Jobs["action"]
	if !ok {
		t.Fatalf("no job named action; the workflow has %v", keysOf(wf.Jobs))
	}

	for _, runner := range []string{"ubuntu-latest", "macos-latest", "windows-latest"} {
		if !contains(job.Strategy.Matrix.OS, runner) {
			t.Errorf("the matrix does not run on %s: %v", runner, job.Strategy.Matrix.OS)
		}
	}
	// Both routes, and each with the version that takes it. The empty version is
	// the action's own default, which is the only one its sha256 table covers.
	for _, route := range []string{"pinned", "cosign"} {
		if !contains(job.Strategy.Matrix.Verify, route) {
			t.Errorf("the matrix does not exercise the %s route: %v", route, job.Strategy.Matrix.Verify)
		}
	}
	versions := map[string]string{}
	for _, inc := range job.Strategy.Matrix.Include {
		versions[inc.Verify] = inc.Version
	}
	if versions["pinned"] != "" {
		t.Errorf("the pinned leg passes version %q, and the table covers the default alone", versions["pinned"])
	}
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(versions["cosign"]) {
		t.Errorf("the cosign leg passes version %q, which is not a release tag, so the cosign route may not run", versions["cosign"])
	}

	var ranAction bool
	for _, step := range job.Steps {
		if step.Uses != "./" {
			continue
		}
		ranAction = true
		// The upload is off, so the job needs no token that can write code
		// scanning results and a synthetic fixture stays out of the alerts.
		if step.With["upload-sarif"] != "false" {
			t.Errorf("the action step uploads SARIF (upload-sarif=%q), and this job has no write token", step.With["upload-sarif"])
		}
	}
	if !ranAction {
		t.Error(`no step runs "uses: ./", so the workflow does not test the local action at all`)
	}

	// Parsed, not grepped: the file explains in a comment why it needs no write
	// token, and a test that searched the bytes would fail on its own explanation.
	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		t.Errorf("permissions = %v, want contents: read alone", wf.Permissions)
	}
	if _, ok := job.Permissions["security-events"]; ok {
		t.Errorf("the job grants security-events, and nothing in it uploads: %v", job.Permissions)
	}
}

// The pinned route quietly becomes the cosign route when the version asked for is
// not the one the table covers, and it says so only in a notice. That makes the two
// values in action.yml a pair that has to move together at every release, which is
// exactly the kind of pair that does not.
func TestActionPinAndDefaultVersionAgree(t *testing.T) {
	action := string(repoFile(t, "action.yml"))

	defaults := regexp.MustCompile(`(?m)^    default: (v[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.-]*)$`).FindAllStringSubmatch(action, -1)
	if len(defaults) != 1 {
		t.Fatalf("found %d version defaults in action.yml, want the one on the version input", len(defaults))
	}
	pin := regexp.MustCompile(`(?m)^        pinned_version=(\S+)$`).FindAllStringSubmatch(action, -1)
	if len(pin) != 1 {
		t.Fatalf("found %d pinned_version assignments in action.yml, want one", len(pin))
	}
	if defaults[0][1] != pin[0][1] {
		t.Errorf("the version input defaults to %s and the sha256 table is for %s, so the default silently takes the cosign route",
			defaults[0][1], pin[0][1])
	}
	// A table left as "pending" is a fallback, not a resting place, and it is the
	// other way the pinned route stops being the pinned route.
	if strings.Contains(action, "sha=pending") {
		t.Error("the sha256 table still holds a pending entry, so the default version is verified through cosign at run time")
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, got := range list {
		if got == want {
			return true
		}
	}
	return false
}

// The README's workflow example is the line a reader copies into their own
// repository. A tagged "uses:" there is what DR110 reports as wrong, at warn,
// which doctor --ci fails on by default, so the example would have handed every
// reader a workflow that fails their own hardening check. Finding F22 of
// docs/review-2026-09-10.md.
//
// The sha has to be the "chore(action): pin <tag> and checksums" commit of the
// release: at the tag itself the action still defaults to the release before it,
// because the checksum table can only be written once the archives exist. This
// cannot check that the sha is the newest such commit, since at the moment it is
// written the newest one is the commit being written. It checks the shape, which
// is the half that rots silently.
func TestREADMEPinsTheActionAtACommit(t *testing.T) {
	readme := string(repoFile(t, "README.md"))
	uses := regexp.MustCompile(`(?m)^- uses: vahapogut/trustdiff@(\S+)(.*)$`).FindAllStringSubmatch(readme, -1)
	if len(uses) == 0 {
		t.Fatal("the README shows no vahapogut/trustdiff action example; the pattern or the document changed")
	}
	for _, match := range uses {
		ref, rest := match[1], match[2]
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(ref) {
			t.Errorf("the example pins %s, which is not a commit sha, and DR110 reports a tag at warn", ref)
			continue
		}
		// The sha alone says nothing about which release it is, which is why every
		// pinned uses: in this repository's own workflows carries the tag beside it.
		if !strings.Contains(rest, "# v") {
			t.Errorf("the example pins %s with no trailing # vX.Y.Z comment, so nothing says which release it is", ref)
		}
	}
}

// The binary carries other people's code and data, and MIT, BSD and Apache all
// ask that their notices travel with a binary distribution. THIRD_PARTY_NOTICES
// is what travels, and it is only worth having while it is complete: a tenth
// module linked in without an entry is the failure mode, and it is silent.
// Finding F23 of docs/review-2026-09-10.md.
//
// The list comes from "go list -deps" over the command, so it is what is in the
// artifact rather than what go.mod requires: the documentation tooling that
// reaches go.sum as a test dependency is not linked and is not listed.
func TestThirdPartyNoticesNameEveryLinkedModule(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps",
		"-f", "{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}", "../../cmd/trustdiff").Output()
	if err != nil {
		t.Skipf("go list did not run: %v", err)
	}
	notices := string(repoFile(t, "THIRD_PARTY_NOTICES"))

	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		mod, version, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || mod == "github.com/vahapogut/trustdiff" || seen[mod] {
			continue
		}
		seen[mod] = true
		if !strings.Contains(notices, mod) {
			t.Errorf("%s is linked into the binary and THIRD_PARTY_NOTICES does not name it", mod)
			continue
		}
		// The version matters: a license can change between releases, and an
		// entry that names an older one is a notice for code that is not there.
		if !strings.Contains(notices, mod+"** "+version) {
			t.Errorf("THIRD_PARTY_NOTICES names %s at another version than the linked %s", mod, version)
		}
	}
	if len(seen) == 0 {
		t.Fatal("go list reported no modules; the command or the flags changed")
	}
	// The vendored diff and the three embedded lists are the other half.
	for _, must := range []string{"internal/textdiff/diff.go", "npm.txt", "pypi.txt", "cargo.txt", "CC BY 4.0"} {
		if !strings.Contains(notices, must) {
			t.Errorf("THIRD_PARTY_NOTICES does not mention %s", must)
		}
	}
}

// The notices only travel if the archive carries them.
func TestReleaseArchivesCarryTheNotices(t *testing.T) {
	config := string(repoFile(t, ".goreleaser.yaml"))
	for _, must := range []string{"src: LICENSE", "src: README.md", "src: THIRD_PARTY_NOTICES"} {
		if !strings.Contains(config, must) {
			t.Errorf(".goreleaser.yaml does not pack %s into the archives", strings.TrimPrefix(must, "src: "))
		}
	}
}
