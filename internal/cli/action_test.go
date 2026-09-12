package cli

import (
	"crypto/sha256"
	"fmt"
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

// GNU coreutils escapes a file name that holds a backslash: it prefixes the whole
// line with one and escapes the character inside the name. On a Windows runner the
// action's download directory is "D:\\a\\_temp/trustdiff", so every archive it hashes
// has backslashes in its path and the digest came back as "\\<hash>", which equals no
// expected value ever. Both Windows legs of the action self-test failed on it and
// both other runner families passed, which is how it survived every release since
// v0.4.0. Reading the file on stdin is the fix: there is no name in that output to
// escape. This runs the function as action.yml holds it, against a path with a
// backslash in it, which is a file name on Linux and macOS and a directory
// separator on Windows. Finding F21 of docs/review-2026-09-10.md.
func TestActionDigestsAPathThatHoldsABackslash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not on PATH, and the function under test is a shell function")
	}
	manifest := string(repoFile(t, "action.yml"))
	const open = "digest() {"
	start := strings.Index(manifest, open)
	if start < 0 {
		t.Fatal("action.yml has no digest function, so this test is checking nothing")
	}
	const close = "\n        }\n"
	end := strings.Index(manifest[start:], close)
	if end < 0 {
		t.Fatal("the digest function has no closing brace at the expected indentation")
	}
	function := manifest[start : start+end+len(close)]

	dir := t.TempDir()
	name := "archive.zip"
	if os.PathSeparator == '/' {
		// A backslash is an ordinary character in a name here, which is what makes
		// the escaping reproducible off Windows.
		name = "arch\\ive.zip"
	}
	file := filepath.Join(dir, name)
	body := []byte("not really a zip, but it hashes the same way\n")
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(body))

	script := function + "\ndigest \"$1\"\n"
	out, err := exec.CommandContext(t.Context(), bash, "-c", script, "bash", file).Output()
	if err != nil {
		t.Fatalf("running the digest function: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != want {
		t.Errorf("digest of %s = %q, want %q: a hash the shell escaped matches nothing", file, got, want)
	}
}

// The job above loads the action out of the workspace, with "uses: ./". That is the
// copy a pull request changes, and it is not the copy a caller resolves: writing
// "uses: vahapogut/trustdiff@<ref>" makes a runner fetch that ref and load the
// manifest inside it, which can be broken there while the workspace is green. v0.5.0
// is what that costs. Its manifest could not be loaded on any runner, six workspace
// legs passed on the same commit, and the defect reached a tag. One leg therefore
// runs the reference a caller writes. Its ref moves with each release, which
// docs/releasing.md section 5 says when, and it has to name the same release the
// action itself defaults to, so the two cannot drift apart quietly.
func TestActionSelfTestAlsoRunsThePublishedReference(t *testing.T) {
	var wf actionSelfTest
	if err := yaml.Unmarshal(repoFile(t, ".github", "workflows", "action-selftest.yml"), &wf); err != nil {
		t.Fatalf("parse the workflow: %v", err)
	}
	job, ok := wf.Jobs["published"]
	if !ok {
		t.Fatalf("no job named published, so nothing loads the manifest a caller resolves; the workflow has %v", keysOf(wf.Jobs))
	}

	var ref string
	for _, step := range job.Steps {
		if !strings.HasPrefix(step.Uses, "vahapogut/trustdiff@") {
			continue
		}
		ref = strings.TrimPrefix(step.Uses, "vahapogut/trustdiff@")
		if step.With["upload-sarif"] != "false" {
			t.Errorf("the action step uploads SARIF (upload-sarif=%q), and this job has no write token", step.With["upload-sarif"])
		}
	}
	if ref == "" {
		t.Fatal(`no step runs "uses: vahapogut/trustdiff@<ref>", so the published manifest is still never loaded`)
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(ref) {
		t.Errorf("the published leg runs %q; DR110 reports a tag at warn, and this repository is judged by its own rules", ref)
	}

	// Which release that commit is lives in the comment beside it, and a YAML
	// parser drops comments, so the line itself is read.
	workflow := string(repoFile(t, ".github", "workflows", "action-selftest.yml"))
	line := regexp.MustCompile(`(?m)^ *uses: vahapogut/trustdiff@[0-9a-f]{40} # (v[0-9]+\.[0-9]+\.[0-9]+)$`).FindStringSubmatch(workflow)
	if line == nil {
		t.Fatal("the published leg's uses: line does not name a commit with the release in a trailing comment")
	}

	action := string(repoFile(t, "action.yml"))
	def := regexp.MustCompile(`(?m)^    default: (v[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.-]*)$`).FindStringSubmatch(action)
	if def == nil {
		t.Fatal("action.yml has no version default to compare the leg against")
	}
	if line[1] != def[1] {
		t.Errorf("the published leg runs %s and action.yml defaults to %s; both name the current release and move together at every release", line[1], def[1])
	}
}

// The pinned route quietly becomes the cosign route when the version asked for is
// The manifest is a template the runner parses before it runs anything, and it
// evaluates every expression it finds in the inputs and the outputs it converts.
// An expression naming the github context there is not an example somebody reads:
// it is an expression where that context does not exist, and the action fails to
// load with "Unrecognized named-value: 'github'" on every runner and for every
// caller. Every release from v0.4.0 carried one in the base input's description,
// and the self-test of finding F21 caught it the first time it ran. The same
// applies to a run: script, where this file's own rules say no value is ever
// interpolated: a comment inside one is interpolated like everything else.
func TestActionManifestKeepsExpressionsOutOfTextTheRunnerEvaluates(t *testing.T) {
	var manifest struct {
		Inputs map[string]struct {
			Description string `yaml:"description"`
		} `yaml:"inputs"`
		Outputs map[string]struct {
			Description string `yaml:"description"`
		} `yaml:"outputs"`
		Runs struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(repoFile(t, "action.yml"), &manifest); err != nil {
		t.Fatalf("action.yml: %v", err)
	}
	if len(manifest.Inputs) == 0 || len(manifest.Outputs) == 0 || len(manifest.Runs.Steps) == 0 {
		t.Fatal("action.yml decoded to nothing, so this test would pass on an empty file")
	}
	for name, in := range manifest.Inputs {
		if strings.Contains(in.Description, "${{") {
			t.Errorf("the %s input's description holds an expression, which the runner evaluates while loading the manifest: %s", name, in.Description)
		}
	}
	for name, out := range manifest.Outputs {
		if strings.Contains(out.Description, "${{") {
			t.Errorf("the %s output's description holds an expression: %s", name, out.Description)
		}
	}
	for _, step := range manifest.Runs.Steps {
		if strings.Contains(step.Run, "${{") {
			t.Errorf("the %q step interpolates an expression into its script; every value reaches the shell through env:", step.Name)
		}
	}
}

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

// SECURITY.md says a tag can be rebuilt and compared byte for byte. That is only
// true while the release job builds with one fixed compiler: "1.26.x" with
// check-latest meant the same tag rebuilt next month was built by a different one.
// The pin and go.mod's toolchain directive are now a pair, and a pair in two files
// is the kind that drifts. Finding F24 of docs/review-2026-09-10.md.
//
// Only the release job. Everything in ci.yml floats forward on purpose, so
// govulncheck sees the newest standard library rather than the one this freezes.
// The release job signs with this repository's own OIDC identity, so whatever can
// push a v* tag can produce a release that verifies. Two settings stand between a
// tag and a signature: a ruleset that restricts who creates the tag, and an
// environment with a required reviewer. The environment applies only while the job
// declares it, and one deleted line puts the pipeline back to where a tag push was
// the whole of the authorization. docs/releasing.md section 7 is the reasoning.
func TestReleaseJobWaitsForTheReleaseEnvironment(t *testing.T) {
	var release struct {
		Jobs map[string]struct {
			Environment string `yaml:"environment"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(repoFile(t, ".github", "workflows", "release.yml"), &release); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	job, ok := release.Jobs["release"]
	if !ok {
		t.Fatalf("no job named release; release.yml has %v", keysOf(release.Jobs))
	}
	if job.Environment != "release" {
		t.Errorf("the release job declares environment %q, and the approval applies only while it names release", job.Environment)
	}
}

func TestReleasePinsTheToolchainGoModNames(t *testing.T) {
	gomod := string(repoFile(t, "go.mod"))
	toolchain := regexp.MustCompile(`(?m)^toolchain go(\S+)$`).FindStringSubmatch(gomod)
	if toolchain == nil {
		t.Fatal("go.mod states no toolchain directive, and the release pin is written from it")
	}

	// Parsed, not grepped. The file explains in a comment why it does not ask for
	// check-latest, and a test that searched the bytes would fail on that sentence.
	var release struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string         `yaml:"uses"`
				With map[string]any `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(repoFile(t, ".github", "workflows", "release.yml"), &release); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}
	var setups int
	for _, job := range release.Jobs {
		for _, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
				continue
			}
			setups++
			if got, _ := step.With["go-version"].(string); got != toolchain[1] {
				t.Errorf("release.yml builds with Go %q and go.mod names toolchain go%s, so a rebuilt tag is a different binary",
					got, toolchain[1])
			}
			if _, ok := step.With["check-latest"]; ok {
				t.Error("release.yml asks setup-go for check-latest, which moves the compiler under a fixed tag")
			}
			if _, ok := step.With["go-version-file"]; ok {
				t.Error("release.yml reads go-version-file, which under GOTOOLCHAIN=local installs the bare go directive version rather than the toolchain one")
			}
		}
	}
	if setups != 1 {
		t.Errorf("release.yml sets up Go %d times, want once", setups)
	}
}
