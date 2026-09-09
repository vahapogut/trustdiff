package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/report"
)

// fakeLoader serves one npm package, lib, with two releases: 1.0.0 by alice a
// year ago and 2.0.0 by bob one day before the injected clock. Every other name is
// unknown, and the name "down" makes the registry unavailable. With slow set,
// 2.0.0 declares a dependency whose version list never arrives before the
// caller's context ends, the way a hung registry looks to TD007.
type fakeLoader struct {
	now time.Time
	// slow makes the introduced dependency's lookups hang past the deadline.
	slow bool
	// malicious makes the advisory source answer a MAL- advisory for maliciousRef.
	malicious bool
}

var errRegistryDown = errors.New("connection refused")

// slowDependency is the dependency whose lookups hang when fakeLoader.slow is set.
const slowDependency = "trustdiff-fixture-slow"

func (f *fakeLoader) list() *registry.VersionList {
	ref := func(v string) model.PackageRef {
		return model.PackageRef{Ecosystem: model.NPM, Name: "trustdiff-fixture-lib", Version: v}
	}
	list := &registry.VersionList{
		Ecosystem: model.NPM,
		Name:      "trustdiff-fixture-lib",
		Latest:    "2.0.0",
		Versions: []model.VersionInfo{
			{Ref: ref("1.0.0"), PublishedAt: f.now.AddDate(-1, 0, 0), Publisher: &model.Publisher{Name: "alice"}, WeeklyDownloads: -1},
			{Ref: ref("2.0.0"), PublishedAt: f.now.Add(-24 * time.Hour), Publisher: &model.Publisher{Name: "bob"}, WeeklyDownloads: -1},
		},
	}
	if f.slow {
		list.Versions[1].Dependencies = map[string]string{slowDependency: "^1.0.0"}
	}
	return list
}

func (f *fakeLoader) Prefetch(context.Context, []model.PackageRef) {}

func (f *fakeLoader) Versions(ctx context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error) {
	switch {
	case name == "down":
		return nil, errRegistryDown
	case name == slowDependency && f.slow:
		// Return a while after the deadline so the runner's timeout is what the
		// report shows, not a race with this answer.
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond)
		return nil, ctx.Err()
	case eco == model.NPM && name == "trustdiff-fixture-lib":
		return f.list(), nil
	}
	return nil, registry.ErrNotFound
}

func (f *fakeLoader) VersionInfo(_ context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	if ref.Name == "down" {
		return nil, errRegistryDown
	}
	if v := registry.Find(f.list(), ref.Version); v != nil && ref.Ecosystem == model.NPM && ref.Name == "trustdiff-fixture-lib" {
		return v, nil
	}
	return nil, registry.ErrNotFound
}

func (f *fakeLoader) Owners(context.Context, model.Ecosystem, string) ([]model.Publisher, error) {
	return []model.Publisher{{Name: "alice"}, {Name: "bob"}}, nil
}

func (f *fakeLoader) Downloads(context.Context, model.Ecosystem, string) (int64, error) {
	return 100000, nil
}

// maliciousRef is the ref the fake loader answers a malicious-package advisory
// for, the way OSV answers for a release a registry has taken down.
var maliciousRef = model.MustParseRef("npm:trustdiff-fixture-lib@2.0.0")

func (f *fakeLoader) Advisories(_ context.Context, ref model.PackageRef) ([]advisory.Advisory, error) {
	if f.malicious && ref == maliciousRef {
		return []advisory.Advisory{{
			ID:        "MAL-2026-9001",
			Summary:   "Malicious code in trustdiff-fixture-lib (npm)",
			Severity:  advisory.SeverityCritical,
			Malicious: true,
			URL:       "https://osv.dev/vulnerability/MAL-2026-9001",
		}}, nil
	}
	return nil, nil
}

func (f *fakeLoader) DepsDev(context.Context, model.PackageRef) (*depsdev.VersionFacts, error) {
	return &depsdev.VersionFacts{Found: true}, nil
}

func (f *fakeLoader) SimilarNames(context.Context, model.Ecosystem, string) ([]depsdev.Similar, error) {
	return nil, nil
}

// useFakeLoader swaps the fake loader in, pins the clock and isolates the policy
// lookup: an empty working directory and an empty user config directory, so a
// developer's own ~/.config/trustdiff/policy.yaml cannot change the assertions.
func useFakeLoader(t *testing.T) time.Time {
	t.Helper()
	now := fixtureClock(t)
	old := loaderFactory
	loaderFactory = func(*App) (checks.Loader, error) { return &fakeLoader{now: now}, nil }
	t.Cleanup(func() { loaderFactory = old })
	return now
}

// fixtureClock pins TRUSTDIFF_NOW and isolates the policy lookup without touching
// the loader, for tests that run the real one.
func fixtureClock(t *testing.T) time.Time {
	t.Helper()
	now := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	t.Setenv(nowEnv, now.Format(time.RFC3339))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no user-level policy
	chdir(t, t.TempDir())                    // no policy file: built-in defaults
	return now
}

// writePolicy puts a policy file in the working directory.
func writePolicy(t *testing.T, body string) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".trustdiff.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// removePolicy removes the policy file writePolicy wrote.
func removePolicy(t *testing.T) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, ".trustdiff.yaml")); err != nil {
		t.Fatal(err)
	}
}

// decodeReport parses a JSON report after validating it against the schema.
func decodeReport(t *testing.T, stdout string) report.Report {
	t.Helper()
	schema, err := jsonschema.Compile(report.SchemaJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate([]byte(stdout)); err != nil {
		t.Fatalf("json report does not match the schema: %v\n%s", err, stdout)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestCheckReportsFindingsAndExitCodes(t *testing.T) {
	useFakeLoader(t)

	// 2.0.0 is one day old (young-version, warn by default) and published by a
	// new account (publisher-changed, block by default).
	code, stdout, stderr := run(t, "check", "npm:trustdiff-fixture-lib@2.0.0")
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr %q)", code, stderr)
	}
	for _, want := range []string{"npm:trustdiff-fixture-lib@2.0.0", "BLOCK", "TD002", "publisher-changed", "TD001", "young-version", "Exit code 1"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}

	// The first release has no history: nothing to compare against, exit 0.
	code, stdout, _ = run(t, "check", "npm:trustdiff-fixture-lib@1.0.0")
	if code != ExitOK || !strings.Contains(stdout, "Exit code 0") {
		t.Fatalf("first release exit = %d\n%s", code, stdout)
	}

	// --fail-on never keeps the exit code at 0 even with a block finding.
	code, _, _ = run(t, "--fail-on", "never", "check", "npm:trustdiff-fixture-lib@2.0.0")
	if code != ExitOK {
		t.Fatalf("--fail-on never exit = %d, want 0", code)
	}

	// --cooldown 1h makes a one day old version old enough: TD001 goes away.
	code, stdout, _ = run(t, "--cooldown", "1h", "--fail-on", "warn", "check", "npm:trustdiff-fixture-lib@2.0.0")
	if code != ExitFindings || strings.Contains(stdout, "TD001") {
		t.Fatalf("--cooldown 1h exit = %d, output should not carry TD001:\n%s", code, stdout)
	}
}

// The acceptance criterion of the release: a malicious-package advisory blocks,
// whatever else the card says, and the exit code tells a script to stop.
func TestCheckMaliciousAdvisoryBlocks(t *testing.T) {
	now := fixtureClock(t)
	old := loaderFactory
	loaderFactory = func(*App) (checks.Loader, error) { return &fakeLoader{now: now, malicious: true}, nil }
	t.Cleanup(func() { loaderFactory = old })

	code, stdout, stderr := run(t, "check", maliciousRef.String())
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 for a malicious-package advisory (stderr %q)\n%s", code, stderr, stdout)
	}
	for _, want := range []string{"BLOCK", "TD009", "malicious-advisory", "MAL-2026-9001"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}

	// Turning the check off is the user's decision, and then it no longer blocks.
	writePolicy(t, "version: 1\nchecks:\n  malicious-advisory: off\n  publisher-changed: warn\n")
	code, stdout, _ = run(t, "check", maliciousRef.String())
	if code != ExitOK || strings.Contains(stdout, "TD009") {
		t.Fatalf("with malicious-advisory off: exit = %d, stdout:\n%s", code, stdout)
	}
}

func TestCheckResolvesLatestStable(t *testing.T) {
	useFakeLoader(t)
	code, stdout, _ := run(t, "--fail-on", "never", "check", "npm:trustdiff-fixture-lib")
	if code != ExitOK || !strings.Contains(stdout, "npm:trustdiff-fixture-lib@2.0.0") {
		t.Fatalf("bare ref exit = %d, stdout:\n%s", code, stdout)
	}
}

func TestCheckJSONMatchesSchema(t *testing.T) {
	useFakeLoader(t)
	code, stdout, stderr := run(t, "--format", "json", "check", "npm:trustdiff-fixture-lib@2.0.0", "npm:trustdiff-fixture-lib@1.0.0")
	if code != ExitFindings {
		t.Fatalf("exit = %d, stderr %q", code, stderr)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 2 || rep.Summary.ExitCode != 1 || rep.Policy.Cooldown != "3d" || rep.Policy.FailOn != "block" {
		t.Fatalf("report = %+v", rep.Summary)
	}
}

func TestCheckUsageErrors(t *testing.T) {
	useFakeLoader(t)
	// Count the loader constructions: a rejected command line must fail before
	// the run, not after a full pass over the registries.
	var loaders int
	inner := loaderFactory
	loaderFactory = func(a *App) (checks.Loader, error) { loaders++; return inner(a) }
	t.Cleanup(func() { loaderFactory = inner })
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "bad ref", args: []string{"check", "express"}, want: "invalid ref"},
		{name: "manifest path is planned", args: []string{"check", "package.json"}, want: "later release"},
		{name: "sarif is planned", args: []string{"--format", "sarif", "check", "npm:trustdiff-fixture-lib@2.0.0"}, want: "later release"},
		{name: "markdown is planned", args: []string{"--format", "markdown", "check", "npm:trustdiff-fixture-lib@2.0.0"}, want: "later release"},
		{name: "unknown package", args: []string{"check", "npm:trustdiff-unknown-package-x9q@1.0.0"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loaders = 0
			code, stdout, stderr := run(t, tt.args...)
			if tt.want == "" {
				// An unknown package is not a usage error and not an outage: every
				// check is skipped with a "not found" reason, the verdict is skipped
				// rather than ok, and the exit code stays 0.
				if code != ExitOK || !strings.Contains(stdout, "not found in the registry") || strings.Contains(stdout, "unavailable") {
					t.Fatalf("exit = %d, stdout:\n%s", code, stdout)
				}
				if !strings.Contains(stdout, "SKIPPED") || strings.Contains(stdout, "  OK") {
					t.Fatalf("verdict for a version the registry does not have should be skipped, not ok:\n%s", stdout)
				}
				return
			}
			if code != ExitUsage || !strings.Contains(stderr, tt.want) {
				t.Fatalf("exit = %d, stderr = %q, want usage error containing %q", code, stderr, tt.want)
			}
			if loaders != 0 {
				t.Errorf("the loader was built %d times for a rejected command line, want 0", loaders)
			}
		})
	}
}

// A package the registry has never heard of leaves nothing to evaluate.
func TestCheckUnknownPackageIsSkipped(t *testing.T) {
	useFakeLoader(t)
	tests := []struct {
		name string
		ref  string
	}{
		{name: "unknown package", ref: "npm:trustdiff-unknown-package-x9q@1.0.0"},
		{name: "bare ref of an unknown package", ref: "npm:trustdiff-unknown-bare"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, _ := run(t, "--format", "json", "check", tt.ref)
			if code != ExitOK {
				t.Fatalf("exit = %d, want 0:\n%s", code, stdout)
			}
			rep := decodeReport(t, stdout)
			s := rep.Subjects[0]
			if s.Verdict != report.VerdictSkipped || len(s.Evaluated) != 0 || len(s.Findings) != 0 {
				t.Errorf("verdict = %s, evaluated = %v, findings = %d; want skipped with nothing evaluated", s.Verdict, s.Evaluated, len(s.Findings))
			}
			if len(s.Skipped) == 0 {
				t.Fatal("no skipped checks recorded")
			}
			for _, sk := range s.Skipped {
				if !strings.Contains(sk.Reason, "not found in the registry") || strings.Contains(sk.Reason, "unavailable") {
					t.Errorf("%s skipped with %q, want the registry's not-found answer", sk.Check, sk.Reason)
				}
			}
		})
	}
}

// A version the registry no longer lists is how a takedown looks, so the checks
// that do not read the registry must still run: that is the flatmap-stream case,
// where npm removed the release and OSV kept the malicious-package advisory.
func TestCheckUnknownVersionStillRunsAdvisoryChecks(t *testing.T) {
	useFakeLoader(t)
	code, stdout, _ := run(t, "--format", "json", "check", "npm:trustdiff-fixture-lib@9.9.9")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0:\n%s", code, stdout)
	}
	rep := decodeReport(t, stdout)
	s := rep.Subjects[0]
	for _, id := range []string{"TD009", "TD010"} {
		if !slices.Contains(s.Evaluated, id) {
			t.Errorf("%s did not run for a version the registry does not list; evaluated = %v", id, s.Evaluated)
		}
	}
	registryChecks := map[string]bool{"TD001": true, "TD002": true, "TD005": true, "TD006": true, "TD007": true}
	for _, sk := range s.Skipped {
		if registryChecks[sk.Check] && !strings.Contains(sk.Reason, "not found in the registry") {
			t.Errorf("%s skipped with %q, want the registry's not-found answer", sk.Check, sk.Reason)
		}
	}
	for id := range registryChecks {
		if slices.Contains(s.Evaluated, id) {
			t.Errorf("%s ran although the registry does not list the version", id)
		}
	}
}

func TestCheckBadClockOverride(t *testing.T) {
	useFakeLoader(t)
	t.Setenv(nowEnv, "yesterday")
	code, _, stderr := run(t, "check", "npm:trustdiff-fixture-lib@2.0.0")
	if code != ExitUsage || !strings.Contains(stderr, "TRUSTDIFF_NOW") {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
}

func TestCheckExit3WhenPolicySaysFail(t *testing.T) {
	useFakeLoader(t)
	writePolicy(t, "version: 1\non_data_unavailable: fail\n")
	code, stdout, _ := run(t, "--format", "json", "check", "npm:down@1.0.0")
	if code != ExitUnavailable {
		t.Fatalf("exit = %d, want 3; stdout:\n%s", code, stdout)
	}
	rep := decodeReport(t, stdout)
	if rep.Summary.ExitCode != ExitUnavailable || !strings.Contains(rep.Summary.ExitMeaning, "unavailable") {
		t.Fatalf("summary = %+v, want exit code 3", rep.Summary)
	}
	if len(rep.Subjects[0].Skipped) == 0 {
		t.Fatal("no skipped checks for a registry outage")
	}
	for _, sk := range rep.Subjects[0].Skipped {
		if !strings.Contains(sk.Reason, "registry unavailable: connection refused") {
			t.Errorf("%s skipped with %q, want the registry outage", sk.Check, sk.Reason)
		}
	}

	// Findings win over the unavailable source: exit code 1 tells a script there
	// is something to act on now, and a retry-on-3 loop must not spin past a
	// block. The document says the same.
	code, stdout, _ = run(t, "--format", "json", "check", "npm:trustdiff-fixture-lib@2.0.0", "npm:down@1.0.0")
	rep = decodeReport(t, stdout)
	if code != ExitFindings || rep.Summary.ExitCode != ExitFindings || rep.Summary.Findings["block"] != 1 {
		t.Fatalf("exit = %d, summary = %+v; want 1 with one block finding", code, rep.Summary)
	}
	if rep.Summary.ExitMeaning != report.ExitMeaning(ExitFindings) {
		t.Errorf("exit_meaning = %q, want the meaning of exit code 1", rep.Summary.ExitMeaning)
	}

	// A version the registry does not have is a definite answer, not an outage.
	if code, stdout, _ = run(t, "check", "npm:trustdiff-unknown-package-x9q@1.0.0"); code != ExitOK {
		t.Fatalf("exit for an unknown package under fail = %d, want 0:\n%s", code, stdout)
	}

	// The default policy (warn) keeps the exit code at 0 for the outage.
	removePolicy(t)
	if code, _, _ = run(t, "check", "npm:down@1.0.0"); code != ExitOK {
		t.Fatalf("exit with the default policy = %d, want 0", code)
	}
}

// A check that hung on a registry request is skipped as timed out, and that
// counts as unavailable data whatever the reason says.
func TestCheckExit3OnTimedOutCheck(t *testing.T) {
	now := useFakeLoader(t)
	loaderFactory = func(*App) (checks.Loader, error) { return &fakeLoader{now: now, slow: true}, nil }
	oldTimeout := checkTimeout
	checkTimeout = 50 * time.Millisecond
	t.Cleanup(func() { checkTimeout = oldTimeout })
	writePolicy(t, "version: 1\non_data_unavailable: fail\n")

	// --fail-on never keeps the block finding of 2.0.0 out of the exit code, so
	// the timed-out check alone decides it.
	code, stdout, _ := run(t, "--format", "json", "--fail-on", "never", "check", "npm:trustdiff-fixture-lib@2.0.0")
	rep := decodeReport(t, stdout)
	var reason string
	for _, sk := range rep.Subjects[0].Skipped {
		if sk.Check == "TD007" {
			reason = sk.Reason
		}
	}
	if reason != "timed out after 50ms" {
		t.Fatalf("TD007 skipped with %q, want the timeout (skipped: %v)", reason, rep.Subjects[0].Skipped)
	}
	if code != ExitUnavailable || rep.Summary.ExitCode != ExitUnavailable {
		t.Fatalf("exit = %d, summary exit = %d; want 3 for a timed-out check under on_data_unavailable: fail", code, rep.Summary.ExitCode)
	}

	removePolicy(t)
	if code, _, _ = run(t, "--fail-on", "never", "check", "npm:trustdiff-fixture-lib@2.0.0"); code != ExitOK {
		t.Fatalf("exit with the default policy = %d, want 0", code)
	}
}

// --offline with a cold cache is the M1 acceptance: nothing is fetched, every
// check that needs data is skipped saying so, and the exit code is the policy's.
func TestCheckOfflineColdCache(t *testing.T) {
	fixtureClock(t)
	t.Setenv(httpcache.EnvDir, t.TempDir())
	code, stdout, stderr := run(t, "--offline", "--format", "json", "check", "npm:express@4.19.2")
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0; stderr %q\n%s", code, stderr, stdout)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty: the skipped reasons already say the cache is cold", stderr)
	}
	rep := decodeReport(t, stdout)
	s := rep.Subjects[0]
	if len(s.Findings) != 0 {
		t.Errorf("findings = %v, want none without data", s.Findings)
	}
	if len(s.Skipped) == 0 {
		t.Fatal("no skipped checks with a cold cache")
	}
	for _, sk := range s.Skipped {
		if !strings.Contains(sk.Reason, "offline") {
			t.Errorf("%s skipped with %q, want the offline reason", sk.Check, sk.Reason)
		}
	}
	// The look-alike name check needs only the embedded lists, so it may run;
	// nothing that needs a registry, OSV or deps.dev may.
	for _, id := range s.Evaluated {
		if id != "TD008" {
			t.Errorf("%s evaluated offline with a cold cache", id)
		}
	}

	writePolicy(t, "version: 1\non_data_unavailable: fail\n")
	code, stdout, _ = run(t, "--offline", "--format", "json", "check", "npm:express@4.19.2")
	rep = decodeReport(t, stdout)
	if code != ExitUnavailable || rep.Summary.ExitCode != ExitUnavailable {
		t.Fatalf("exit = %d, summary exit = %d; want 3 under on_data_unavailable: fail", code, rep.Summary.ExitCode)
	}
}

// --cooldown is the top of the precedence chain: it beats the ecosystem override
// of the policy file, and cooldown_exclude still applies alongside it.
func TestCheckCooldownFlagBeatsEcosystemOverride(t *testing.T) {
	useFakeLoader(t)
	const override = "version: 1\necosystems:\n  npm:\n    cooldown: 30d\n"
	tests := []struct {
		name         string
		policy       string
		args         []string
		wantTD001    bool
		wantSkipped  string
		wantCooldown string
	}{
		{name: "override applies without the flag", policy: override, wantTD001: true, wantCooldown: "3d"},
		{name: "flag wins over the override", policy: override, args: []string{"--cooldown", "1h"}, wantCooldown: "1h"},
		{name: "cooldown_exclude survives the flag", policy: override + "cooldown_exclude:\n  - npm:trustdiff-fixture-*\n", args: []string{"--cooldown", "1h"}, wantSkipped: "excluded by cooldown_exclude", wantCooldown: "1h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writePolicy(t, tt.policy)
			t.Cleanup(func() { removePolicy(t) })
			args := append(append([]string{"--format", "json"}, tt.args...), "check", "npm:trustdiff-fixture-lib@2.0.0")
			_, stdout, _ := run(t, args...)
			rep := decodeReport(t, stdout)
			s := rep.Subjects[0]
			var young bool
			for i := range s.Findings {
				if s.Findings[i].ID == "TD001" {
					young = true
				}
			}
			if young != tt.wantTD001 {
				t.Errorf("TD001 present = %v, want %v (findings %v)", young, tt.wantTD001, s.Findings)
			}
			var skipped string
			for _, sk := range s.Skipped {
				if sk.Check == "TD001" {
					skipped = sk.Reason
				}
			}
			if skipped != tt.wantSkipped {
				t.Errorf("TD001 skipped with %q, want %q", skipped, tt.wantSkipped)
			}
			if rep.Policy.Cooldown != tt.wantCooldown {
				t.Errorf("report policy.cooldown = %q, want %q", rep.Policy.Cooldown, tt.wantCooldown)
			}
		})
	}
}
