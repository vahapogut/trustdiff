package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/jsonschema"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/report"
)

// fakeLoader serves one npm package, lib, with two releases: 1.0.0 by alice a
// year ago and 2.0.0 by bob one day before the injected clock. Every other name is
// unknown, and the name "down" makes the registry unavailable.
type fakeLoader struct {
	now time.Time
}

var errRegistryDown = errors.New("connection refused")

func (f *fakeLoader) list() *registry.VersionList {
	ref := func(v string) model.PackageRef {
		return model.PackageRef{Ecosystem: model.NPM, Name: "trustdiff-fixture-lib", Version: v}
	}
	return &registry.VersionList{
		Ecosystem: model.NPM,
		Name:      "trustdiff-fixture-lib",
		Latest:    "2.0.0",
		Versions: []model.VersionInfo{
			{Ref: ref("1.0.0"), PublishedAt: f.now.AddDate(-1, 0, 0), Publisher: &model.Publisher{Name: "alice"}, WeeklyDownloads: -1},
			{Ref: ref("2.0.0"), PublishedAt: f.now.Add(-24 * time.Hour), Publisher: &model.Publisher{Name: "bob"}, WeeklyDownloads: -1},
		},
	}
}

func (f *fakeLoader) Prefetch(context.Context, []model.PackageRef) {}

func (f *fakeLoader) Versions(_ context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error) {
	switch {
	case name == "down":
		return nil, errRegistryDown
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

func (f *fakeLoader) Advisories(context.Context, model.PackageRef) ([]advisory.Advisory, error) {
	return nil, nil
}

func (f *fakeLoader) DepsDev(context.Context, model.PackageRef) (*depsdev.VersionFacts, error) {
	return &depsdev.VersionFacts{Found: true}, nil
}

func (f *fakeLoader) SimilarNames(context.Context, model.Ecosystem, string) ([]depsdev.Similar, error) {
	return nil, nil
}

func useFakeLoader(t *testing.T) time.Time {
	t.Helper()
	now := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	old := loaderFactory
	loaderFactory = func(*App) (checks.Loader, error) { return &fakeLoader{now: now}, nil }
	t.Cleanup(func() { loaderFactory = old })
	t.Setenv(nowEnv, now.Format(time.RFC3339))
	chdir(t, t.TempDir()) // no policy file: built-in defaults
	return now
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
	if len(rep.Subjects) != 2 || rep.Summary.ExitCode != 1 || rep.Policy.Cooldown != "3d" || rep.Policy.FailOn != "block" {
		t.Fatalf("report = %+v", rep.Summary)
	}
}

func TestCheckUsageErrors(t *testing.T) {
	useFakeLoader(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "bad ref", args: []string{"check", "express"}, want: "invalid ref"},
		{name: "manifest path is planned", args: []string{"check", "package.json"}, want: "later release"},
		{name: "sarif is planned", args: []string{"--format", "sarif", "check", "npm:trustdiff-fixture-lib@2.0.0"}, want: "later release"},
		{name: "unknown package", args: []string{"check", "npm:trustdiff-unknown-package-x9q@1.0.0"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tt.args...)
			if tt.want == "" {
				// An unknown package is not a usage error and not an outage: the registry
				// checks are skipped with a "not found" reason and the exit code stays 0.
				if code != ExitOK || !strings.Contains(stdout, "not found in the registry") || strings.Contains(stdout, "unavailable") {
					t.Fatalf("exit = %d, stdout:\n%s", code, stdout)
				}
				return
			}
			if code != ExitUsage || !strings.Contains(stderr, tt.want) {
				t.Fatalf("exit = %d, stderr = %q, want usage error containing %q", code, stderr, tt.want)
			}
		})
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
	dir, _ := os.Getwd()
	if err := os.WriteFile(filepath.Join(dir, ".trustdiff.yaml"), []byte("version: 1\non_data_unavailable: fail\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := run(t, "check", "npm:down@1.0.0")
	if code != ExitUnavailable || !strings.Contains(stdout, "unavailable") {
		t.Fatalf("exit = %d, want 3; stdout:\n%s", code, stdout)
	}
	// The default policy (warn) keeps the exit code at 0 for the same failure.
	if err := os.Remove(filepath.Join(dir, ".trustdiff.yaml")); err != nil {
		t.Fatal(err)
	}
	code, _, _ = run(t, "check", "npm:down@1.0.0")
	if code != ExitOK {
		t.Fatalf("exit with the default policy = %d, want 0", code)
	}
}
