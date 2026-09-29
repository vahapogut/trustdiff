package cli

import (
	"context"
	"testing"

	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/guarddog"
	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/report"
)

type fakeCodeScanner struct {
	refs    []model.PackageRef
	partial bool
}

func (s *fakeCodeScanner) Scan(_ context.Context, ref model.PackageRef) (guarddog.Result, error) {
	s.refs = append(s.refs, ref)
	status := "completed"
	if s.partial {
		status = "partial"
	}
	return guarddog.Result{Ref: ref, Source: guarddog.SourceURL, Status: status, Issues: 1}, nil
}

func TestGuardDogOnlySelectedRegistryReleasesAndPartialExit(t *testing.T) {
	original := guardDogFactory
	t.Cleanup(func() { guardDogFactory = original })
	fake := &fakeCodeScanner{}
	guardDogFactory = func(*App) (codeScanner, error) { return fake, nil }
	ref := model.PackageRef{Ecosystem: model.NPM, Name: "suspect", Version: "1.0.0"}
	inputs := []checks.Input{{Lock: &lockfile.Entry{Source: lockfile.SourceGit}}, {}, {}, {}}
	rep := &report.Report{Subjects: []report.Subject{
		{Ref: ref, Verdict: report.VerdictBlock},
		{Ref: ref, Verdict: report.VerdictWarn},
		{Ref: ref, Verdict: report.VerdictWarn},
		{Ref: model.PackageRef{Ecosystem: model.NPM, Name: "clean", Version: "1.0.0"}, Verdict: report.VerdictOK},
	}}
	a := &App{Opts: Options{GuardDog: true}}
	a.addGuardDog(context.Background(), rep, inputs)
	if len(fake.refs) != 1 || len(rep.GuardDog) != 2 || rep.GuardDog[0].Status != "unavailable" {
		t.Fatalf("wrong selection: %+v %+v", fake.refs, rep.GuardDog)
	}
	if rep.Subjects[0].Verdict != report.VerdictBlock || rep.Summary.ExitCode != ExitUnavailable {
		t.Fatalf("wrong verdict/exit: %+v", rep)
	}
	fake.partial = true
	rep = &report.Report{Subjects: []report.Subject{{Ref: ref, Verdict: report.VerdictWarn}}}
	a.addGuardDog(context.Background(), rep, nil)
	if rep.Summary.ExitCode != ExitUnavailable {
		t.Fatal("partial scan reported successful exit")
	}
}

func TestGuardDogRejectsOfflineBeforeAnyAnalysis(t *testing.T) {
	code, _, stderr := run(t, "check", "npm:foo@1.0.0", "--guarddog", "--offline")
	if code != ExitUsage || stderr == "" {
		t.Fatalf("offline accepted: %d %s", code, stderr)
	}
}

func TestGuardDogDoesNotSubstitutePublicPackageForPrivateMirror(t *testing.T) {
	original := guardDogFactory
	t.Cleanup(func() { guardDogFactory = original })
	fake := &fakeCodeScanner{}
	guardDogFactory = func(*App) (codeScanner, error) { return fake, nil }
	ref := model.PackageRef{Ecosystem: model.NPM, Name: "suspect", Version: "1.0.0"}
	rep := &report.Report{Subjects: []report.Subject{{Ref: ref, Verdict: report.VerdictWarn}, {Ref: ref, Verdict: report.VerdictWarn}}}
	inputs := []checks.Input{
		{Lock: &lockfile.Entry{Ref: ref, Source: lockfile.SourceRegistry, Resolved: "https://registry.npmjs.org/suspect/-/suspect-1.0.0.tgz"}},
		{Lock: &lockfile.Entry{Ref: ref, Source: lockfile.SourceRegistry, Resolved: "https://artifacts.example.com/suspect/-/suspect-1.0.0.tgz"}},
	}
	a := &App{Opts: Options{GuardDog: true}}
	a.addGuardDog(context.Background(), rep, inputs)
	if len(fake.refs) != 1 || len(rep.GuardDog) != 2 || rep.GuardDog[1].Status != "unavailable" {
		t.Fatalf("private artifact substitution: %+v", rep.GuardDog)
	}
}

func TestGuardDogNPMLockedArtifactIdentity(t *testing.T) {
	for _, tt := range []struct {
		name, resolved string
		want           bool
	}{
		{"suspect", "https://registry.npmjs.org/suspect/-/suspect-1.0.0.tgz", true},
		{"suspect", "https://REGISTRY.NPMJS.ORG/%73uspect/-/suspect-1.0.0.tgz", true},
		{"@scope/suspect", "https://registry.npmjs.org/@scope/suspect/-/suspect-1.0.0.tgz", true},
		{"@scope/suspect", "https://registry.npmjs.org/%40scope%2fsuspect/-/suspect-1.0.0.tgz", true},
		{"@scope/suspect", "https://registry.npmjs.org/@scope%2Fsuspect/-/suspect-1.0.0.tgz", true},
		{"suspect", "https://registry.npmjs.org/other/-/other-1.0.0.tgz", false},
		{"suspect", "https://registry.npmjs.org/suspect/-/suspect-1.0.1.tgz", false},
		{"suspect", "https://registry.npmjs.org/suspect/-/other-1.0.0.tgz", false},
		{"@scope/suspect", "https://registry.npmjs.org/@other/suspect/-/suspect-1.0.0.tgz", false},
		{"@scope/suspect", "https://registry.npmjs.org/@scope%252fsuspect/-/suspect-1.0.0.tgz", false},
		{"suspect", "https://registry.npmjs.org/suspect/-/suspect-1.0.0.tgz?alternate=1", false},
		{"suspect", "https://registry.npmjs.org/suspect/-/suspect-1.0.0.tgz?", false},
		{"suspect", "https://registry.npmjs.org/suspect/-/suspect-1.0.0.tgz#alternate", false},
		{"suspect", "https://registry.npmjs.org/suspect/-/suspect-1.0.0.tgz#", false},
		{"suspect", "https://someone@registry.npmjs.org/suspect/-/suspect-1.0.0.tgz", false},
		{"suspect", "https://registry.npmjs.org:443/suspect/-/suspect-1.0.0.tgz", false},
		{"suspect", "http://registry.npmjs.org/suspect/-/suspect-1.0.0.tgz", false},
		{"suspect", "https://registry.npmjs.org.example.com/suspect/-/suspect-1.0.0.tgz", false},
	} {
		t.Run(tt.resolved, func(t *testing.T) {
			entry := &lockfile.Entry{Ref: model.PackageRef{Ecosystem: model.NPM, Name: tt.name, Version: "1.0.0"}, Source: lockfile.SourceRegistry, Resolved: tt.resolved}
			if got := publicRegistryEntry(entry); got != tt.want {
				t.Fatalf("publicRegistryEntry=%v, want %v", got, tt.want)
			}
		})
	}
}
