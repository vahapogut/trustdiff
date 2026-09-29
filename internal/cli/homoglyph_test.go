package cli

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/typosquat"
)

func noDiagnosticLoader(t *testing.T) {
	t.Helper()
	old := loaderFactory
	loaderFactory = func(*App, time.Time) (checks.Loader, error) {
		t.Fatal("name-only diagnostic must not construct a registry loader")
		return nil, nil
	}
	t.Cleanup(func() { loaderFactory = old })
}

func TestCheckUnicodeNPMNameOnly(t *testing.T) {
	fixtureClock(t)
	t.Setenv("TRUSTDIFF_CACHE_DIR", t.TempDir())
	noDiagnosticLoader(t)
	for _, offline := range []bool{false, true} {
		args := []string{"--format", "json", "check", "npm:\u0441halk"}
		if offline {
			args = append([]string{"--offline"}, args...)
		}
		code, stdout, stderr := run(t, args...)
		if code != ExitFindings || stderr != "" {
			t.Fatalf("exit=%d stderr=%q\n%s", code, stderr, stdout)
		}
		rep := decodeReport(t, stdout)
		if len(rep.Subjects) != 1 {
			t.Fatalf("subjects=%d", len(rep.Subjects))
		}
		s := rep.Subjects[0]
		if s.Ref.Name != "\u0441halk" || s.Ref.Version != "" || !slices.Equal(s.Evaluated, []string{"TD008"}) {
			t.Fatalf("name-only subject=%+v", s)
		}
		if len(s.Findings) != 1 || s.Findings[0].ID != "TD008" {
			t.Fatalf("findings=%+v", s.Findings)
		}
		for key, want := range map[string]string{"neighbor": "chalk", "rule": "unicode-homoglyph", "skeleton": "chalk", "unicode_version": typosquat.HomoglyphUnicodeVersion} {
			if s.Findings[0].Evidence[key] != want {
				t.Errorf("evidence[%s]=%v want %s", key, s.Findings[0].Evidence[key], want)
			}
		}
		if len(s.Skipped) == 0 {
			t.Fatal("registry/advisory checks must explicitly skip")
		}
		for _, skipped := range s.Skipped {
			if !strings.Contains(skipped.Reason, "name-only diagnostic") {
				t.Errorf("skip=%+v", skipped)
			}
		}
	}
	if _, err := model.ParseRef("npm:\u0441halk"); err == nil {
		t.Fatal("general npm validation was relaxed")
	}
}

func TestCheckUnicodeNPMRespectsPolicy(t *testing.T) {
	fixtureClock(t)
	t.Setenv("TRUSTDIFF_CACHE_DIR", t.TempDir())
	noDiagnosticLoader(t)
	for _, tt := range []struct {
		name, policy   string
		flags          []string
		code, findings int
	}{
		{"fail-on never", "", []string{"--fail-on", "never"}, ExitOK, 1},
		{"off", "version: 1\nchecks:\n  typosquat-suspect: off\n", nil, ExitOK, 0},
		{"warn", "version: 1\nchecks:\n  typosquat-suspect: warn\n", nil, ExitOK, 1},
		{"warn gate", "version: 1\nchecks:\n  typosquat-suspect: warn\n", []string{"--fail-on", "warn"}, ExitFindings, 1},
		{"allow", "version: 1\nallow:\n  - check: typosquat-suspect\n    package: npm:*\n    reason: local diagnostic accepted\n", nil, ExitOK, 0},
		{"unavailability fail is not a registry outage", "version: 1\non_data_unavailable: fail\n", []string{"--fail-on", "never"}, ExitOK, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.policy != "" {
				writePolicy(t, tt.policy)
				defer removePolicy(t)
			}
			args := append(slices.Clone(tt.flags), "--format", "json", "check", "npm:\u0441halk@1.0.0")
			code, stdout, stderr := run(t, args...)
			if code != tt.code {
				t.Fatalf("exit=%d want%d stderr=%s", code, tt.code, stderr)
			}
			rep := decodeReport(t, stdout)
			if len(rep.Subjects[0].Findings) != tt.findings {
				t.Fatalf("findings=%+v", rep.Subjects[0].Findings)
			}
		})
	}
}

type unicodeGuardLoader struct {
	fakeLoader
	sawInvalid atomic.Bool
}

func (l *unicodeGuardLoader) Versions(ctx context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error) {
	if eco == model.NPM && model.NPMNameProblem(name) != "" {
		l.sawInvalid.Store(true)
	}
	return l.fakeLoader.Versions(ctx, eco, name)
}
func (l *unicodeGuardLoader) Prefetch(_ context.Context, refs []model.PackageRef) {
	for _, ref := range refs {
		if model.NPMNameProblem(ref.Name) != "" {
			l.sawInvalid.Store(true)
		}
	}
}

func TestCheckMixedUnicodeAndRegistryNames(t *testing.T) {
	now := fixtureClock(t)
	t.Setenv("TRUSTDIFF_CACHE_DIR", t.TempDir())
	loader := &unicodeGuardLoader{fakeLoader: fakeLoader{now: now}}
	old := loaderFactory
	loaderFactory = func(*App, time.Time) (checks.Loader, error) { return loader, nil }
	t.Cleanup(func() { loaderFactory = old })
	code, stdout, stderr := run(t, "--format", "json", "check", "npm:\u0441halk", "npm:trustdiff-fixture-lib@1.0.0", "npm:@typ\u0435s/node")
	if code != ExitFindings {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	rep := decodeReport(t, stdout)
	if len(rep.Subjects) != 3 || rep.Subjects[0].Ref.Name != "\u0441halk" || rep.Subjects[1].Ref.Name != "trustdiff-fixture-lib" || rep.Subjects[2].Ref.Name != "@typ\u0435s/node" {
		t.Fatalf("subject order=%+v", rep.Subjects)
	}
	if loader.sawInvalid.Load() {
		t.Fatal("Unicode diagnostic leaked into registry/prefetch")
	}
}

func TestUnicodeNPMDiagnosticRejectsUnrelatedInvalidRefs(t *testing.T) {
	for _, ref := range []string{"npm:\u0441halk@", "npm:\u0441halk?secret", "npm:\u0441halk#fragment", "npm:../\u0441halk", "npm:\u0441halk/name", "npm:\u0441halk\\file", "npm:my \u0441halk", "npm:\u65e5\u672c\u8a9e", "npm:@\u0441halk/name/extra", "pypi:\u0441halk"} {
		if got, ok := unicodeNPMDiagnostic(ref); ok {
			t.Errorf("accepted %q as %+v", ref, got)
		}
	}
}
