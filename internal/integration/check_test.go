//go:build integration

package integration

import (
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/advisory/osv"
	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/registry/crates"
	"github.com/vahapogut/trustdiff/internal/registry/npm"
	"github.com/vahapogut/trustdiff/internal/registry/pypi"
	"github.com/vahapogut/trustdiff/internal/report"
)

// TestCheckRunnerEndToEnd wires the real registries and advisory sources into
// checks.NewLoader and runs every check through checks.Runner for the three
// refs of the M1 acceptance command, the way the check command does. It asserts
// that each bare ref resolved to a version, that checks ran, and that no check
// was skipped because a registry answer was missing; skips for other reasons
// (PyPI has no per-version publisher, the baseline arrives in M4) are logged.
func TestCheckRunnerEndToEnd(t *testing.T) {
	ctx, l := start(t)
	// TD008 reads a refreshed popular list from the trustdiff cache directory
	// when one is there; point it at the temporary one so the run reads nothing
	// from the user's cache.
	t.Setenv(httpcache.EnvDir, l.http.Dir())

	reg := registry.Registry{
		model.NPM:   npm.New(l.http, npm.WithLogger(l.log)),
		model.PyPI:  pypi.New(l.http, pypi.WithLogger(l.log)),
		model.Cargo: crates.New(l.http, crates.WithLogger(l.log)),
	}
	loader := checks.NewLoader(reg, osv.New(l.http, osv.WithLogger(l.log)), depsdev.New(l.http, depsdev.WithLogger(l.log)), l.log)
	runner := &checks.Runner{Loader: loader, Jobs: 3, Log: l.log}
	inputs := []checks.Input{
		{Ref: model.MustParseRef("npm:express")},
		{Ref: model.MustParseRef("pypi:requests")},
		{Ref: model.MustParseRef("cargo:serde")},
	}

	subjects := runner.Run(ctx, inputs)
	if ctx.Err() != nil {
		t.Fatalf("the run did not finish within %v: %v", deadline, ctx.Err())
	}
	if len(subjects) != len(inputs) {
		t.Fatalf("%d subjects, want %d", len(subjects), len(inputs))
	}
	for i := range subjects {
		s := &subjects[i]
		want := inputs[i].Ref
		if s.Ref.Ecosystem != want.Ecosystem || s.Ref.Name != want.Name {
			t.Errorf("subject %d is %s, want %s", i, s.Ref.Package(), want)
			continue
		}
		if s.Ref.Version == "" {
			t.Errorf("%s did not resolve to a version", want)
		}
		if len(s.Evaluated) == 0 {
			t.Errorf("%s: no check ran", s.Ref)
		}
		for _, sk := range s.Skipped {
			if strings.HasPrefix(sk.Reason, checks.SourceRegistry) {
				t.Errorf("%s: %s skipped for a registry reason: %s", s.Ref, sk.Check, sk.Reason)
				continue
			}
			t.Logf("%s: %s skipped: %s", s.Ref, sk.Check, sk.Reason)
		}
		t.Logf("%s: %d checks evaluated, %d skipped, findings %v", s.Ref, len(s.Evaluated), len(s.Skipped), findingIDs(s))
	}
}

// findingIDs lists the check ids of a subject's findings, for the log.
func findingIDs(s *report.Subject) []string {
	out := make([]string, 0, len(s.Findings))
	for i := range s.Findings {
		out = append(out, s.Findings[i].ID)
	}
	return out
}
