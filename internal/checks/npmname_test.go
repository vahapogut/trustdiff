package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

// hostileSubjectN is a lockfile subject whose name npm's grammar refuses. It is
// built by hand because MustParseRef, rightly, refuses to build one.
func hostileSubjectN(name string, opts ...func(*lockfile.Entry)) *Subject {
	ref := model.PackageRef{Ecosystem: model.NPM, Name: name, Version: "1.0.0"}
	entry := &lockfile.Entry{Ref: ref, Source: lockfile.SourceRegistry, Resolved: "https://registry.npmjs.org/x/-/x-1.0.0.tgz", Line: 12}
	for _, opt := range opts {
		opt(entry)
	}
	return &Subject{
		Ref:         ref,
		Now:         nowC,
		Settings:    (*policy.Policy)(nil).Effective(model.NPM),
		Lock:        entry,
		Location:    &model.Location{Path: "package-lock.json", Line: 12},
		Downloads:   -1,
		Unavailable: map[string]error{},
	}
}

// A lockfile entry whose name npm's own grammar refuses names something the
// registry cannot hold, so whatever it installed came from somewhere else. That is
// what exotic-source exists to say, and it says it at the level the policy sets.
// Finding F25 of docs/review-2026-09-10.md.
func TestExoticSourceReportsANameNpmCouldNeverHold(t *testing.T) {
	for _, name := range []string{"evil?trustdiff=1", "@scope/..", "..", "foo#frag"} {
		t.Run(name, func(t *testing.T) {
			res := exoticSource{}.Run(context.Background(), hostileSubjectN(name))
			if len(res.Findings) != 1 {
				t.Fatalf("findings = %+v, want one", res.Findings)
			}
			f := &res.Findings[0]
			if f.Level != model.LevelBlock {
				t.Errorf("level = %s, want block, the level the policy sets for exotic-source", f.Level)
			}
			if !strings.Contains(f.Explanation, "name cannot exist on the registry") {
				t.Errorf("explanation does not say the name cannot exist on the registry:\n%s", f.Explanation)
			}
			if got := evidenceC(t, f, "signal"); got != "invalid-name" {
				t.Errorf("signal = %s, want invalid-name", got)
			}
		})
	}
	// A bundled entry is normally left to the package that carries it, but a name
	// that cannot exist is a fact about the lockfile, whoever wrote the line.
	bundled := hostileSubjectN("evil?trustdiff=1", func(e *lockfile.Entry) { e.Bundled = true })
	if res := (exoticSource{}).Run(context.Background(), bundled); len(res.Findings) != 1 {
		t.Errorf("a bundled entry with an impossible name produced %+v, want one finding", res.Findings)
	}
	// The one rule left out of the grammar: "-" is on the registry.
	dash := hostileSubjectN("-")
	if res := (exoticSource{}).Run(context.Background(), dash); len(res.Findings) != 0 {
		t.Errorf("npm:- produced %+v, want nothing: the registry serves it", res.Findings)
	}
}

// The runner asks no source about such a name. It is a definite answer, so every
// check that reads the registry skips with it and the outcome is not unavailable,
// and the lockfile checks still run and report the entry.
func TestRunnerAsksNoSourceAboutANameNpmCouldNeverHold(t *testing.T) {
	loader := newFakeLoaderR()
	s := hostileSubjectN("evil?trustdiff=1")
	in := Input{Ref: s.Ref, Location: s.Location, Lock: s.Lock}
	out := newRunnerR(loader).Evaluate(context.Background(), []Input{in})
	if len(out) != 1 {
		t.Fatalf("outcomes = %d, want 1", len(out))
	}
	for _, what := range []string{"versions", "info", "owners", "downloads", "advisories", "depsdev", "similar"} {
		if n := loader.count(what); n != 0 {
			t.Errorf("the loader was asked %s %d times about a name that cannot exist", what, n)
		}
	}
	for _, batch := range loader.prefetched {
		for _, ref := range batch {
			if ref.Name == s.Ref.Name {
				t.Errorf("the name reached Prefetch: %v", batch)
			}
		}
	}
	o := &out[0]
	if o.Unavailable {
		t.Error("the outcome counts as unavailable, and nothing was: the name is an answer")
	}
	var reported bool
	for _, f := range o.Subject.Findings {
		if f.ID == "TD013" && f.Level == model.LevelBlock {
			reported = true
		}
	}
	if !reported {
		t.Errorf("no TD013 block finding: %+v", o.Subject.Findings)
	}
	for _, sk := range o.Subject.Skipped {
		if sk.Check == "TD016" || sk.Check == "TD017" {
			continue
		}
		if !strings.HasPrefix(sk.Reason, "not a valid npm name") {
			t.Errorf("%s skipped with %q, want the name named as the reason", sk.Check, sk.Reason)
		}
	}
}
