package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
)

// localSubjectL is a lockfile entry that resolves to a directory of the project,
// which is what a workspace member and a link: entry look like in every format
// that writes one.
func localSubjectL(ref string, resolved string) *Subject {
	r := model.MustParseRef(ref)
	entry := &lockfile.Entry{Ref: r, Source: lockfile.SourcePath, Resolved: resolved, Line: 8317}
	return &Subject{
		Ref:         r,
		Now:         nowC,
		Settings:    (*policy.Policy)(nil).Effective(r.Ecosystem),
		Lock:        entry,
		Location:    &model.Location{Path: "yarn.lock", Line: 8317},
		Downloads:   -1,
		Unavailable: map[string]error{},
	}
}

// A lockfile entry that resolves to a directory of the project is not the registry's
// package of that name, and a run that asks a registry or an advisory database about
// it is asking about something else. The precision pass of 2026-09-12 measured what
// that costs. React's yarn.lock links eslint-plugin-react-internal to
// ./scripts/eslint-rules, and npm holds a package of that name which OSV lists as
// malicious (MAL-2025-19860): the scan reported React's own lint rules as malware
// at block. npm/cli's lockfile links sixteen workspace members whose names npm also
// publishes, and six of them produced publisher-changed at block, comparing the
// registry's release history against a directory in the repository.
//
// So the run settles such an entry without asking anything: every check that reads
// a source skips with the reason, the lockfile checks still run, and exotic-source
// reports the entry at info the way it already did. It is an answer and not an
// outage, so on_data_unavailable is not involved, which is the rule a name npm's
// grammar refuses already follows.
func TestRunnerAsksNoSourceAboutAnEntryThatIsADirectory(t *testing.T) {
	loader := newFakeLoaderR()
	s := localSubjectL("npm:eslint-plugin-react-internal@0.0.0", "./scripts/eslint-rules")
	in := Input{Ref: s.Ref, Location: s.Location, Lock: s.Lock}
	out := newRunnerR(loader).Evaluate(context.Background(), []Input{in})
	if len(out) != 1 {
		t.Fatalf("outcomes = %d, want 1", len(out))
	}
	for _, what := range []string{"versions", "info", "owners", "downloads", "advisories", "depsdev", "similar"} {
		if n := loader.count(what); n != 0 {
			t.Errorf("the loader was asked %s %d times about a directory of the project", what, n)
		}
	}
	for _, batch := range loader.prefetched {
		for _, ref := range batch {
			if ref.Name == s.Ref.Name {
				t.Errorf("the entry reached Prefetch: %v", batch)
			}
		}
	}
	o := &out[0]
	if o.Unavailable {
		t.Error("the outcome counts as unavailable, and nothing was: a directory is an answer")
	}
	var reported bool
	for _, f := range o.Subject.Findings {
		if f.ID == "TD013" {
			reported = true
			if f.Level != model.LevelInfo {
				t.Errorf("TD013 level = %s, want info: a workspace member is reported, not failed", f.Level)
			}
			continue
		}
		t.Errorf("a check reported a finding about a directory of the project: %+v", f)
	}
	if !reported {
		t.Errorf("no TD013 finding: %+v", o.Subject.Findings)
	}
	for _, sk := range o.Subject.Skipped {
		if sk.Check == "TD016" || sk.Check == "TD017" {
			continue
		}
		if !strings.Contains(sk.Reason, "directory") {
			t.Errorf("%s skipped with %q, want the directory named as the reason", sk.Check, sk.Reason)
		}
	}
}
