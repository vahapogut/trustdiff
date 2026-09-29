package dumpindex

import (
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// The public owner rows describe current membership. Even an old created_at
// cannot establish continuous membership at publication: deleted owner rows and
// owner actions are omitted from the public dump. Those rows must never become
// historical maintainers that would demote a publisher-change finding.
func TestCurrentDumpOwnersNeverBecomeHistoricalMaintainers(t *testing.T) {
	tables := fixtureTables()
	tables["data/users.csv"] = "id,gh_login,username\n2,alice,alice\n3,bob,bob\n"
	tables["data/crate_owners.csv"] = "crate_id,owner_kind,owner_id,created_at\n1,0,3,2020-01-01T00:00:00Z\n"
	tables["data/versions.csv"] = "crate_id,num,created_at,published_by,yanked,tar_sha256\n" +
		"1,1.0.0,2026-09-25T00:00:00Z,2,f," + strings.Repeat("a", 64) + "\n" +
		"1,2.0.0,2026-09-27T00:00:00Z,3,f," + strings.Repeat("b", 64) + "\n"
	dir := t.TempDir()
	if _, err := refreshFixture(t, dir, archiveFixture(t, tables), nil); err != nil {
		t.Fatal(err)
	}
	index, err := Open(dir, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	owners, err := index.Owners(t.Context(), "test_crate")
	if err != nil || len(owners) != 1 || owners[0].Name != "bob" {
		t.Fatalf("current owners = %+v, %v", owners, err)
	}
	list, err := index.Versions(t.Context(), "test_crate")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range list.Versions {
		if len(version.Maintainers) != 0 {
			t.Fatalf("current owners were assigned to historical release %s: %+v", version.Ref, version.Maintainers)
		}
	}
	selected := make([]checks.Check, 0, 2)
	for _, id := range []string{"TD002", "TD003"} {
		check, ok := checks.Lookup(id)
		if !ok {
			t.Fatalf("%s not registered", id)
		}
		selected = append(selected, check)
	}
	loader := checks.NewLoader(registry.Registry{model.Cargo: index}, nil, nil, nil)
	runner := &checks.Runner{Loader: loader, Checks: selected, Now: fixtureTime}
	results := runner.Evaluate(t.Context(), []checks.Input{{Ref: model.MustParseRef("cargo:test_crate@2.0.0")}})
	subject := results[0].Subject
	if len(subject.Findings) != 1 || subject.Findings[0].ID != "TD002" || subject.Findings[0].Level != model.LevelBlock {
		t.Fatalf("current owner wrongly cleared or demoted a new publisher: %+v", subject)
	}
	if _, claimed := subject.Findings[0].Evidence["publisher_is_maintainer"]; claimed {
		t.Fatal("finding claims a historical maintainer identity from current owner rows")
	}
	if len(subject.Skipped) != 1 || subject.Skipped[0].Check != "TD003" ||
		!strings.Contains(subject.Skipped[0].Reason, "no maintainer set per version") ||
		!strings.Contains(subject.Skipped[0].Reason, "no baseline") {
		t.Fatalf("missing historical membership was not explicit: %+v", subject.Skipped)
	}
}
