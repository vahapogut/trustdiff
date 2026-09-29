package dumpindex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

type removingAfterPrefetch struct {
	*Index
	t     *testing.T
	calls int
	names int
}

func (s *removingAfterPrefetch) PrefetchVersions(ctx context.Context, names []string) {
	s.calls++
	s.names = len(names)
	s.Index.PrefetchVersions(ctx, names)
	// Removing the selected temporary shard proves that every subsequent
	// Versions/VersionInfo call uses the prefetched records before resolution.
	for shard := range s.Meta.Shards {
		if err := os.Remove(filepath.Join(s.dir, shard)); err != nil {
			s.t.Fatal(err)
		}
	}
}

func TestRunnerPrefetchesSameShardBeforeResolvingCrates(t *testing.T) {
	other := ""
	for n := 0; n < 10000; n++ {
		candidate := fmt.Sprintf("same_shard_%d", n)
		if shardFor(candidate) == shardFor("test_crate") {
			other = candidate
			break
		}
	}
	if other == "" {
		t.Fatal("no same-shard test name")
	}
	tables := fixtureTables()
	tables["data/crates.csv"] += "4," + other + ",2020-01-01T00:00:00Z,2026-09-28T00:00:00Z\n"
	tables["data/versions.csv"] += "4,1.0.0,2026-09-27T00:00:00Z,2,f," + strings.Repeat("c", 64) + "\n"
	dir := t.TempDir()
	if _, err := refreshFixture(t, dir, archiveFixture(t, tables), nil); err != nil {
		t.Fatal(err)
	}
	i, err := Open(dir, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	source := &removingAfterPrefetch{Index: i, t: t}
	loader := checks.NewLoader(registry.Registry{model.Cargo: source}, nil, nil, nil)
	var selected []checks.Check
	for _, check := range checks.All() {
		if check.ID() == "TD001" {
			selected = append(selected, check)
		}
	}
	runner := &checks.Runner{Loader: loader, Checks: selected, Now: fixtureTime}
	inputs := []checks.Input{{Ref: model.MustParseRef("cargo:test-crate@1.0.0")}, {Ref: model.MustParseRef("cargo:" + other + "@1.0.0")}}
	got := runner.Evaluate(context.Background(), inputs)
	if source.calls != 1 || source.names != 2 {
		t.Fatalf("prefetch calls=%d names=%d", source.calls, source.names)
	}
	for _, out := range got {
		if len(out.Subject.Skipped) > 0 || len(out.Subject.Findings) != 1 {
			t.Fatalf("prefetched metadata was unavailable: %+v", out.Subject)
		}
	}
}

func TestClearAndRefreshShareAnExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	if _, err := refreshFixture(t, dir, archiveFixture(t, fixtureTables()), nil); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(Dir(dir), "refresh.lock")
	if err := os.WriteFile(lock, []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir); err == nil {
		t.Fatal("clear ignored an active refresh")
	}
	if _, err := Refresh(context.Background(), dir, nil); err == nil {
		t.Fatal("refresh ignored an active clear/refresh")
	}
	data, err := os.ReadFile(lock)
	if err != nil || string(data) != "held" {
		t.Fatalf("another operation removed lock: %q %v", data, err)
	}
	if _, err := ReadMeta(dir); err != nil {
		t.Fatal("lock refusal changed metadata")
	}
}
