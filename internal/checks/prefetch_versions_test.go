package checks

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// bulkVersionsSourceR models the dump's batch preparation contract. Versions
// records an early call so moving the preload after resolution cannot pass.
type bulkVersionsSourceR struct {
	*fakeSourceR
	warmed      atomic.Bool
	earlyRead   atomic.Bool
	requested   []string
	preloadErr  error
	contextErr  error
	preloadRuns int
}

func (s *bulkVersionsSourceR) PrefetchVersions(ctx context.Context, names []string) {
	s.preloadRuns++
	s.requested = append([]string(nil), names...)
	s.contextErr = ctx.Err()
	s.err = s.preloadErr
	s.warmed.Store(true)
}

func (s *bulkVersionsSourceR) Versions(ctx context.Context, name string) (*registry.VersionList, error) {
	if !s.warmed.Load() {
		s.earlyRead.Store(true)
	}
	return s.fakeSourceR.Versions(ctx, name)
}

func TestRunnerPrefetchVersionsBeforeResolutionAndExcludesLocalInputs(t *testing.T) {
	source := &bulkVersionsSourceR{fakeSourceR: newFakeSourceR(model.Cargo)}
	source.add(stableListR(model.Cargo, "first", "1.0.0"))
	source.add(stableListR(model.Cargo, "second", "2.0.0"))
	npm := newFakeSourceR(model.NPM)
	npm.add(stableListR(model.NPM, "other", "3.0.0"))
	loader := newDataLoader(registry.Registry{model.Cargo: source, model.NPM: npm}, nil, nil, nil)
	inputs := inputsR("cargo:first", "cargo:local@1.0.0", "cargo:second@2.0.0", "npm:other@3.0.0")
	inputs[1].Lock = &lockfile.Entry{Ref: inputs[1].Ref, Source: lockfile.SourcePath, Resolved: "packages/local"}
	out := newRunnerR(loader, skipsOn(SourceRegistry)).Run(context.Background(), inputs)
	if source.earlyRead.Load() {
		t.Fatal("registry Versions ran before bulk preparation completed")
	}
	if source.preloadRuns != 1 || !slices.Equal(source.requested, []string{"first", "second"}) {
		t.Fatalf("bulk preparation calls=%d names=%v, want one call for the two registry Cargo inputs", source.preloadRuns, source.requested)
	}
	if source.count("versions") != 2 {
		t.Fatalf("Cargo Versions called %d times, want two and no local-directory lookup", source.count("versions"))
	}
	if len(out) != len(inputs) || out[0].Ref.Version != "1.0.0" {
		t.Fatalf("resolution did not preserve outcomes or resolve the bare ref: %+v", out)
	}
	for _, n := range []int{0, 2, 3} {
		if !slices.Equal(out[n].Evaluated, []string{"TD001"}) || len(out[n].Skipped) != 0 {
			t.Errorf("registry input %s: evaluated=%v skipped=%v", out[n].Ref, out[n].Evaluated, out[n].Skipped)
		}
	}
	if reason := skippedReasonsR(&out[1])["TD001"]; !strings.Contains(reason, "directory of the project") {
		t.Fatalf("local input skip=%q, want an explicit local-source explanation", reason)
	}
}

func TestRunnerPrefetchVersionsFailureRemainsUnavailable(t *testing.T) {
	source := &bulkVersionsSourceR{
		fakeSourceR: newFakeSourceR(model.Cargo),
		preloadErr:  errors.New("dump shard checksum mismatch"),
	}
	source.add(stableListR(model.Cargo, "first", "1.0.0"))
	loader := newDataLoader(registry.Registry{model.Cargo: source}, nil, nil, nil)
	out := newRunnerR(loader, skipsOn(SourceRegistry)).Run(context.Background(), inputsR("cargo:first", "cargo:first@1.0.0"))
	if len(out) != 2 {
		t.Fatalf("got %d outcomes, want both requested inputs", len(out))
	}
	for n := range out {
		if len(out[n].Evaluated) != 0 || len(out[n].Findings) != 0 {
			t.Errorf("failed bulk preparation produced evaluated checks: %+v", out[n])
		}
		if reason := skippedReasonsR(&out[n])["TD001"]; !strings.Contains(reason, "dump shard checksum mismatch") {
			t.Errorf("skip=%q, want the bulk source failure", reason)
		}
	}
}

func TestRunnerPrefetchVersionsReceivesCancellation(t *testing.T) {
	source := &bulkVersionsSourceR{fakeSourceR: newFakeSourceR(model.Cargo)}
	source.add(stableListR(model.Cargo, "first", "1.0.0"))
	loader := newDataLoader(registry.Registry{model.Cargo: source}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := newRunnerR(loader, skipsOn(SourceRegistry)).Run(ctx, inputsR("cargo:first"))
	if !errors.Is(source.contextErr, context.Canceled) {
		t.Fatalf("bulk source context error=%v, want context.Canceled", source.contextErr)
	}
	if len(out) != 1 || len(out[0].Evaluated) != 0 || len(out[0].Skipped) != 1 {
		t.Fatalf("canceled preparation must leave the input skipped: %+v", out)
	}
	if reason := out[0].Skipped[0].Reason; !strings.Contains(reason, "context canceled") {
		t.Fatalf("canceled input skip=%q", reason)
	}
}

func TestRunnerPrefetchVersionsOrdinaryAPISourceUnchanged(t *testing.T) {
	source := newFakeSourceR(model.Cargo)
	source.add(stableListR(model.Cargo, "first", "1.0.0"))
	loader := newDataLoader(registry.Registry{model.Cargo: source}, nil, nil, nil)
	out := newRunnerR(loader, skipsOn(SourceRegistry)).Run(context.Background(), inputsR("cargo:first", "cargo:first@1.0.0"))
	if len(out) != 2 || source.count("versions") != 1 {
		t.Fatalf("ordinary source outcomes=%d versions calls=%d, want two outcomes and one memoized API lookup", len(out), source.count("versions"))
	}
	for n := range out {
		if out[n].Ref.Version != "1.0.0" || !slices.Equal(out[n].Evaluated, []string{"TD001"}) || len(out[n].Skipped) != 0 {
			t.Errorf("ordinary API behavior changed: %+v", out[n])
		}
	}
}

func TestRunnerPrefetchVersionsIsOptionalForExistingLoaders(t *testing.T) {
	loader := libLoaderR()
	out := newRunnerR(loader, skipsOn(SourceRegistry)).Run(context.Background(), inputsR("npm:lib"))
	if len(out) != 1 || out[0].Ref.Version != "2.0.0" || !slices.Equal(out[0].Evaluated, []string{"TD001"}) {
		t.Fatalf("loader without PrefetchVersions did not retain normal resolution: %+v", out)
	}
	if loader.prefetchCalls() != 1 {
		t.Fatalf("ordinary advisory prefetch calls=%d, want one", loader.prefetchCalls())
	}
}
