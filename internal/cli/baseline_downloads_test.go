package cli

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/baseline"
	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/model"
)

type baselineCountsLoader struct {
	*fakeLoader
	selected        []model.PackageRef
	readBeforeBatch bool
}

func (l *baselineCountsLoader) PrefetchDownloads(_ context.Context, refs []model.PackageRef) {
	l.selected = slices.Clone(refs)
}

func (l *baselineCountsLoader) Downloads(context.Context, model.Ecosystem, string) (int64, error) {
	if len(l.selected) == 0 {
		l.readBeforeBatch = true
	}
	return 42, nil
}

func TestBaselineForwardsPolicySelectedCountsBeforeLowUsage(t *testing.T) {
	now := time.Date(2026, time.September, 29, 0, 0, 0, 0, time.UTC)
	loader := &baselineCountsLoader{fakeLoader: &fakeLoader{now: now}}
	ref := model.MustParseRef("npm:trustdiff-fixture-lib@2.0.0")
	check, ok := checks.Lookup("TD012")
	if !ok {
		t.Fatal("TD012 not registered")
	}
	r := checks.Runner{Loader: withBaseline(loader, &baseline.Set{}), Checks: []checks.Check{check}, Now: now}
	out := r.Evaluate(t.Context(), []checks.Input{{Ref: ref}})
	if loader.readBeforeBatch || !slices.Equal(loader.selected, []model.PackageRef{ref}) {
		t.Fatalf("baseline lost counts batching: selected %v, read first %v", loader.selected, loader.readBeforeBatch)
	}
	if len(out[0].Subject.Findings) != 1 || out[0].Subject.Findings[0].ID != "TD012" {
		t.Fatalf("low-usage lost the count through baseline: %+v", out[0])
	}
}
