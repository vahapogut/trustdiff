package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/registry/jsr"
)

// A run whose clock is pinned with TRUSTDIFF_NOW must read the same weekly
// download figure whenever it is repeated, and the JSR client is the one source
// that measures a window against a clock of its own. The loader is an interface,
// so the client it holds cannot be reached from here; what is asserted instead is
// the options the loader builds it from. Finding F25 of
// docs/review-2026-09-10.md.
func TestTheRunsClockReachesTheJSRClient(t *testing.T) {
	// One daily bucket, five years before any wall clock this test will run under.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":[{"timeBucket":"2020-01-01T00:00:00Z","kind":"jsr_meta","count":5}]}`))
	}))
	t.Cleanup(srv.Close)

	downloads := func(t *testing.T, now time.Time) int64 {
		t.Helper()
		hc, err := httpcache.New(httpcache.Options{
			Dir:       t.TempDir(),
			UserAgent: "trustdiff/test (+https://github.com/vahapogut/trustdiff)",
			Retries:   -1,
		})
		if err != nil {
			t.Fatalf("httpcache.New: %v", err)
		}
		opts := append(jsrOptions(nil, now), jsr.WithRegistryBase(srv.URL), jsr.WithAPIBase(srv.URL))
		got, err := jsr.New(hc, opts...).Downloads(context.Background(), "@std/fs")
		if err != nil {
			t.Fatalf("Downloads: %v", err)
		}
		return got
	}

	if got := downloads(t, time.Date(2020, 1, 3, 0, 0, 0, 0, time.UTC)); got != 5 {
		t.Errorf("weekly downloads = %d for a run pinned two days after the bucket, want 5", got)
	}
	// No override: the week is this week, and a bucket from 2020 is not in it.
	if got := downloads(t, time.Time{}); got != 0 {
		t.Errorf("weekly downloads = %d for a run on the wall clock, want 0", got)
	}
}
