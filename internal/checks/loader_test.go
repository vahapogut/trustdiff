package checks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/advisory/osv"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// npmLoaderR returns a loader over one npm source that knows lib at 1.0.0 and 1.1.0.
func npmLoaderR(adv advisory.Source, dd depsDevSource) (*DataLoader, *fakeSourceR) {
	src := newFakeSourceR(model.NPM)
	src.add(stableListR(model.NPM, "lib", "1.0.0", "1.1.0"))
	src.owners["lib"] = []model.Publisher{{Name: "alice"}}
	src.downloads["lib"] = 42
	return newDataLoader(registry.Registry{model.NPM: src}, adv, dd, nil), src
}

// concurrentlyR runs fn n times at once and returns the errors.
func concurrentlyR(n int, fn func() error) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = fn()
		}()
	}
	wg.Wait()
	return errs
}

func TestLoaderMemoizesPerKey(t *testing.T) {
	ctx := context.Background()
	ref := model.MustParseRef("npm:lib@1.0.0")
	tests := []struct {
		name string
		what string
		call func(l *DataLoader) error
	}{
		{name: "versions", what: "versions", call: func(l *DataLoader) error {
			_, err := l.Versions(ctx, model.NPM, "lib")
			return err
		}},
		{name: "version info", what: "info", call: func(l *DataLoader) error {
			_, err := l.VersionInfo(ctx, ref)
			return err
		}},
		{name: "owners", what: "owners", call: func(l *DataLoader) error {
			_, err := l.Owners(ctx, model.NPM, "lib")
			return err
		}},
		{name: "downloads", what: "downloads", call: func(l *DataLoader) error {
			_, err := l.Downloads(ctx, model.NPM, "lib")
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, src := npmLoaderR(nil, nil)
			for _, err := range concurrentlyR(20, func() error { return tt.call(l) }) {
				if err != nil {
					t.Fatalf("call failed: %v", err)
				}
			}
			if err := tt.call(l); err != nil {
				t.Fatalf("later call failed: %v", err)
			}
			if got := src.count(tt.what); got != 1 {
				t.Errorf("source called %d times, want 1", got)
			}
		})
	}
}

func TestLoaderMemoizesErrors(t *testing.T) {
	boom := errors.New("registry down")
	l, src := npmLoaderR(nil, nil)
	src.err = boom
	errs := concurrentlyR(10, func() error {
		_, err := l.Versions(context.Background(), model.NPM, "lib")
		return err
	})
	for _, err := range errs {
		if !errors.Is(err, boom) {
			t.Fatalf("Versions error = %v, want the source error", err)
		}
	}
	if _, err := l.Versions(context.Background(), model.NPM, "lib"); !errors.Is(err, boom) {
		t.Fatalf("later Versions error = %v, want the memoized source error", err)
	}
	if got := src.count("versions"); got != 1 {
		t.Errorf("a failing source was asked %d times, want 1", got)
	}

	// A registry that does not provide downloads is asked once as well.
	l, src = npmLoaderR(nil, nil)
	delete(src.downloads, "lib")
	for range 3 {
		if _, err := l.Downloads(context.Background(), model.NPM, "lib"); !errors.Is(err, registry.ErrUnsupported) {
			t.Fatalf("Downloads error = %v, want ErrUnsupported", err)
		}
	}
	if got := src.count("downloads"); got != 1 {
		t.Errorf("unsupported downloads asked %d times, want 1", got)
	}
}

func TestLoaderSharesInFlightRequest(t *testing.T) {
	l, src := npmLoaderR(nil, nil)
	src.gate = make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := l.Versions(context.Background(), model.NPM, "lib")
			results <- err
		}()
	}
	// Wait until the first caller is inside the source, then make sure the second
	// one is waiting on it instead of fetching too.
	deadline := time.Now().Add(2 * time.Second)
	for src.count("versions") == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if got := src.count("versions"); got != 1 {
		t.Fatalf("source called %d times while one request was in flight, want 1", got)
	}
	close(src.gate)
	for range 2 {
		if err := <-results; err != nil {
			t.Errorf("Versions error = %v", err)
		}
	}
	if got := src.count("versions"); got != 1 {
		t.Errorf("source called %d times in total, want 1", got)
	}
}

func TestLoaderCallerCancellationDoesNotPoisonTheMemo(t *testing.T) {
	l, src := npmLoaderR(nil, nil)
	src.gate = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := l.Versions(ctx, model.NPM, "lib"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Versions under an expired context = %v, want DeadlineExceeded", err)
	}
	close(src.gate)
	list, err := l.Versions(context.Background(), model.NPM, "lib")
	if err != nil || list == nil {
		t.Fatalf("Versions after the source recovered = %v, %v; want the list", list, err)
	}
	if got := src.count("versions"); got != 2 {
		t.Errorf("source called %d times, want 2: the canceled attempt must not be memoized", got)
	}
}

func TestLoaderWaiterStopsOnItsOwnContext(t *testing.T) {
	l, src := npmLoaderR(nil, nil)
	src.gate = make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, err := l.Versions(context.Background(), model.NPM, "lib")
		first <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for src.count("versions") == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := l.Versions(ctx, model.NPM, "lib"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter error = %v, want DeadlineExceeded", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the waiter did not return when its own context ended")
	}
	close(src.gate)
	if err := <-first; err != nil {
		t.Errorf("first caller error = %v, want success", err)
	}
	if got := src.count("versions"); got != 1 {
		t.Errorf("source called %d times, want 1", got)
	}
}

func TestLoaderUnsupportedEcosystem(t *testing.T) {
	l, src := npmLoaderR(nil, nil)
	ctx := context.Background()
	cargo := model.MustParseRef("cargo:serde@1.0.0")
	tests := []struct {
		name string
		call func() error
	}{
		{name: "versions", call: func() error { _, err := l.Versions(ctx, model.Cargo, "serde"); return err }},
		{name: "version info", call: func() error { _, err := l.VersionInfo(ctx, cargo); return err }},
		{name: "owners", call: func() error { _, err := l.Owners(ctx, model.Cargo, "serde"); return err }},
		{name: "downloads", call: func() error { _, err := l.Downloads(ctx, model.Cargo, "serde"); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, registry.ErrUnsupported) {
				t.Errorf("error = %v, want registry.ErrUnsupported", err)
			}
		})
	}
	if got := src.count("versions") + src.count("info") + src.count("owners") + src.count("downloads"); got != 0 {
		t.Errorf("the npm source was called %d times for cargo refs, want 0", got)
	}
}

func TestLoaderNormalizesNames(t *testing.T) {
	src := newFakeSourceR(model.PyPI)
	src.add(stableListR(model.PyPI, "requests-toolbelt", "1.0.0"))
	l := newDataLoader(registry.Registry{model.PyPI: src}, nil, nil, nil)
	for _, name := range []string{"Requests_Toolbelt", "requests.toolbelt", "requests-toolbelt"} {
		if _, err := l.Versions(context.Background(), model.PyPI, name); err != nil {
			t.Fatalf("Versions(%q) = %v", name, err)
		}
	}
	if got := src.count("versions"); got != 1 {
		t.Errorf("source called %d times for three spellings of one name, want 1", got)
	}
	if !slices.Equal(src.seen, []string{"requests-toolbelt"}) {
		t.Errorf("source saw %v, want the PEP 503 spelling only", src.seen)
	}
	if _, err := l.VersionInfo(context.Background(), model.PackageRef{Ecosystem: model.PyPI, Name: "Requests_Toolbelt", Version: "1.0.0"}); err != nil {
		t.Errorf("VersionInfo with a non-canonical name = %v, want the normalized lookup to succeed", err)
	}
}

func TestLoaderPrefetchAdvisories(t *testing.T) {
	adv := newFakeAdvisoriesR()
	one := model.MustParseRef("npm:lib@1.0.0")
	two := model.MustParseRef("npm:lib@1.1.0")
	adv.results[one] = []advisory.Advisory{{ID: "GHSA-1"}}
	l, _ := npmLoaderR(adv, nil)
	deno := model.MustParseRef("deno:std@1.0.0")
	// npm names keep their case: LIB is a package of its own, not a duplicate of
	// lib, and OSV indexes it that way too.
	upper := model.PackageRef{Ecosystem: model.NPM, Name: "LIB", Version: "1.0.0"}
	l.Prefetch(context.Background(), []model.PackageRef{one, two, one, model.MustParseRef("npm:bare"), upper, deno})
	if adv.count("advisories") != 1 {
		t.Fatalf("advisory source called %d times by Prefetch, want 1", adv.count("advisories"))
	}
	if want := []model.PackageRef{one, two, upper}; !slices.Equal(adv.batches[0], want) {
		t.Errorf("batch = %v, want %v (deduplicated, versioned refs of indexed ecosystems only)", adv.batches[0], want)
	}

	got, err := l.Advisories(context.Background(), one)
	if err != nil || len(got) != 1 || got[0].ID != "GHSA-1" {
		t.Errorf("Advisories(one) = %v, %v; want GHSA-1 from the batch", got, err)
	}
	got, err = l.Advisories(context.Background(), two)
	if err != nil || len(got) != 0 {
		t.Errorf("Advisories(two) = %v, %v; want none and no error for a ref absent from the batch result", got, err)
	}
	// The source drops refs of ecosystems it does not index from a mixed batch;
	// the loader must not read that silence as "no advisories".
	if _, err := l.Advisories(context.Background(), deno); !errors.Is(err, osv.ErrUnsupported) || !errors.Is(err, registry.ErrUnsupported) {
		t.Errorf("Advisories(deno) after a mixed Prefetch = %v, want an error wrapping osv.ErrUnsupported and registry.ErrUnsupported", err)
	}
	if adv.count("advisories") != 1 {
		t.Errorf("advisory source called %d times after prefetched lookups, want still 1", adv.count("advisories"))
	}

	three := model.MustParseRef("npm:dep@3.0.0")
	adv.results[three] = []advisory.Advisory{{ID: "MAL-1", Malicious: true}}
	got, err = l.Advisories(context.Background(), three)
	if err != nil || len(got) != 1 || !got[0].Malicious {
		t.Errorf("Advisories(three) = %v, %v; want the on-demand result", got, err)
	}
	if adv.count("advisories") != 2 || !slices.Equal(adv.batches[1], []model.PackageRef{three}) {
		t.Errorf("on-demand lookup: calls %d batches %v, want one extra single-ref batch", adv.count("advisories"), adv.batches)
	}
}

func TestLoaderPrefetchBatchFailureIsMemoized(t *testing.T) {
	adv := newFakeAdvisoriesR()
	adv.err = errors.New("osv down")
	dd := newFakeDepsDevR()
	dd.err = errors.New("deps.dev down")
	l, _ := npmLoaderR(adv, dd)
	refs := []model.PackageRef{model.MustParseRef("npm:lib@1.0.0"), model.MustParseRef("npm:lib@1.1.0")}
	l.Prefetch(context.Background(), refs)
	for _, ref := range refs {
		if _, err := l.Advisories(context.Background(), ref); !errors.Is(err, adv.err) {
			t.Errorf("Advisories(%s) = %v, want the batch error", ref, err)
		}
		if _, err := l.DepsDev(context.Background(), ref); !errors.Is(err, dd.err) {
			t.Errorf("DepsDev(%s) = %v, want the batch error", ref, err)
		}
		if _, err := l.DepsDevFindings(context.Background(), ref); !errors.Is(err, dd.err) {
			t.Errorf("DepsDevFindings(%s) = %v, want the batch error", ref, err)
		}
	}
	if adv.count("advisories") != 1 || dd.count("versions") != 1 || dd.count("findings") != 1 {
		t.Errorf("calls after a failed batch: osv %d, deps.dev versions %d, findings %d; want 1 each", adv.count("advisories"), dd.count("versions"), dd.count("findings"))
	}
}

func TestLoaderPrefetchUnderCanceledContextStoresNothing(t *testing.T) {
	adv := newFakeAdvisoriesR()
	ref := model.MustParseRef("npm:lib@1.0.0")
	adv.results[ref] = []advisory.Advisory{{ID: "GHSA-1"}}
	l, _ := npmLoaderR(adv, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.Prefetch(ctx, []model.PackageRef{ref})
	got, err := l.Advisories(context.Background(), ref)
	if err != nil || len(got) != 1 {
		t.Errorf("Advisories after a canceled Prefetch = %v, %v; want a fresh successful fetch", got, err)
	}
	if adv.count("advisories") != 2 {
		t.Errorf("advisory source called %d times, want 2", adv.count("advisories"))
	}
}

func TestLoaderPrefetchDepsDev(t *testing.T) {
	dd := newFakeDepsDevR()
	one := model.MustParseRef("npm:lib@1.0.0")
	two := model.MustParseRef("npm:lib@1.1.0")
	deno := model.MustParseRef("deno:std@0.1.0")
	dd.facts[one] = depsdev.VersionFacts{Found: true, AttestationVerified: true}
	dd.findings[one] = []depsdev.Finding{{Type: "MALICIOUS", Risk: "RISK_CRITICAL"}}
	src := newFakeSourceR(model.NPM)
	l := newDataLoader(registry.Registry{model.NPM: src}, nil, dd, nil)
	l.Prefetch(context.Background(), []model.PackageRef{one, two, deno})
	for _, what := range []string{"versions", "findings"} {
		if dd.count(what) != 1 {
			t.Fatalf("deps.dev %s called %d times by Prefetch, want 1", what, dd.count(what))
		}
		if want := []model.PackageRef{one, two}; !slices.Equal(dd.batches[what][0], want) {
			t.Errorf("deps.dev %s batch = %v, want %v (deno is not indexed)", what, dd.batches[what][0], want)
		}
	}

	facts, err := l.DepsDev(context.Background(), one)
	if err != nil || facts == nil || !facts.AttestationVerified {
		t.Errorf("DepsDev(one) = %+v, %v; want the verified facts", facts, err)
	}
	facts, err = l.DepsDev(context.Background(), two)
	if err != nil || facts == nil || facts.Found {
		t.Errorf("DepsDev(two) = %+v, %v; want Found false for a version deps.dev did not list", facts, err)
	}
	findings, err := l.DepsDevFindings(context.Background(), one)
	if err != nil || len(findings) != 1 || findings[0].Type != "MALICIOUS" {
		t.Errorf("DepsDevFindings(one) = %v, %v; want MALICIOUS", findings, err)
	}
	findings, err = l.DepsDevFindings(context.Background(), two)
	if err != nil || len(findings) != 0 {
		t.Errorf("DepsDevFindings(two) = %v, %v; want none", findings, err)
	}
	// An ecosystem deps.dev does not index is a definite answer: the error matches
	// the deps.dev sentinel and registry.ErrUnsupported alike.
	if _, err := l.DepsDev(context.Background(), deno); !errors.Is(err, depsdev.ErrUnsupported) || !errors.Is(err, registry.ErrUnsupported) {
		t.Errorf("DepsDev(deno) = %v, want depsdev.ErrUnsupported and registry.ErrUnsupported", err)
	}
	if _, err := l.DepsDevFindings(context.Background(), deno); !errors.Is(err, depsdev.ErrUnsupported) || !errors.Is(err, registry.ErrUnsupported) {
		t.Errorf("DepsDevFindings(deno) = %v, want depsdev.ErrUnsupported and registry.ErrUnsupported", err)
	}
	if _, err := l.SimilarNames(context.Background(), model.Deno, "std"); !errors.Is(err, depsdev.ErrUnsupported) || !errors.Is(err, registry.ErrUnsupported) {
		t.Errorf("SimilarNames(deno) = %v, want depsdev.ErrUnsupported and registry.ErrUnsupported", err)
	}
	if dd.count("versions") != 1 || dd.count("findings") != 1 || dd.count("similar") != 0 {
		t.Errorf("deps.dev calls after prefetched lookups: versions %d findings %d similar %d; want 1, 1, 0", dd.count("versions"), dd.count("findings"), dd.count("similar"))
	}

	three := model.MustParseRef("npm:dep@3.0.0")
	if _, err := l.DepsDev(context.Background(), three); err != nil {
		t.Errorf("on-demand DepsDev = %v", err)
	}
	if dd.count("versions") != 2 || !slices.Equal(dd.batches["versions"][1], []model.PackageRef{three}) {
		t.Errorf("on-demand facts: calls %d batches %v, want one extra single-ref batch", dd.count("versions"), dd.batches["versions"])
	}
}

// A mixed batch of indexed and unindexed refs must give every ref the same
// answer it would get on its own: the OSV client leaves unindexed refs out of
// its map and returns ErrUnsupported only when every ref was unindexed, so a
// loader that stored "no advisories" for the whole batch turned a jsr subject
// into a false pass whenever an npm ref shared the command line.
func TestLoaderMixedPrefetchReportsUnsupportedRefs(t *testing.T) {
	adv := newFakeAdvisoriesR()
	lib := model.MustParseRef("npm:lib@1.0.0")
	jsr := model.MustParseRef("jsr:@std/path@1.0.0")
	adv.results[lib] = []advisory.Advisory{{ID: "GHSA-1"}}
	l, _ := npmLoaderR(adv, nil)
	l.Prefetch(context.Background(), []model.PackageRef{lib, jsr})
	if !slices.Equal(adv.batches[0], []model.PackageRef{lib}) {
		t.Errorf("batch = %v, want the npm ref only", adv.batches[0])
	}
	if got, err := l.Advisories(context.Background(), lib); err != nil || len(got) != 1 {
		t.Errorf("Advisories(lib) = %v, %v; want GHSA-1", got, err)
	}
	got, err := l.Advisories(context.Background(), jsr)
	if !errors.Is(err, osv.ErrUnsupported) {
		t.Fatalf("Advisories(jsr) = %v, %v; want an error wrapping osv.ErrUnsupported, not a silent empty answer", got, err)
	}
	if !errors.Is(err, registry.ErrUnsupported) {
		t.Errorf("Advisories(jsr) = %v, want it to match registry.ErrUnsupported too", err)
	}
	if !strings.Contains(err.Error(), "jsr: ecosystem not indexed by OSV") {
		t.Errorf("error text = %q, want it to name the ecosystem and the source", err)
	}
	if adv.count("advisories") != 1 {
		t.Errorf("advisory source called %d times, want 1: an unindexed ref is answered without a request", adv.count("advisories"))
	}
	// A fresh loader asked on demand agrees.
	l, _ = npmLoaderR(newFakeAdvisoriesR(), nil)
	if _, err := l.Advisories(context.Background(), jsr); !errors.Is(err, osv.ErrUnsupported) {
		t.Errorf("on-demand Advisories(jsr) = %v, want osv.ErrUnsupported", err)
	}
}

// A failed batch is worth a warning on stderr when the source could not be
// reached; an expected condition is stated in the report already and only goes
// to the debug log, so an offline run does not print three warnings.
func TestLoaderBatchFailureLogLevel(t *testing.T) {
	ref := model.MustParseRef("npm:lib@1.0.0")
	tests := []struct {
		name     string
		err      error
		wantWarn bool
	}{
		{name: "outage", err: errors.New("503 after 3 attempts"), wantWarn: true},
		{name: "offline miss", err: fmt.Errorf("GET https://osv.example/querybatch: %w", httpcache.ErrOffline)},
		{name: "not indexed", err: fmt.Errorf("osv: %w: jsr", osv.ErrUnsupported)},
		{name: "not configured", err: fmt.Errorf("osv: %w", ErrNotConfigured)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			adv := newFakeAdvisoriesR()
			adv.err = tt.err
			dd := newFakeDepsDevR()
			dd.err = tt.err
			src := newFakeSourceR(model.NPM)
			l := newDataLoader(registry.Registry{model.NPM: src}, adv, dd, log)
			l.Prefetch(context.Background(), []model.PackageRef{ref})
			if _, err := l.Advisories(context.Background(), ref); !errors.Is(err, tt.err) {
				t.Errorf("Advisories = %v, want the batch error memoized whatever the log level", err)
			}
			warned := strings.Contains(buf.String(), "level=WARN")
			if warned != tt.wantWarn {
				t.Errorf("stderr = %q, want a warning: %v", buf.String(), tt.wantWarn)
			}
			if tt.wantWarn {
				for _, msg := range []string{"advisory batch failed", "deps.dev version batch failed", "deps.dev findings batch failed"} {
					if !strings.Contains(buf.String(), msg) {
						t.Errorf("stderr lacks %q:\n%s", msg, buf.String())
					}
				}
			}
		})
	}
}

func TestLoaderSimilarNamesMemoized(t *testing.T) {
	dd := newFakeDepsDevR()
	dd.similar["lib"] = []depsdev.Similar{{Name: "lіb", Popularity: 9}}
	l, _ := npmLoaderR(nil, dd)
	for range 3 {
		got, err := l.SimilarNames(context.Background(), model.NPM, "lib")
		if err != nil || len(got) != 1 {
			t.Fatalf("SimilarNames = %v, %v", got, err)
		}
	}
	if dd.count("similar") != 1 {
		t.Errorf("deps.dev similar called %d times, want 1", dd.count("similar"))
	}
	// A different spelling is a different npm package, so it is a lookup of its own.
	if _, err := l.SimilarNames(context.Background(), model.NPM, "LIB"); err != nil {
		t.Fatalf("SimilarNames(LIB) = %v", err)
	}
	if dd.count("similar") != 2 {
		t.Errorf("deps.dev similar called %d times after asking for LIB, want 2", dd.count("similar"))
	}
}

func TestLoaderWithoutOptionalSources(t *testing.T) {
	src := newFakeSourceR(model.NPM)
	src.add(stableListR(model.NPM, "lib", "1.0.0"))
	ref := model.MustParseRef("npm:lib@1.0.0")
	tests := []struct {
		name   string
		loader *DataLoader
	}{
		{name: "nil interfaces", loader: NewLoader(registry.Registry{model.NPM: src}, nil, nil, nil)},
		{name: "typed nil deps.dev client", loader: NewLoader(registry.Registry{model.NPM: src}, nil, (*depsdev.Client)(nil), nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := tt.loader
			l.Prefetch(context.Background(), []model.PackageRef{ref})
			if _, err := l.Advisories(context.Background(), ref); !errors.Is(err, ErrNotConfigured) {
				t.Errorf("Advisories = %v, want ErrNotConfigured", err)
			}
			if _, err := l.DepsDev(context.Background(), ref); !errors.Is(err, ErrNotConfigured) {
				t.Errorf("DepsDev = %v, want ErrNotConfigured", err)
			}
			if _, err := l.DepsDevFindings(context.Background(), ref); !errors.Is(err, ErrNotConfigured) {
				t.Errorf("DepsDevFindings = %v, want ErrNotConfigured", err)
			}
			if _, err := l.SimilarNames(context.Background(), model.NPM, "lib"); !errors.Is(err, ErrNotConfigured) {
				t.Errorf("SimilarNames = %v, want ErrNotConfigured", err)
			}
			if _, err := l.VersionInfo(context.Background(), ref); err != nil {
				t.Errorf("VersionInfo = %v, want the registry to keep working", err)
			}
		})
	}
}

func TestLoaderRequiresVersion(t *testing.T) {
	l, src := npmLoaderR(newFakeAdvisoriesR(), newFakeDepsDevR())
	bare := model.MustParseRef("npm:lib")
	tests := []struct {
		name string
		call func() error
	}{
		{name: "version info", call: func() error { _, err := l.VersionInfo(context.Background(), bare); return err }},
		{name: "advisories", call: func() error { _, err := l.Advisories(context.Background(), bare); return err }},
		{name: "deps.dev facts", call: func() error { _, err := l.DepsDev(context.Background(), bare); return err }},
		{name: "deps.dev findings", call: func() error { _, err := l.DepsDevFindings(context.Background(), bare); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, ErrNoVersion) {
				t.Errorf("error = %v, want ErrNoVersion", err)
			}
		})
	}
	if got := src.count("info"); got != 0 {
		t.Errorf("source asked %d times for a bare ref, want 0", got)
	}
}

func TestLoaderVersionNotFound(t *testing.T) {
	l, _ := npmLoaderR(nil, nil)
	_, err := l.VersionInfo(context.Background(), model.MustParseRef("npm:lib@9.9.9"))
	if !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("VersionInfo(unknown) = %v, want registry.ErrNotFound", err)
	}
	if err == nil || err.Error() != "version info of npm:lib@9.9.9: not found in the registry" {
		t.Errorf("error text = %q, want the ref in the message", err)
	}
}

// A batch that answered some refs and lost others comes back as those answers plus
// an *advisory.PartialError. Storing the batch error for every ref, as the loader
// used to, reported an OSV outage for packages OSV had answered for, and every
// check that reads OSV would then skip for them instead of saying what came back.
func TestLoaderPrefetchPartialFailurePoisonsOnlyTheLostRefs(t *testing.T) {
	adv := newFakeAdvisoriesR()
	answered := model.MustParseRef("npm:lib@1.0.0")
	lost := model.MustParseRef("npm:lib@1.1.0")
	boom := errors.New("osv querybatch chunk failed")
	adv.results[answered] = []advisory.Advisory{{ID: "MAL-1", Malicious: true}}
	adv.lose = map[model.PackageRef]error{lost: boom}
	l, _ := npmLoaderR(adv, nil)
	l.Prefetch(context.Background(), []model.PackageRef{answered, lost})

	got, err := l.Advisories(context.Background(), answered)
	if err != nil || len(got) != 1 || !got[0].Malicious {
		t.Errorf("Advisories(%s) = %v, %v; want the advisory the batch did answer", answered, got, err)
	}
	if _, err := l.Advisories(context.Background(), lost); !errors.Is(err, boom) {
		t.Errorf("Advisories(%s) = %v, want the error that lost the ref", lost, err)
	}
	if adv.count("advisories") != 1 {
		t.Errorf("advisory source called %d times, want 1: both answers were memoized by Prefetch", adv.count("advisories"))
	}
}

// bulkSourceR answers many names in one call, the way the npm client does, and
// counts how often it was asked.
type bulkSourceR struct {
	*fakeSourceR
	bulkCalls int
	asked     [][]string
	bulkErr   error
}

func (b *bulkSourceR) BulkDownloads(_ context.Context, names []string) (map[string]int64, error) {
	b.bulkCalls++
	b.asked = append(b.asked, append([]string(nil), names...))
	if b.bulkErr != nil {
		return nil, b.bulkErr
	}
	out := make(map[string]int64, len(names))
	for _, name := range names {
		if n, ok := b.downloads[name]; ok {
			out[name] = n
		}
	}
	return out, nil
}

// A scan of a large lockfile asked the counts API once per package. On npm/cli's
// 1201 entry package-lock.json, evaluated live on 2026-09-12, api.npmjs.org
// answered 1684 of those requests with 429 and the client spent the run backing
// off and retrying. The counts API takes up to 128 names in one request, which is
// what Prefetch now uses, so the per name path is left with the names a batch
// cannot carry and the ones it did not know.
func TestPrefetchAsksTheCountsApiOnceForTheWholeRun(t *testing.T) {
	src := newFakeSourceR(model.NPM)
	src.add(stableListR(model.NPM, "lib", "1.0.0"))
	src.add(stableListR(model.NPM, "other", "2.0.0"))
	src.downloads["lib"] = 42
	src.downloads["other"] = 7
	bulk := &bulkSourceR{fakeSourceR: src}
	l := newDataLoader(registry.Registry{model.NPM: bulk}, nil, nil, nil)

	refs := []model.PackageRef{
		model.MustParseRef("npm:lib@1.0.0"),
		model.MustParseRef("npm:other@2.0.0"),
		model.MustParseRef("npm:lib@1.0.0"),
		model.MustParseRef("npm:unknown@3.0.0"),
	}
	l.Prefetch(t.Context(), refs)

	if bulk.bulkCalls != 1 {
		t.Fatalf("the counts API was asked %d times, want once for the whole run", bulk.bulkCalls)
	}
	if want := []string{"lib", "other", "unknown"}; !slices.Equal(bulk.asked[0], want) {
		t.Errorf("asked for %v, want %v, each name once and in first seen order", bulk.asked[0], want)
	}

	// What the batch answered is answered from the memo, without a second request.
	for _, tc := range []struct {
		name string
		want int64
	}{{"lib", 42}, {"other", 7}} {
		got, err := l.Downloads(t.Context(), model.NPM, tc.name)
		if err != nil || got != tc.want {
			t.Errorf("Downloads(%s) = %d, %v, want %d", tc.name, got, err, tc.want)
		}
	}
	if n := src.count("downloads"); n != 0 {
		t.Errorf("the per name path was used %d times for names the batch answered", n)
	}

	// A name the batch did not know is not an answer, so the per name path asks and
	// reports what it gets. Leaving it in the memo as zero would read as a package
	// nobody installs, which is what the low usage check is about.
	if _, err := l.Downloads(t.Context(), model.NPM, "unknown"); err == nil {
		t.Error("a name the batch did not know returned no error")
	}
	if n := src.count("downloads"); n != 1 {
		t.Errorf("the per name path was used %d times for the unknown name, want once", n)
	}
}

// A batch that fails used to leave every name to the per name path, which is how
// one refused request became a thousand. api.npmjs.org answers a scan of a large
// lockfile with 429 and then with Cloudflare's 1015, which blocks the address
// altogether: measured on 2026-09-12, after which even one request per second and
// the batch form itself were refused. So a failed batch is an answer about every
// name it carried: the checks that read counts report themselves as skipped, which
// a policy can fail the run on, and nothing asks again.
func TestPrefetchDoesNotFallBackToOneRequestPerPackage(t *testing.T) {
	src := newFakeSourceR(model.NPM)
	src.add(stableListR(model.NPM, "lib", "1.0.0"))
	src.downloads["lib"] = 42
	bulk := &bulkSourceR{fakeSourceR: src, bulkErr: errors.New("429 Too Many Requests")}
	l := newDataLoader(registry.Registry{model.NPM: bulk}, nil, nil, nil)

	l.Prefetch(t.Context(), []model.PackageRef{model.MustParseRef("npm:lib@1.0.0")})
	if bulk.bulkCalls != 1 {
		t.Fatalf("the batch was asked %d times, want once", bulk.bulkCalls)
	}

	_, err := l.Downloads(t.Context(), model.NPM, "lib")
	if err == nil {
		t.Error("a name whose batch failed returned a count, and the batch answered nothing")
	}
	if n := src.count("downloads"); n != 0 {
		t.Errorf("the per name path was used %d times after the batch failed, which is the storm this prevents", n)
	}
}
