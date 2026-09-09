package checks

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
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
	l.Prefetch(context.Background(), []model.PackageRef{one, two, one, model.MustParseRef("npm:bare"), {Ecosystem: model.NPM, Name: "LIB", Version: "1.0.0"}})
	if adv.count("advisories") != 1 {
		t.Fatalf("advisory source called %d times by Prefetch, want 1", adv.count("advisories"))
	}
	if want := []model.PackageRef{one, two}; !slices.Equal(adv.batches[0], want) {
		t.Errorf("batch = %v, want %v (deduplicated, normalized, versioned refs only)", adv.batches[0], want)
	}

	got, err := l.Advisories(context.Background(), one)
	if err != nil || len(got) != 1 || got[0].ID != "GHSA-1" {
		t.Errorf("Advisories(one) = %v, %v; want GHSA-1 from the batch", got, err)
	}
	got, err = l.Advisories(context.Background(), two)
	if err != nil || len(got) != 0 {
		t.Errorf("Advisories(two) = %v, %v; want none and no error for a ref absent from the batch result", got, err)
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
	if _, err := l.DepsDev(context.Background(), deno); !errors.Is(err, depsdev.ErrUnsupported) {
		t.Errorf("DepsDev(deno) = %v, want depsdev.ErrUnsupported", err)
	}
	if _, err := l.DepsDevFindings(context.Background(), deno); !errors.Is(err, depsdev.ErrUnsupported) {
		t.Errorf("DepsDevFindings(deno) = %v, want depsdev.ErrUnsupported", err)
	}
	if _, err := l.SimilarNames(context.Background(), model.Deno, "std"); !errors.Is(err, depsdev.ErrUnsupported) {
		t.Errorf("SimilarNames(deno) = %v, want depsdev.ErrUnsupported", err)
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

func TestLoaderSimilarNamesMemoized(t *testing.T) {
	dd := newFakeDepsDevR()
	dd.similar["lib"] = []depsdev.Similar{{Name: "lіb", Popularity: 9}}
	l, _ := npmLoaderR(nil, dd)
	for range 3 {
		got, err := l.SimilarNames(context.Background(), model.NPM, "LIB")
		if err != nil || len(got) != 1 {
			t.Fatalf("SimilarNames = %v, %v", got, err)
		}
	}
	if dd.count("similar") != 1 {
		t.Errorf("deps.dev similar called %d times, want 1", dd.count("similar"))
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
