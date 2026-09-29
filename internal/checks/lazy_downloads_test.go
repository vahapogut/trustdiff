package checks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/registry/npm"
)

// npmCountsSource uses a real npm counts client and fake package metadata, so
// request assertions cover the runner, loader and npm batching without fixtures
// for unrelated registry fields. The HTTP answers below are synthetic.
type npmCountsSource struct {
	*fakeSourceR
	counts *npm.Client
}

func (s npmCountsSource) Downloads(ctx context.Context, name string) (int64, error) {
	return s.counts.Downloads(ctx, name)
}

func (s npmCountsSource) BulkDownloads(ctx context.Context, names []string) (map[string]int64, error) {
	return s.counts.BulkDownloads(ctx, names)
}

func TestLazyDownloadsRequestOnlyWhatThePolicyUses(t *testing.T) {
	off := model.LevelOff
	zero := int64(0)
	allow := policy.AllowEntry{Check: "low-usage", Package: policy.MustParsePattern("npm:@scope/*"), Reason: "reviewed internal packages"}
	expired := allow
	expired.Expires = policy.Date{Year: 2025, Month: time.January, Day: 1}
	tests := []struct {
		name         string
		pol          *policy.Policy
		wantRequests int
		wantLow      bool
		wantAllowed  bool
	}{
		{name: "default low usage retains the scoped requests", wantRequests: 3, wantLow: true},
		{name: "off needs no counts for names without candidates", pol: &policy.Policy{Checks: map[string]policy.CheckConfig{"low-usage": {Level: &off}}}},
		{name: "active scoped allows retain the unscoped batch", pol: &policy.Policy{Allow: []policy.AllowEntry{allow}}, wantRequests: 1, wantAllowed: true},
		{name: "expired scoped allows request counts again", pol: &policy.Policy{Allow: []policy.AllowEntry{expired}}, wantRequests: 3, wantLow: true},
		{name: "zero threshold preserves registry precedence over fallback", pol: &policy.Policy{Checks: map[string]policy.CheckConfig{"low-usage": {MinWeeklyDownloads: &zero}}}, wantRequests: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var requests []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, r.URL.Path)
				mu.Unlock()
				names := strings.Split(strings.TrimPrefix(r.URL.Path, "/downloads/point/last-week/"), ",")
				count := func(name string) map[string]any {
					n := 1000
					if strings.HasPrefix(name, "@") {
						n = 42
					}
					return map[string]any{"package": name, "downloads": n}
				}
				var body any
				if len(names) == 1 {
					body = count(names[0])
				} else {
					bulk := map[string]any{}
					for _, name := range names {
						bulk[name] = count(name)
					}
					body = bulk
				}
				if err := json.NewEncoder(w).Encode(body); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			h, err := httpcache.New(httpcache.Options{NoCache: true, UserAgent: "trustdiff-test", Retries: -1})
			if err != nil {
				t.Fatal(err)
			}
			source := newFakeSourceR(model.NPM)
			names := []string{"@scope/quartz", "@scope/velocity", "unrelated-alpha", "unrelated-bravo"}
			dd := newFakeDepsDevR()
			var inputs []Input
			for _, name := range names {
				list := stableListR(model.NPM, name, "1.0.0", "2.0.0")
				source.add(list)
				for _, version := range list.Versions {
					inputs = append(inputs, Input{Ref: version.Ref})
					dd.findings[version.Ref] = []depsdev.Finding{{Type: "LOW_USAGE"}}
				}
			}
			loader := newDataLoader(registry.Registry{model.NPM: npmCountsSource{source, npm.New(h, npm.WithDownloadsURL(srv.URL))}}, nil, dd, nil)
			r := newRunnerR(loader, newTyposquatT(), lowUsage{})
			r.Policy = tt.pol
			out := r.Evaluate(t.Context(), inputs)
			if len(requests) != tt.wantRequests {
				t.Fatalf("counts requests = %v, want %d", requests, tt.wantRequests)
			}
			if tt.wantRequests > 0 && !slices.Contains(requests, "/downloads/point/last-week/unrelated-alpha,unrelated-bravo") {
				t.Errorf("unscoped names were not batched: %v", requests)
			}
			for i := range out {
				s := &out[i].Subject
				scoped := strings.HasPrefix(s.Ref.Name, "@")
				wantLow := tt.wantLow && scoped
				if got := slices.Contains(findingIDsR(s), "TD012"); got != wantLow {
					t.Errorf("%s findings = %v, want low-usage %v", s.Ref, findingIDsR(s), wantLow)
				}
				if tt.wantAllowed && scoped {
					if !strings.Contains(skippedReasonsR(s)["TD012"], "allow entry") || slices.Contains(s.Evaluated, "TD012") || out[i].Unavailable {
						t.Errorf("allowed check must be a policy skip: %+v", out[i])
					}
				}
			}
		})
	}
}

func TestGenericPrefetchDoesNotRequestDownloads(t *testing.T) {
	source := &bulkSourceR{fakeSourceR: newFakeSourceR(model.NPM)}
	loader := newDataLoader(registry.Registry{model.NPM: source}, nil, nil, nil)
	loader.Prefetch(t.Context(), []model.PackageRef{model.MustParseRef("npm:lib@1.0.0")})
	if source.bulkCalls != 0 || source.count("downloads") != 0 {
		t.Fatal("generic prefetch asked for download counts")
	}
}

func TestLazyDownloadsOutageRemainsUnavailable(t *testing.T) {
	loader := libLoaderR()
	loader.fail[SourceDownloads] = errors.New("counts service unreachable")
	r := newRunnerR(loader, lowUsage{})
	out := r.Evaluate(t.Context(), inputsR("npm:lib@1.0.0"))
	if !out[0].Unavailable || !strings.Contains(skippedReasonsR(&out[0].Subject)["TD012"], "counts service unreachable") {
		t.Fatalf("download outage lost its unavailable status: %+v", out[0])
	}
}

func TestLazyDownloadsFailedBatchDoesNotRetryPerPackage(t *testing.T) {
	source := newFakeSourceR(model.NPM)
	source.add(stableListR(model.NPM, "lib", "1.0.0", "2.0.0"))
	bulk := &bulkSourceR{fakeSourceR: source, bulkErr: errors.New("counts service rejected the batch")}
	loader := newDataLoader(registry.Registry{model.NPM: bulk}, nil, nil, nil)
	out := newRunnerR(loader, lowUsage{}).Evaluate(t.Context(), inputsR("npm:lib@1.0.0", "npm:lib@2.0.0"))
	if bulk.bulkCalls != 1 || source.count("downloads") != 0 {
		t.Fatalf("batch calls %d, individual calls %d", bulk.bulkCalls, source.count("downloads"))
	}
	for _, got := range out {
		if !got.Unavailable || !strings.Contains(skippedReasonsR(&got.Subject)["TD012"], "rejected the batch") {
			t.Errorf("failed count was not reported as unavailable: %+v", got)
		}
	}
}

func TestLazyTyposquatCountsAreSharedWithLowUsage(t *testing.T) {
	source := newFakeSourceR(model.NPM)
	list := stableListR(model.NPM, "crossenv", "1.0.0", "2.0.0")
	for i := range list.Versions {
		list.Versions[i].PublishedAt = nowR.AddDate(-2, 0, i)
	}
	source.add(list)
	source.downloads["crossenv"] = 1000
	source.downloads["cross-env"] = 10000
	bulk := &bulkSourceR{fakeSourceR: source}
	loader := newDataLoader(registry.Registry{model.NPM: bulk}, nil, nil, nil)
	out := newRunnerR(loader, newTyposquatT(), lowUsage{}).Evaluate(t.Context(), inputsR("npm:crossenv@1.0.0", "npm:crossenv@2.0.0"))
	if bulk.bulkCalls != 1 || source.count("downloads") != 1 {
		t.Fatalf("want one candidate batch and one neighbor request shared across versions, got %d and %d", bulk.bulkCalls, source.count("downloads"))
	}
	for _, got := range out {
		if len(got.Subject.Findings) != 1 || got.Subject.Findings[0].ID != "TD008" || got.Subject.Findings[0].Level != model.LevelWarn {
			t.Errorf("count sharing changed the findings: %+v", got)
		}
	}
}

func TestLazyTyposquatActiveAllowNeedsNoDownloads(t *testing.T) {
	loader := libLoaderR()
	list := stableListR(model.NPM, "crossenv", "1.0.0")
	list.Versions[0].PublishedAt = nowR.AddDate(-2, 0, 0)
	loader.add(list)
	r := newRunnerR(loader, newTyposquatT())
	r.Policy = &policy.Policy{Allow: []policy.AllowEntry{{Check: "typosquat-suspect", Package: policy.MustParsePattern("npm:crossenv"), Reason: "reviewed look-alike"}}}
	out := r.Evaluate(t.Context(), inputsR("npm:crossenv@1.0.0"))
	if loader.count("downloads") != 0 || len(out[0].Subject.Findings) != 0 || !strings.Contains(skippedReasonsR(&out[0].Subject)["TD008"], "allow entry") {
		t.Fatalf("allowed typo check fetched or evaluated: %+v, calls %d", out[0], loader.count("downloads"))
	}
}

func TestLazyTyposquatNonListNeighborStillComparesCounts(t *testing.T) {
	loader := &fakeLoaderT{similar: []depsdev.Similar{{Name: "left-pad"}}, downloads: map[string]int64{"leftpad-fork": 10, "left-pad": 2000000}}
	s := subjectT("npm:leftpad-fork@1.0.0", loader, -1)
	result := newTyposquatT().Run(t.Context(), s)
	if len(result.Findings) != 1 || result.Findings[0].Evidence["deps_dev_neighbor"] != "left-pad" {
		t.Fatalf("lazy counts lost the non-list neighbor finding: %+v", result)
	}
	if want := []string{"similar npm:leftpad-fork", "downloads npm:leftpad-fork", "downloads npm:left-pad"}; !slices.Equal(loader.calls, want) {
		t.Errorf("calls = %v, want %v", loader.calls, want)
	}
}

func TestLazyDownloadsErrorDoesNotMutateSubject(t *testing.T) {
	loader := libLoaderR()
	loader.fail[SourceDownloads] = errors.New("counts down")
	s := subjectT("npm:lib@1.0.0", loader, -1)
	s.Unavailable = map[string]error{SourceOwners: errors.New("owners down")}
	result := lowUsage{}.Run(t.Context(), s)
	if !result.Unavailable || s.Downloads != -1 || len(s.Unavailable) != 1 || s.Unavailable[SourceDownloads] != nil {
		t.Fatalf("lazy failure mutated the subject or lost its outage: %+v, %+v", s, result)
	}
}

type cancelCountsSource struct {
	*fakeSourceR
	started chan struct{}
	calls   atomic.Int32
}

func (s *cancelCountsSource) Downloads(ctx context.Context, _ string) (int64, error) {
	if s.calls.Add(1) == 1 {
		close(s.started)
		<-ctx.Done()
		return -1, ctx.Err()
	}
	return 1000, nil
}

func TestLazyDownloadsCancellationLeavesNoPoisonedMemo(t *testing.T) {
	source := &cancelCountsSource{fakeSourceR: newFakeSourceR(model.NPM), started: make(chan struct{})}
	loader := newDataLoader(registry.Registry{model.NPM: source}, nil, nil, nil)
	s := subjectT("npm:lib@1.0.0", loader, -1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan Result, 1)
	go func() { finished <- (lowUsage{}).Run(ctx, s) }()
	select {
	case <-source.started:
	case <-time.After(time.Second):
		t.Fatal("download did not start")
	}
	cancel()
	select {
	case result := <-finished:
		if !result.Unavailable || result.Skipped == nil {
			t.Fatalf("canceled count passed: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("download ignored cancellation")
	}
	result := lowUsage{}.Run(t.Context(), s)
	if result.Skipped != nil || len(result.Findings) != 0 || source.calls.Load() != 2 || s.Downloads != -1 {
		t.Fatalf("canceled count poisoned the next check: %+v, calls %d", result, source.calls.Load())
	}
}

func TestLazyDownloadsKeepIntroducedDependencyEscalationWithLowUsageOff(t *testing.T) {
	source := newFakeSourceR(model.NPM)
	parent := stableListR(model.NPM, "lib", "1.0.0", "2.0.0")
	parent.Versions[1].Dependencies = map[string]string{"plain-crypto-js": "^1.0.0"}
	source.add(parent)
	dep := stableListR(model.NPM, "plain-crypto-js", "1.0.0")
	dep.Versions[0].Publisher = &model.Publisher{Name: "different-author"}
	source.add(dep)
	source.downloads["plain-crypto-js"] = 12
	bulk := &bulkSourceR{fakeSourceR: source}
	loader := newDataLoader(registry.Registry{model.NPM: bulk}, nil, newFakeDepsDevR(), nil)
	r := newRunnerR(loader, td007{}, lowUsage{})
	off := model.LevelOff
	r.Policy = &policy.Policy{Checks: map[string]policy.CheckConfig{"low-usage": {Level: &off}}}
	out := r.Evaluate(t.Context(), inputsR("npm:lib@2.0.0"))
	if bulk.bulkCalls != 0 || source.count("downloads") != 1 {
		t.Fatalf("want only the introduced dependency's count, got %d batches and %d point requests", bulk.bulkCalls, source.count("downloads"))
	}
	if len(out[0].Subject.Findings) != 1 || out[0].Subject.Findings[0].ID != "TD007" || out[0].Subject.Findings[0].Level != model.LevelBlock {
		t.Fatalf("lazy counts lost introduced dependency escalation: %+v", out[0])
	}
}

func TestLazyTyposquatDownloadsKeepTheStandingDecision(t *testing.T) {
	tests := []struct {
		name      string
		days      int
		wantCalls int
		wantLevel model.Level
	}{
		{name: "young candidate needs no count", days: 1, wantLevel: model.LevelBlock},
		{name: "old candidate needs counts to demote", days: 400, wantCalls: 2, wantLevel: model.LevelWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := &fakeLoaderT{downloads: map[string]int64{"crossenv": 1000, "cross-env": 10000}}
			s := subjectT("npm:crossenv@1.0.0", loader, -1)
			s.Package = &registry.VersionList{Versions: []model.VersionInfo{{Ref: s.Ref, PublishedAt: s.Now.AddDate(0, 0, -tt.days)}}}
			res := newTyposquatT().Run(t.Context(), s)
			if len(res.Findings) != 1 || res.Findings[0].Level != tt.wantLevel {
				t.Fatalf("result = %+v", res)
			}
			calls := 0
			for _, call := range loader.calls {
				if strings.HasPrefix(call, "downloads ") {
					calls++
				}
			}
			if calls != tt.wantCalls {
				t.Errorf("downloads calls = %v, want %d", loader.calls, tt.wantCalls)
			}
			if s.Downloads != -1 || len(s.Unavailable) != 0 {
				t.Fatal("lazy loading mutated the shared subject")
			}
		})
	}
}
