package httpcache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is the injected Now function; tests advance it to expire entries.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// sleepRecorder replaces the retry sleep so tests assert delays without waiting.
type sleepRecorder struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (s *sleepRecorder) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.delays = append(s.delays, d)
	s.mu.Unlock()
	return ctx.Err()
}

func (s *sleepRecorder) recorded() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.delays...)
}

// testServer counts requests and keeps the last request's method, headers and
// body, plus every body it received in order, so retries can be checked.
type testServer struct {
	*httptest.Server
	calls      atomic.Int32
	mu         sync.Mutex
	lastMethod string
	lastReq    http.Header
	lastBody   []byte
	bodies     [][]byte
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *testServer {
	t.Helper()
	ts := &testServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.calls.Add(1)
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		ts.mu.Lock()
		ts.lastMethod = r.Method
		ts.lastReq = r.Header.Clone()
		ts.lastBody = data
		ts.bodies = append(ts.bodies, data)
		ts.mu.Unlock()
		// The handler may read the body again, as a real one would.
		r.Body = io.NopCloser(bytes.NewReader(data))
		handler(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *testServer) method() string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.lastMethod
}

func (ts *testServer) body() []byte {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]byte(nil), ts.lastBody...)
}

func (ts *testServer) allBodies() [][]byte {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	out := make([][]byte, 0, len(ts.bodies))
	for _, b := range ts.bodies {
		out = append(out, append([]byte(nil), b...))
	}
	return out
}

func (ts *testServer) host(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func (ts *testServer) header(key string) string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.lastReq.Get(key)
}

// testEnv bundles a client with its injected clock, sleep recorder and directory.
type testEnv struct {
	client *Client
	clock  *fakeClock
	sleeps *sleepRecorder
	dir    string
}

func newTestEnv(t *testing.T, ts *testServer, mutate func(*Options)) *testEnv {
	t.Helper()
	env := &testEnv{clock: newFakeClock(), sleeps: &sleepRecorder{}, dir: t.TempDir()}
	opts := Options{
		Dir:       env.dir,
		UserAgent: "trustdiff/test (+https://github.com/vahapogut/trustdiff)",
		Now:       env.clock.now,
		HostRPS:   map[string]float64{},
	}
	if ts != nil {
		// A high rate keeps the limiter out of the way unless a test lowers it.
		opts.HostRPS[ts.host(t)] = 10000
	}
	if mutate != nil {
		mutate(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.sleep = env.sleeps.sleep
	env.client = c
	return env
}

func okHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func entryFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestNewValidatesOptions(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{name: "missing user agent", opts: Options{Dir: t.TempDir()}, wantErr: "UserAgent"},
		{name: "negative header timeout", opts: Options{Dir: t.TempDir(), UserAgent: "x", HeaderTimeout: -1}, wantErr: "HeaderTimeout"},
		{name: "negative body timeout", opts: Options{Dir: t.TempDir(), UserAgent: "x", BodyTimeout: -1}, wantErr: "BodyTimeout"},
		{name: "zero host rate", opts: Options{Dir: t.TempDir(), UserAgent: "x", HostRPS: map[string]float64{"a": 0}}, wantErr: "HostRPS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New() error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	c, err := New(Options{Dir: t.TempDir(), UserAgent: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if c.headerTimeout != 10*time.Second {
		t.Errorf("header timeout = %v, want 10s", c.headerTimeout)
	}
	if c.bodyTimeout != 45*time.Second {
		t.Errorf("body timeout = %v, want 45s", c.bodyTimeout)
	}
	if c.retries != 3 {
		t.Errorf("retries = %d, want 3", c.retries)
	}
	if got := c.limiterFor("crates.io").Limit(); got != 1 {
		t.Errorf("crates.io limit = %v, want 1 request per second", got)
	}
	if got := c.limiterFor("registry.npmjs.org").Limit(); got != 10 {
		t.Errorf("default limit = %v, want 10 requests per second", got)
	}
	if _, err := os.Stat(c.Dir()); err != nil {
		t.Errorf("New did not create the cache directory: %v", err)
	}
}

func TestNewCreatesDirUnlessNoCache(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "cache")
	if _, err := New(Options{Dir: dir, UserAgent: "x", NoCache: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("NoCache client created %s", dir)
	}
	if _, err := New(Options{Dir: dir, UserAgent: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cache directory not created: %v", err)
	}
}

// TestNewNoCacheDoesNotNeedUserCacheDir covers minimal CI containers and users
// without a home directory: a client that never touches the cache must not fail
// because the platform cache directory cannot be located.
func TestNewNoCacheDoesNotNeedUserCacheDir(t *testing.T) {
	t.Setenv(EnvDir, "")
	if runtime.GOOS == "windows" {
		t.Setenv("LocalAppData", "")
	} else {
		t.Setenv("HOME", "")
		t.Setenv("XDG_CACHE_HOME", "")
	}
	if _, err := os.UserCacheDir(); err == nil {
		t.Skip("os.UserCacheDir still resolves on this platform")
	}
	c, err := New(Options{UserAgent: "x", NoCache: true})
	if err != nil {
		t.Fatalf("New with NoCache must not need the user cache directory: %v", err)
	}
	if c.Dir() != "" {
		t.Errorf("Dir() = %q, want empty for a NoCache client without Options.Dir", c.Dir())
	}
	if _, err := New(Options{UserAgent: "x"}); err == nil {
		t.Fatal("New without NoCache must report the missing user cache directory")
	}
}

func TestGetSendsUserAgentAcceptAndHeaders(t *testing.T) {
	ts := newTestServer(t, okHandler(`{}`))
	env := newTestEnv(t, ts, nil)
	tests := []struct {
		name       string
		req        Request
		wantAccept string
		wantExtra  string
	}{
		{name: "explicit accept", req: Request{Accept: "application/vnd.npm.install-v1+json"}, wantAccept: "application/vnd.npm.install-v1+json"},
		{name: "default accept", req: Request{}, wantAccept: "*/*"},
		{name: "extra header", req: Request{Header: http.Header{"X-Test": {"yes"}}}, wantAccept: "*/*", wantExtra: "yes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := ts.URL + "/" + strings.ReplaceAll(tt.name, " ", "-")
			if _, err := env.client.Get(context.Background(), u, tt.req); err != nil {
				t.Fatal(err)
			}
			if got := ts.header("User-Agent"); got != "trustdiff/test (+https://github.com/vahapogut/trustdiff)" {
				t.Errorf("User-Agent = %q", got)
			}
			if got := ts.header("Accept"); got != tt.wantAccept {
				t.Errorf("Accept = %q, want %q", got, tt.wantAccept)
			}
			if got := ts.header("X-Test"); got != tt.wantExtra {
				t.Errorf("X-Test = %q, want %q", got, tt.wantExtra)
			}
		})
	}
}

func TestGetRejectsBadURLs(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	for _, u := range []string{"", "not a url", "ftp://example.com/x", "/relative", "http://"} {
		if _, err := env.client.Get(context.Background(), u, Request{}); err == nil {
			t.Errorf("Get(%q) succeeded, want an error", u)
		}
	}
}

func TestGetFreshHitSkipsTheNetwork(t *testing.T) {
	ts := newTestServer(t, okHandler(`{"name":"express"}`))
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()

	first, err := env.client.Get(ctx, ts.URL+"/express", Request{Accept: "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	if first.FromCache || first.StatusCode != 200 || string(first.Body) != `{"name":"express"}` {
		t.Fatalf("first = %+v", first)
	}
	if !first.FetchedAt.Equal(env.clock.now()) {
		t.Errorf("FetchedAt = %v, want %v", first.FetchedAt, env.clock.now())
	}

	env.clock.advance(30 * time.Minute)
	second, err := env.client.Get(ctx, ts.URL+"/express", Request{Accept: "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	if !second.FromCache || !bytes.Equal(second.Body, first.Body) || second.StatusCode != 200 {
		t.Fatalf("second = %+v", second)
	}
	if got := second.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("cached Content-Type = %q", got)
	}
	if got := ts.calls.Load(); got != 1 {
		t.Fatalf("server calls = %d, want 1", got)
	}
	names := entryFiles(t, env.dir)
	if len(names) != 2 {
		t.Fatalf("cache files = %v, want one metadata and one body file", names)
	}
	for _, n := range names {
		if !entryFileName.MatchString(n) || strings.HasSuffix(n, ".tmp") {
			t.Errorf("unexpected file %q", n)
		}
	}
}

func TestGetAcceptIsPartOfTheKey(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("Accept")))
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	full, err := env.client.Get(ctx, ts.URL+"/p", Request{Accept: "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	abbrev, err := env.client.Get(ctx, ts.URL+"/p", Request{Accept: "application/vnd.npm.install-v1+json"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(full.Body, abbrev.Body) || abbrev.FromCache {
		t.Fatalf("different Accept values shared an entry: %q vs %q", full.Body, abbrev.Body)
	}
	if got := ts.calls.Load(); got != 2 {
		t.Fatalf("server calls = %d, want 2", got)
	}
}

func TestGetRevalidatesExpiredEntries(t *testing.T) {
	tests := []struct {
		name       string
		validator  string // response header the server sets
		condHeader string // request header the client must send back
	}{
		{name: "etag", validator: "ETag", condHeader: "If-None-Match"},
		{name: "last modified", validator: "Last-Modified", condHeader: "If-Modified-Since"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := `"v1"`
			if tt.validator == "Last-Modified" {
				value = "Tue, 08 Sep 2026 10:00:00 GMT"
			}
			ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(tt.condHeader) == value {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				w.Header().Set(tt.validator, value)
				_, _ = w.Write([]byte("body-v1"))
			})
			env := newTestEnv(t, ts, nil)
			ctx := context.Background()
			u := ts.URL + "/pkg"

			if _, err := env.client.Get(ctx, u, Request{TTL: time.Hour}); err != nil {
				t.Fatal(err)
			}
			env.clock.advance(2 * time.Hour)
			resp, err := env.client.Get(ctx, u, Request{TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			if got := ts.header(tt.condHeader); got != value {
				t.Errorf("%s = %q, want %q", tt.condHeader, got, value)
			}
			if !resp.FromCache || string(resp.Body) != "body-v1" || resp.StatusCode != 200 {
				t.Fatalf("revalidated response = %+v", resp)
			}
			if !resp.FetchedAt.Equal(env.clock.now()) {
				t.Errorf("FetchedAt not refreshed by 304: %v", resp.FetchedAt)
			}
			if got := ts.calls.Load(); got != 2 {
				t.Fatalf("server calls = %d, want 2", got)
			}

			// The 304 refreshed the metadata, so the entry is fresh again.
			env.clock.advance(30 * time.Minute)
			if _, err := env.client.Get(ctx, u, Request{TTL: time.Hour}); err != nil {
				t.Fatal(err)
			}
			if got := ts.calls.Load(); got != 2 {
				t.Fatalf("server calls after refresh = %d, want 2", got)
			}
		})
	}
}

func TestGetExpiredEntryReplacedByNewBody(t *testing.T) {
	var version atomic.Int32
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if version.Load() == 0 {
			_, _ = w.Write([]byte("old"))
			return
		}
		_, _ = w.Write([]byte("new"))
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	if _, err := env.client.Get(ctx, ts.URL, Request{}); err != nil {
		t.Fatal(err)
	}
	version.Store(1)
	env.clock.advance(2 * time.Hour)
	resp, err := env.client.Get(ctx, ts.URL, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.FromCache || string(resp.Body) != "new" {
		t.Fatalf("response = %+v", resp)
	}
	env.clock.advance(time.Minute)
	resp, err = env.client.Get(ctx, ts.URL, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.FromCache || string(resp.Body) != "new" {
		t.Fatalf("cached response = %+v", resp)
	}
}

func TestGetForeverNeverExpires(t *testing.T) {
	ts := newTestServer(t, okHandler("immutable"))
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	if _, err := env.client.Get(ctx, ts.URL, Request{TTL: Forever}); err != nil {
		t.Fatal(err)
	}
	env.clock.advance(10 * 365 * 24 * time.Hour)
	resp, err := env.client.Get(ctx, ts.URL, Request{TTL: Forever})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.FromCache || ts.calls.Load() != 1 {
		t.Fatalf("Forever entry was refetched: %+v, calls %d", resp, ts.calls.Load())
	}
}

// TestGetRequestTTLGovernsFreshness pins that the TTL of the current request, not
// the one stored by whichever caller wrote the entry, decides whether the entry is
// served without revalidation.
func TestGetRequestTTLGovernsFreshness(t *testing.T) {
	ts := newTestServer(t, okHandler("body"))
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()

	if _, err := env.client.Get(ctx, ts.URL, Request{TTL: Forever}); err != nil {
		t.Fatal(err)
	}
	env.clock.advance(time.Hour)
	resp, err := env.client.Get(ctx, ts.URL, Request{TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if resp.FromCache || ts.calls.Load() != 2 {
		t.Fatalf("a Forever entry was served to a caller asking for 1m: %+v, calls %d", resp, ts.calls.Load())
	}
	// The refetch stored the entry again, and a long TTL is satisfied by it.
	env.clock.advance(time.Minute)
	if resp, err := env.client.Get(ctx, ts.URL, Request{TTL: Forever}); err != nil || !resp.FromCache {
		t.Fatalf("fresh entry not served under Forever: %+v, %v", resp, err)
	}

	// The same holds between two finite TTLs.
	env.clock.advance(10 * time.Minute)
	if resp, err := env.client.Get(ctx, ts.URL, Request{TTL: time.Hour}); err != nil || !resp.FromCache {
		t.Fatalf("11m old entry not served under 1h: %+v, %v", resp, err)
	}
	resp, err = env.client.Get(ctx, ts.URL, Request{TTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if resp.FromCache || ts.calls.Load() != 3 {
		t.Fatalf("11m old entry served under 5m: %+v, calls %d", resp, ts.calls.Load())
	}
}

func TestGetCaches404(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	resp, err := env.client.Get(ctx, ts.URL+"/missing", Request{})
	if err != nil {
		t.Fatalf("404 must be a response, not an error: %v", err)
	}
	if resp.StatusCode != 404 || resp.FromCache {
		t.Fatalf("response = %+v", resp)
	}
	again, err := env.client.Get(ctx, ts.URL+"/missing", Request{})
	if err != nil {
		t.Fatal(err)
	}
	if again.StatusCode != 404 || !again.FromCache || ts.calls.Load() != 1 {
		t.Fatalf("second 404 = %+v, calls %d", again, ts.calls.Load())
	}
}

// TestGet404IsNeverCachedForever covers a version fetched before the registry
// replicated it, or mistyped once: the negative answer must expire even when the
// caller asked for Forever, so the positive answer can replace it.
func TestGet404IsNeverCachedForever(t *testing.T) {
	var published atomic.Bool
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !published.Load() {
			http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
			return
		}
		okHandler(`{"version":"1.0.0"}`)(w, r)
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	u := ts.URL + "/pkg/1.0.0"

	first, err := env.client.Get(ctx, u, Request{TTL: Forever})
	if err != nil || first.StatusCode != http.StatusNotFound {
		t.Fatalf("first = %+v, %v", first, err)
	}
	// Within DefaultTTL the 404 is a cache hit like any other answer.
	env.clock.advance(30 * time.Minute)
	hit, err := env.client.Get(ctx, u, Request{TTL: Forever})
	if err != nil || !hit.FromCache || hit.StatusCode != http.StatusNotFound || ts.calls.Load() != 1 {
		t.Fatalf("404 within DefaultTTL: %+v, %v, calls %d", hit, err, ts.calls.Load())
	}

	published.Store(true)
	env.clock.advance(2 * time.Hour)
	second, err := env.client.Get(ctx, u, Request{TTL: Forever})
	if err != nil {
		t.Fatal(err)
	}
	if second.FromCache || second.StatusCode != http.StatusOK || ts.calls.Load() != 2 {
		t.Fatalf("a 404 stored under Forever was pinned: %+v, calls %d", second, ts.calls.Load())
	}
	// The 200 that replaced it is immutable as requested.
	env.clock.advance(30 * time.Minute)
	third, err := env.client.Get(ctx, u, Request{TTL: Forever})
	if err != nil || !third.FromCache || third.StatusCode != http.StatusOK || ts.calls.Load() != 2 {
		t.Fatalf("200 after the 404: %+v, %v, calls %d", third, err, ts.calls.Load())
	}
}

// TestGet404RefreshedBy304IsNotPinned covers the other write path: a 404 with a
// validator that the server confirms with 304 must keep expiring after the refresh.
func TestGet404RefreshedBy304IsNotPinned(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"gone"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"gone"`)
		http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	u := ts.URL + "/pkg/9.9.9"

	if _, err := env.client.Get(ctx, u, Request{TTL: Forever}); err != nil {
		t.Fatal(err)
	}
	env.clock.advance(2 * time.Hour)
	resp, err := env.client.Get(ctx, u, Request{TTL: Forever})
	if err != nil || !resp.FromCache || resp.StatusCode != http.StatusNotFound || ts.calls.Load() != 2 {
		t.Fatalf("revalidated 404 = %+v, %v, calls %d", resp, err, ts.calls.Load())
	}
	env.clock.advance(2 * time.Hour)
	if _, err := env.client.Get(ctx, u, Request{TTL: Forever}); err != nil {
		t.Fatal(err)
	}
	if got := ts.calls.Load(); got != 3 {
		t.Fatalf("server calls = %d, want 3: the 304 refresh must not pin the 404", got)
	}
	// The stored TTL, which cache status reports, carries the cap as well.
	for _, n := range entryFiles(t, env.dir) {
		if !strings.HasSuffix(n, metaSuffix) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(env.dir, n))
		if err != nil {
			t.Fatal(err)
		}
		meta, err := parseMeta(data)
		if err != nil {
			t.Fatal(err)
		}
		if meta.TTL != DefaultTTL {
			t.Fatalf("stored TTL for a 404 = %v, want %v", meta.TTL, DefaultTTL)
		}
	}
}

func TestGetDoesNotCacheOtherStatuses(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		noCache bool
		wantErr bool
	}{
		{name: "204", status: http.StatusNoContent},
		{name: "403", status: http.StatusForbidden, wantErr: true},
		{name: "410", status: http.StatusGone, wantErr: true},
		// A 304 is only meaningful as the answer to a conditional request; on a
		// miss and with NoCache no validators were sent, so it is a server error.
		{name: "304 on a miss", status: http.StatusNotModified, wantErr: true},
		{name: "304 with NoCache", status: http.StatusNotModified, noCache: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			env := newTestEnv(t, ts, func(o *Options) { o.NoCache = tt.noCache })
			ctx := context.Background()
			resp, err := env.client.Get(ctx, ts.URL, Request{})
			var se *StatusError
			switch {
			case tt.wantErr && (!errors.As(err, &se) || se.StatusCode != tt.status || se.URL != ts.URL):
				t.Fatalf("err = %v, want *StatusError with %d", err, tt.status)
			case !tt.wantErr && (err != nil || resp.StatusCode != tt.status):
				t.Fatalf("resp = %+v, err = %v", resp, err)
			}
			if _, err := env.client.Get(ctx, ts.URL, Request{}); err == nil != !tt.wantErr {
				t.Fatalf("second Get err = %v", err)
			}
			if got := ts.calls.Load(); got != 2 {
				t.Fatalf("server calls = %d, want 2 (status %d must not be cached)", got, tt.status)
			}
			if names := entryFiles(t, env.dir); len(names) != 0 {
				t.Fatalf("cache files = %v, want none", names)
			}
		})
	}
}

func TestGetRetriesThenSucceeds(t *testing.T) {
	var n atomic.Int32
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		okHandler("recovered")(w, r)
	})
	env := newTestEnv(t, ts, nil)
	resp, err := env.client.Get(context.Background(), ts.URL, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "recovered" || ts.calls.Load() != 2 {
		t.Fatalf("resp = %+v, calls = %d", resp, ts.calls.Load())
	}
	delays := env.sleeps.recorded()
	if len(delays) != 1 || delays[0] <= 0 {
		t.Fatalf("sleeps = %v, want one positive backoff", delays)
	}
}

func TestGetBackoffGrowsAndIsCapped(t *testing.T) {
	c, err := New(Options{Dir: t.TempDir(), UserAgent: "x"})
	if err != nil {
		t.Fatal(err)
	}
	// Each attempt has a deterministic window: the upper half of the doubled base,
	// capped at maxBackoff. A backoff that stops growing fails at attempt 1 and a
	// missing cap fails from attempt 7 on.
	for attempt := range 12 {
		d := c.backoff(attempt, 0)
		want := min(baseBackoff<<min(attempt, 7), maxBackoff)
		if d < want/2 || d > want {
			t.Fatalf("attempt %d: backoff %v outside [%v, %v]", attempt, d, want/2, want)
		}
	}
	if got := c.backoff(0, 7*time.Second); got != 7*time.Second {
		t.Fatalf("Retry-After 7s gave %v", got)
	}
	if got := c.backoff(0, 10*time.Minute); got != maxRetryAfter {
		t.Fatalf("Retry-After 10m gave %v, want the cap %v", got, maxRetryAfter)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "", want: 0},
		{value: " ", want: 0},
		{value: "abc", want: 0},
		{value: "-5", want: 0},
		{value: "0", want: 0},
		{value: "7.5", want: 0},
		{value: "7", want: 7 * time.Second},
		{value: " 7 ", want: 7 * time.Second},
		{value: now.Add(-time.Minute).Format(http.TimeFormat), want: 0},
		{value: now.Format(http.TimeFormat), want: 0},
		{value: now.Add(30 * time.Second).Format(http.TimeFormat), want: 30 * time.Second},
		// Huge values are clamped before the multiplication so they cannot
		// overflow into a negative duration; backoff caps them anyway.
		{value: "9223372036854775807", want: maxRetryAfter},
		{value: "99999999999999999999", want: maxRetryAfter},
		{value: "-99999999999999999999", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if got := parseRetryAfter(tt.value, now); got != tt.want {
				t.Fatalf("parseRetryAfter(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestGetHonorsRetryAfter(t *testing.T) {
	clock := newFakeClock()
	httpDate := clock.now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	tests := []struct {
		name       string
		retryAfter string
		want       time.Duration
	}{
		{name: "seconds", retryAfter: "7", want: 7 * time.Second},
		{name: "http date", retryAfter: httpDate, want: 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var n atomic.Int32
			ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if n.Add(1) == 1 {
					w.Header().Set("Retry-After", tt.retryAfter)
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				okHandler("ok")(w, r)
			})
			env := newTestEnv(t, ts, func(o *Options) { o.Now = clock.now })
			if _, err := env.client.Get(context.Background(), ts.URL, Request{}); err != nil {
				t.Fatal(err)
			}
			if delays := env.sleeps.recorded(); len(delays) != 1 || delays[0] != tt.want {
				t.Fatalf("sleeps = %v, want [%v]", delays, tt.want)
			}
		})
	}
}

func TestGetGivesUpAfterRetries(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{name: "429", status: http.StatusTooManyRequests},
		{name: "502", status: http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			env := newTestEnv(t, ts, func(o *Options) { o.Retries = 2 })
			_, err := env.client.Get(context.Background(), ts.URL, Request{})
			var se *StatusError
			if !errors.As(err, &se) || se.StatusCode != tt.status {
				t.Fatalf("err = %v, want *StatusError %d", err, tt.status)
			}
			if got := ts.calls.Load(); got != 3 {
				t.Fatalf("server calls = %d, want 1 attempt + 2 retries", got)
			}
			if got := len(env.sleeps.recorded()); got != 2 {
				t.Fatalf("sleeps = %d, want 2", got)
			}
			if names := entryFiles(t, env.dir); len(names) != 0 {
				t.Fatalf("cache files = %v, want none", names)
			}
		})
	}
}

func TestGetRetriesTransportErrors(t *testing.T) {
	var n atomic.Int32
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			// Close the connection without a response.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("server does not support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			return
		}
		okHandler("after hiccup")(w, r)
	})
	env := newTestEnv(t, ts, nil)
	resp, err := env.client.Get(context.Background(), ts.URL, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "after hiccup" || len(env.sleeps.recorded()) != 1 {
		t.Fatalf("resp = %+v, sleeps = %v", resp, env.sleeps.recorded())
	}
}

// TestGetBodyCap lowers the cap so the test does not need a 128 MiB body: a body
// exactly at the cap is accepted, one byte more is ErrBodyTooLarge, and an
// oversized body is neither retried nor cached.
func TestGetBodyCap(t *testing.T) {
	const limit = 16
	t.Run("at the cap", func(t *testing.T) {
		ts := newTestServer(t, okHandler(strings.Repeat("x", limit)))
		env := newTestEnv(t, ts, nil)
		env.client.maxBody = limit
		resp, err := env.client.Get(context.Background(), ts.URL, Request{})
		if err != nil {
			t.Fatalf("a body of exactly %d bytes must be accepted: %v", limit, err)
		}
		if len(resp.Body) != limit {
			t.Fatalf("body length = %d, want %d", len(resp.Body), limit)
		}
		if names := entryFiles(t, env.dir); len(names) != 2 {
			t.Fatalf("cache files = %v, want the entry", names)
		}
	})
	t.Run("one byte over", func(t *testing.T) {
		ts := newTestServer(t, okHandler(strings.Repeat("x", limit+1)))
		env := newTestEnv(t, ts, nil)
		env.client.maxBody = limit
		_, err := env.client.Get(context.Background(), ts.URL, Request{})
		if !errors.Is(err, ErrBodyTooLarge) || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("err = %v, want ErrBodyTooLarge naming the cap", err)
		}
		if !strings.Contains(err.Error(), ts.URL) {
			t.Errorf("error should name the URL: %v", err)
		}
		if got := ts.calls.Load(); got != 1 {
			t.Fatalf("server calls = %d, want 1: an oversized body must not be retried", got)
		}
		if len(env.sleeps.recorded()) != 0 || len(entryFiles(t, env.dir)) != 0 {
			t.Fatal("oversized body was retried or cached")
		}
	})
}

func TestGetNoRetriesWhenDisabled(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	env := newTestEnv(t, ts, func(o *Options) { o.Retries = -1 })
	_, err := env.client.Get(context.Background(), ts.URL, Request{})
	var se *StatusError
	if !errors.As(err, &se) || ts.calls.Load() != 1 {
		t.Fatalf("err = %v, calls = %d", err, ts.calls.Load())
	}
}

func TestGetNeverRetriesAfterCancellation(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	env := newTestEnv(t, ts, nil)
	ctx, cancel := context.WithCancel(context.Background())
	env.client.sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	_, err := env.client.Get(ctx, ts.URL, Request{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := ts.calls.Load(); got != 1 {
		t.Fatalf("server calls = %d, want 1", got)
	}
}

// TestGetTimeoutPerAttempt covers the header budget: the handler blocks before it
// writes the status line, so the attempt never reaches the body at all.
func TestGetTimeoutPerAttempt(t *testing.T) {
	release := make(chan struct{})
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	defer close(release)
	env := newTestEnv(t, ts, func(o *Options) {
		o.HeaderTimeout = 50 * time.Millisecond
		o.Retries = -1
	})
	_, err := env.client.Get(context.Background(), ts.URL, Request{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	var se *StatusError
	if errors.As(err, &se) {
		t.Fatalf("a timeout must not be a StatusError: %v", err)
	}
}

// TestGetRetriesAfterAttemptTimeout pins that the timeout bounds one attempt and
// leaves the parent context intact, so a single slow response is retried.
func TestGetRetriesAfterAttemptTimeout(t *testing.T) {
	var n atomic.Int32
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			time.Sleep(300 * time.Millisecond)
		}
		okHandler("second try")(w, r)
	})
	env := newTestEnv(t, ts, func(o *Options) { o.HeaderTimeout = 50 * time.Millisecond })
	resp, err := env.client.Get(context.Background(), ts.URL, Request{})
	if err != nil {
		t.Fatalf("a per-attempt timeout must be retried: %v", err)
	}
	if string(resp.Body) != "second try" || ts.calls.Load() != 2 || len(env.sleeps.recorded()) != 1 {
		t.Fatalf("resp = %+v, calls = %d, sleeps = %v", resp, ts.calls.Load(), env.sleeps.recorded())
	}
}

// dribble is a handler that sends its headers at once and then one byte every 20
// ms until the test releases it, which is a body that never finishes.
func dribble(release <-chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		flusher.Flush()
		for {
			select {
			case <-release:
				return
			case <-time.After(20 * time.Millisecond):
				if _, err := w.Write([]byte("x")); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}

// A slow body is a large document, not a host that is not answering, and the one
// budget that covered both made the first look like the second: the largest body
// this client fetches was 2,007,058 bytes on the wire on 2026-09-11, which ten
// seconds could only finish above 200 KiB/s. The handler sends its headers at once
// and its body over four chunks, which outlasts the header budget and finishes well
// inside the body one. Finding F25 of docs/review-2026-09-10.md.
func TestGetSlowBodyIsNotAHeaderTimeout(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("the test server cannot flush")
			return
		}
		flusher.Flush()
		for _, part := range []string{"one ", "two ", "three ", "four"} {
			time.Sleep(40 * time.Millisecond)
			_, _ = w.Write([]byte(part))
			flusher.Flush()
		}
	})
	env := newTestEnv(t, ts, func(o *Options) {
		o.HeaderTimeout = 100 * time.Millisecond
		o.BodyTimeout = 5 * time.Second
		o.Retries = -1
	})
	resp, err := env.client.Get(context.Background(), ts.URL, Request{})
	if err != nil {
		t.Fatalf("a body that outlasts the header budget must still be read: %v", err)
	}
	if got := string(resp.Body); got != "one two three four" {
		t.Errorf("body = %q, want the whole document", got)
	}
	if ts.calls.Load() != 1 || len(env.sleeps.recorded()) != 0 {
		t.Errorf("calls = %d, sleeps = %v, want one request and no retry", ts.calls.Load(), env.sleeps.recorded())
	}
}

// The body budget still bounds a server that sends its headers and then dribbles
// forever. Splitting the budget must not have made total time unbounded.
func TestGetBodyTimeoutBoundsASlowLoris(t *testing.T) {
	release := make(chan struct{})
	ts := newTestServer(t, dribble(release))
	defer close(release)
	env := newTestEnv(t, ts, func(o *Options) {
		o.HeaderTimeout = 5 * time.Second
		o.BodyTimeout = 200 * time.Millisecond
		o.Retries = -1
	})
	start := time.Now()
	_, err := env.client.Get(context.Background(), ts.URL, Request{})
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	var se *StatusError
	if errors.As(err, &se) {
		t.Fatalf("a timeout must not be a StatusError: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("the attempt took %v, want it bounded by the 200ms body budget", elapsed)
	}
	if got := ts.calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1", got)
	}
}

// A body that got past the headers and still did not finish is tried once more
// and no further. A third try pulls the same bytes over the same link, so a wedged
// origin would cost four times the body budget and the download three times over.
func TestGetBodyTimeoutIsRetriedOnce(t *testing.T) {
	release := make(chan struct{})
	ts := newTestServer(t, dribble(release))
	defer close(release)
	env := newTestEnv(t, ts, func(o *Options) {
		o.HeaderTimeout = 2 * time.Second
		o.BodyTimeout = 100 * time.Millisecond
	})
	_, err := env.client.Get(context.Background(), ts.URL, Request{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "after 2 attempts") {
		t.Errorf("err = %v, want it to say it stopped after 2 attempts", err)
	}
	if got := ts.calls.Load(); got != 2 {
		t.Errorf("server calls = %d, want 2", got)
	}
	if got := len(env.sleeps.recorded()); got != 1 {
		t.Errorf("sleeps = %d, want 1", got)
	}
}

func TestOffline(t *testing.T) {
	ts := newTestServer(t, okHandler("cached"))
	dir := t.TempDir()
	online := newTestEnv(t, ts, func(o *Options) { o.Dir = dir })
	ctx := context.Background()
	if _, err := online.client.Get(ctx, ts.URL+"/hit", Request{TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}

	offline := newTestEnv(t, ts, func(o *Options) {
		o.Dir = dir
		o.Offline = true
		o.Now = online.clock.now
		o.Transport = failingTransport{}
	})
	online.clock.advance(time.Hour) // the entry is expired, offline serves it anyway

	hit, err := offline.client.Get(ctx, ts.URL+"/hit", Request{TTL: time.Minute})
	if err != nil {
		t.Fatalf("offline hit: %v", err)
	}
	if !hit.FromCache || string(hit.Body) != "cached" {
		t.Fatalf("offline hit = %+v", hit)
	}

	_, err = offline.client.Get(ctx, ts.URL+"/miss", Request{})
	if !errors.Is(err, ErrOffline) {
		t.Fatalf("offline miss err = %v, want ErrOffline", err)
	}
	if !strings.Contains(err.Error(), ts.URL+"/miss") {
		t.Errorf("offline error should name the URL: %v", err)
	}
	if got := ts.calls.Load(); got != 1 {
		t.Fatalf("server calls = %d, offline must not touch the network", got)
	}
}

// failingTransport fails every request; it proves a code path never reaches the network.
type failingTransport struct{}

func (failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("network access attempted for " + r.URL.String())
}

func TestNoCache(t *testing.T) {
	ts := newTestServer(t, okHandler("live"))
	dir := t.TempDir()
	env := newTestEnv(t, ts, func(o *Options) {
		o.Dir = dir
		o.NoCache = true
	})
	ctx := context.Background()
	for range 2 {
		resp, err := env.client.Get(ctx, ts.URL, Request{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.FromCache {
			t.Fatal("NoCache served from cache")
		}
	}
	if got := ts.calls.Load(); got != 2 {
		t.Fatalf("server calls = %d, want 2", got)
	}
	if names := entryFiles(t, dir); len(names) != 0 {
		t.Fatalf("NoCache wrote %v", names)
	}
}

func TestPerHostLimiter(t *testing.T) {
	ts := newTestServer(t, okHandler("x"))
	env := newTestEnv(t, ts, func(o *Options) {
		o.HostRPS[ts.host(t)] = 20 // one request every 50 ms
	})
	ctx := context.Background()
	start := time.Now()
	for i := range 3 {
		u := ts.URL + "/" + string(rune('a'+i))
		if _, err := env.client.Get(ctx, u, Request{}); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("3 requests at 20 rps took %v, want at least 100ms", elapsed)
	}
	if got := ts.calls.Load(); got != 3 {
		t.Fatalf("server calls = %d", got)
	}
	// The limiter is keyed by host and shared across URLs of that host.
	same := env.client.limiterFor(ts.host(t))
	again := env.client.limiterFor(strings.ToUpper(ts.host(t)))
	other := env.client.limiterFor("other.example")
	if same != again {
		t.Fatal("limiterFor returned different limiters for the same host")
	}
	if other == same {
		t.Fatal("different hosts share a limiter")
	}
}

func TestLimiterWaitRespectsContext(t *testing.T) {
	ts := newTestServer(t, okHandler("x"))
	env := newTestEnv(t, ts, func(o *Options) {
		o.HostRPS[ts.host(t)] = 0.001 // the second request would wait for minutes
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := env.client.Get(ctx, ts.URL+"/1", Request{}); err != nil {
		t.Fatal(err)
	}
	_, err := env.client.Get(ctx, ts.URL+"/2", Request{})
	if err == nil || ts.calls.Load() != 1 {
		t.Fatalf("err = %v, calls = %d; want the limiter wait to fail on the deadline", err, ts.calls.Load())
	}
}

func TestCorruptMetadataIsAMiss(t *testing.T) {
	ts := newTestServer(t, okHandler("fresh"))
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	if _, err := env.client.Get(ctx, ts.URL, Request{}); err != nil {
		t.Fatal(err)
	}
	names := entryFiles(t, env.dir)
	var metaPath string
	for _, n := range names {
		if strings.HasSuffix(n, metaSuffix) {
			metaPath = filepath.Join(env.dir, n)
		}
	}
	if metaPath == "" {
		t.Fatalf("no metadata file among %v", names)
	}
	tests := []struct {
		name    string
		content string
	}{
		{name: "truncated", content: `{"url":"` + ts.URL},
		{name: "not json", content: "garbage"},
		{name: "empty", content: ""},
		{name: "wrong url", content: `{"url":"http://other/","accept":"*/*","fetched_at":"2026-09-09T12:00:00Z","ttl":"1h0m0s","status":200}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := ts.calls.Load()
			if err := os.WriteFile(metaPath, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			resp, err := env.client.Get(ctx, ts.URL, Request{})
			if err != nil {
				t.Fatalf("Get after corruption: %v", err)
			}
			if resp.FromCache || ts.calls.Load() != before+1 {
				t.Fatalf("corrupt metadata was served: %+v", resp)
			}
			// The entry was rewritten and is valid again.
			again, err := env.client.Get(ctx, ts.URL, Request{})
			if err != nil || !again.FromCache {
				t.Fatalf("entry not repaired: %+v, %v", again, err)
			}
		})
	}
}

func TestMissingBodyIsAMiss(t *testing.T) {
	ts := newTestServer(t, okHandler("fresh"))
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	if _, err := env.client.Get(ctx, ts.URL, Request{}); err != nil {
		t.Fatal(err)
	}
	for _, n := range entryFiles(t, env.dir) {
		if strings.HasSuffix(n, bodySuffix) {
			if err := os.Remove(filepath.Join(env.dir, n)); err != nil {
				t.Fatal(err)
			}
		}
	}
	resp, err := env.client.Get(ctx, ts.URL, Request{})
	if err != nil || resp.FromCache || ts.calls.Load() != 2 {
		t.Fatalf("resp = %+v, err = %v, calls = %d", resp, err, ts.calls.Load())
	}
}

// TestTruncatedBodyIsAMiss covers a power loss after the rename or two processes
// writing the same key: a body that does not match its metadata must not be
// served, even for a Forever entry, and the next fetch must repair it.
func TestTruncatedBodyIsAMiss(t *testing.T) {
	const full = `{"name":"express","versions":{}}`
	tests := []struct {
		name string
		body string
	}{
		{name: "truncated", body: `{"name":"ex`},
		{name: "empty", body: ""},
		{name: "longer", body: full + `{"name":"other"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestServer(t, okHandler(full))
			env := newTestEnv(t, ts, nil)
			ctx := context.Background()
			if _, err := env.client.Get(ctx, ts.URL, Request{TTL: Forever}); err != nil {
				t.Fatal(err)
			}
			var bodyPath string
			for _, n := range entryFiles(t, env.dir) {
				if strings.HasSuffix(n, bodySuffix) {
					bodyPath = filepath.Join(env.dir, n)
				}
			}
			if bodyPath == "" {
				t.Fatal("no body file written")
			}
			if err := os.WriteFile(bodyPath, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			env.clock.advance(365 * 24 * time.Hour)
			resp, err := env.client.Get(ctx, ts.URL, Request{TTL: Forever})
			if err != nil {
				t.Fatal(err)
			}
			if resp.FromCache || string(resp.Body) != full || ts.calls.Load() != 2 {
				t.Fatalf("mismatched body was served: %+v, calls %d", resp, ts.calls.Load())
			}
			// The entry was rewritten and is valid again.
			again, err := env.client.Get(ctx, ts.URL, Request{TTL: Forever})
			if err != nil || !again.FromCache || string(again.Body) != full || ts.calls.Load() != 2 {
				t.Fatalf("entry not repaired: %+v, %v, calls %d", again, err, ts.calls.Load())
			}
		})
	}
}

func TestConcurrentGetsShareOneFetch(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		okHandler("shared")(w, r)
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Go(func() {
			resp, err := env.client.Get(ctx, ts.URL, Request{})
			if err != nil {
				errs <- err
				return
			}
			if string(resp.Body) != "shared" {
				errs <- errors.New("wrong body " + string(resp.Body))
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := ts.calls.Load(); got != 1 {
		t.Fatalf("server calls = %d, want 1: concurrent Gets of one URL must share the fetch", got)
	}
	if names := entryFiles(t, env.dir); len(names) != 2 {
		t.Fatalf("cache files = %v", names)
	}
}

func TestStatusErrorMessage(t *testing.T) {
	err := &StatusError{URL: "https://example.com/x", StatusCode: 503}
	if got := err.Error(); !strings.Contains(got, "503") || !strings.Contains(got, "https://example.com/x") {
		t.Fatalf("Error() = %q", got)
	}
}

func TestCacheKeyIsStable(t *testing.T) {
	a := cacheKey("GET", "https://example.com/a", "*/*", "")
	b := cacheKey("GET", "https://example.com/a", "*/*", "")
	c := cacheKey("GET", "https://example.com/a", "application/json", "")
	d := cacheKey("HEAD", "https://example.com/a", "*/*", "")
	if a != b || a == c || a == d {
		t.Fatalf("keys: %s %s %s %s", a, b, c, d)
	}
	if len(a) != 64 {
		t.Fatalf("key length = %d, want 64 hex characters", len(a))
	}
	// The GET key is the sha256 of "GET\n<url>\n<accept>", the format of the
	// first release, so caches written before Post existed stay valid.
	if want := "d35a6660d954935970de05cd0a348bef773de4aad2989fbfc792c9e97482269f"; a != want {
		t.Fatalf("GET key = %s, want %s: the on-disk key format changed", a, want)
	}

	hash1 := strings.Repeat("1", 64)
	hash2 := strings.Repeat("2", 64)
	p1 := cacheKey("POST", "https://example.com/a", "*/*", hash1)
	p2 := cacheKey("POST", "https://example.com/a", "*/*", hash2)
	if p1 == p2 || p1 == a || p1 == cacheKey("POST", "https://example.com/a", "*/*", "") {
		t.Fatalf("POST keys: %s %s (GET %s)", p1, p2, a)
	}
	if again := cacheKey("POST", "https://example.com/a", "*/*", hash1); again != p1 {
		t.Fatalf("POST key not stable: %s vs %s", again, p1)
	}
}
