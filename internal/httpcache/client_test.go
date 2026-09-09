package httpcache

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

// testServer counts requests and keeps the last request headers.
type testServer struct {
	*httptest.Server
	calls   atomic.Int32
	mu      sync.Mutex
	lastReq http.Header
}

func newTestServer(t *testing.T, handler http.HandlerFunc) *testServer {
	t.Helper()
	ts := &testServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.calls.Add(1)
		ts.mu.Lock()
		ts.lastReq = r.Header.Clone()
		ts.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
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
		{name: "negative timeout", opts: Options{Dir: t.TempDir(), UserAgent: "x", Timeout: -1}, wantErr: "Timeout"},
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
	if c.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", c.timeout)
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

func TestGetDoesNotCacheOtherStatuses(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{name: "204", status: http.StatusNoContent},
		{name: "403", status: http.StatusForbidden, wantErr: true},
		{name: "410", status: http.StatusGone, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			env := newTestEnv(t, ts, nil)
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
	var prev time.Duration
	for attempt := range 12 {
		d := c.backoff(attempt, 0)
		if d <= 0 {
			t.Fatalf("attempt %d: backoff %v, want positive", attempt, d)
		}
		if d > maxBackoff {
			t.Fatalf("attempt %d: backoff %v exceeds cap %v", attempt, d, maxBackoff)
		}
		if attempt > 0 && attempt < 5 && d <= prev/2 {
			t.Fatalf("attempt %d: backoff %v did not grow from %v", attempt, d, prev)
		}
		prev = d
	}
	if got := c.backoff(0, 7*time.Second); got != 7*time.Second {
		t.Fatalf("Retry-After 7s gave %v", got)
	}
	if got := c.backoff(0, 10*time.Minute); got != maxRetryAfter {
		t.Fatalf("Retry-After 10m gave %v, want the cap %v", got, maxRetryAfter)
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

func TestGetTimeoutPerAttempt(t *testing.T) {
	release := make(chan struct{})
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	defer close(release)
	env := newTestEnv(t, ts, func(o *Options) {
		o.Timeout = 50 * time.Millisecond
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
	a := cacheKey("GET", "https://example.com/a", "*/*")
	b := cacheKey("GET", "https://example.com/a", "*/*")
	c := cacheKey("GET", "https://example.com/a", "application/json")
	d := cacheKey("HEAD", "https://example.com/a", "*/*")
	if a != b || a == c || a == d {
		t.Fatalf("keys: %s %s %s %s", a, b, c, d)
	}
	if len(a) != 64 {
		t.Fatalf("key length = %d, want 64 hex characters", len(a))
	}
}
