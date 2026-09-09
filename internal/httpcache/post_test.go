package httpcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// osvQuery has the shape of an OSV querybatch body (verified 2026-09-09). The
// tests only need something realistic to send and to hash; no server here
// interprets it.
const osvQuery = `{"queries":[{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}]}`

// echoHandler answers with the request body, so a test can tell which body an
// entry was stored for.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.Copy(w, r.Body)
}

// closeConnection drops the connection without a response, a transport error
// for the client.
func closeConnection(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("server does not support hijacking")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}
}

func TestPostSendsBodyAndContentType(t *testing.T) {
	ts := newTestServer(t, okHandler(`{"results":[]}`))
	env := newTestEnv(t, ts, nil)
	tests := []struct {
		name       string
		req        Request
		wantAccept string
		wantExtra  string
	}{
		{name: "default accept", req: Request{}, wantAccept: "*/*"},
		{name: "explicit accept", req: Request{Accept: "application/json"}, wantAccept: "application/json"},
		{name: "extra header", req: Request{Header: http.Header{"X-Test": {"yes"}}}, wantAccept: "*/*", wantExtra: "yes"},
		// The body handed to Post is JSON, so a caller cannot relabel it.
		{name: "content type wins", req: Request{Header: http.Header{"Content-Type": {"text/plain"}}}, wantAccept: "*/*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := ts.URL + "/" + strings.ReplaceAll(tt.name, " ", "-")
			resp, err := env.client.Post(context.Background(), u, []byte(osvQuery), tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.FromCache || resp.StatusCode != http.StatusOK || string(resp.Body) != `{"results":[]}` {
				t.Fatalf("resp = %+v", resp)
			}
			if got := ts.method(); got != http.MethodPost {
				t.Errorf("method = %q, want POST", got)
			}
			if got := string(ts.body()); got != osvQuery {
				t.Errorf("body = %q, want %q", got, osvQuery)
			}
			if got := ts.header("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
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

func TestPostRejectsBadURLs(t *testing.T) {
	env := newTestEnv(t, nil, nil)
	for _, u := range []string{"", "not a url", "ftp://example.com/x", "/relative", "http://"} {
		_, err := env.client.Post(context.Background(), u, []byte(osvQuery), Request{})
		if err == nil {
			t.Errorf("Post(%q) succeeded, want an error", u)
			continue
		}
		if !strings.HasPrefix(err.Error(), "POST ") {
			t.Errorf("Post(%q) error = %v, want it to name the method", u, err)
		}
	}
}

func TestPostFreshHitSkipsTheNetwork(t *testing.T) {
	ts := newTestServer(t, okHandler(`{"results":[{"vulns":[]}]}`))
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	u := ts.URL + "/v1/querybatch"

	first, err := env.client.Post(ctx, u, []byte(osvQuery), Request{TTL: 6 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if first.FromCache || first.StatusCode != http.StatusOK || !first.FetchedAt.Equal(env.clock.now()) {
		t.Fatalf("first = %+v", first)
	}

	env.clock.advance(5 * time.Hour)
	second, err := env.client.Post(ctx, u, []byte(osvQuery), Request{TTL: 6 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !second.FromCache || !bytes.Equal(second.Body, first.Body) || !second.FetchedAt.Equal(first.FetchedAt) {
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

	// The TTL of the current request decides, as for Get.
	third, err := env.client.Post(ctx, u, []byte(osvQuery), Request{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if third.FromCache || ts.calls.Load() != 2 {
		t.Fatalf("a 5h old entry was served under a 1h TTL: %+v, calls %d", third, ts.calls.Load())
	}
}

// TestPostExpiredEntryIsFetchedAgainNotRevalidated pins that a POST never sends
// If-None-Match or If-Modified-Since: an origin that evaluates the condition
// answers a POST with 412, not 304 (RFC 9110 section 13.1.2).
func TestPostExpiredEntryIsFetchedAgainNotRevalidated(t *testing.T) {
	var version atomic.Int32
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Tue, 08 Sep 2026 10:00:00 GMT")
		_, _ = fmt.Fprintf(w, "answer-%d", version.Load())
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()

	first, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Body) != "answer-0" {
		t.Fatalf("first = %+v", first)
	}

	version.Store(1)
	env.clock.advance(2 * time.Hour)
	second, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{TTL: time.Hour})
	if err != nil {
		t.Fatalf("an expired POST entry must be fetched again, not revalidated: %v", err)
	}
	if second.FromCache || string(second.Body) != "answer-1" || ts.calls.Load() != 2 {
		t.Fatalf("second = %+v, calls %d", second, ts.calls.Load())
	}
	if got := ts.header("If-None-Match"); got != "" {
		t.Errorf("If-None-Match = %q sent with a POST", got)
	}
	if got := ts.header("If-Modified-Since"); got != "" {
		t.Errorf("If-Modified-Since = %q sent with a POST", got)
	}

	// The new answer replaced the entry.
	env.clock.advance(time.Minute)
	third, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{TTL: time.Hour})
	if err != nil || !third.FromCache || string(third.Body) != "answer-1" || ts.calls.Load() != 2 {
		t.Fatalf("replaced entry not served: %+v, %v, calls %d", third, err, ts.calls.Load())
	}
}

func TestPostDifferentBodiesGetDifferentEntries(t *testing.T) {
	ts := newTestServer(t, echoHandler)
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	u := ts.URL + "/v3alpha/versionbatch"
	lodash := []byte(`{"requests":[{"versionKey":{"system":"NPM","name":"lodash","version":"4.17.20"}}]}`)
	express := []byte(`{"requests":[{"versionKey":{"system":"NPM","name":"express","version":"4.19.2"}}]}`)

	a, err := env.client.Post(ctx, u, lodash, Request{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.client.Post(ctx, u, express, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if a.FromCache || b.FromCache || !bytes.Equal(a.Body, lodash) || !bytes.Equal(b.Body, express) {
		t.Fatalf("a = %q (cache %v), b = %q (cache %v)", a.Body, a.FromCache, b.Body, b.FromCache)
	}
	if got := ts.calls.Load(); got != 2 {
		t.Fatalf("server calls = %d, want 2", got)
	}
	if names := entryFiles(t, env.dir); len(names) != 4 {
		t.Fatalf("cache files = %v, want two entries", names)
	}

	// Each body finds its own entry afterwards.
	tests := []struct {
		name string
		body []byte
	}{
		{name: "lodash", body: lodash},
		{name: "express", body: express},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := env.client.Post(ctx, u, tt.body, Request{})
			if err != nil {
				t.Fatal(err)
			}
			if !resp.FromCache || !bytes.Equal(resp.Body, tt.body) {
				t.Fatalf("resp = %q (cache %v), want the %s answer from the cache", resp.Body, resp.FromCache, tt.name)
			}
		})
	}
	if got := ts.calls.Load(); got != 2 {
		t.Fatalf("server calls after the hits = %d, want 2", got)
	}
}

func TestPostAndGetDoNotShareAnEntry(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Method))
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()

	get, err := env.client.Get(ctx, ts.URL, Request{})
	if err != nil {
		t.Fatal(err)
	}
	post, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{})
	if err != nil {
		t.Fatal(err)
	}
	if post.FromCache || string(get.Body) != "GET" || string(post.Body) != "POST" {
		t.Fatalf("get = %q, post = %q (cache %v)", get.Body, post.Body, post.FromCache)
	}
	if names := entryFiles(t, env.dir); len(names) != 4 {
		t.Fatalf("cache files = %v, want two entries", names)
	}

	get, err = env.client.Get(ctx, ts.URL, Request{})
	if err != nil || !get.FromCache || string(get.Body) != "GET" {
		t.Fatalf("second get = %+v, %v", get, err)
	}
	post, err = env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{})
	if err != nil || !post.FromCache || string(post.Body) != "POST" {
		t.Fatalf("second post = %+v, %v", post, err)
	}
	if got := ts.calls.Load(); got != 2 {
		t.Fatalf("server calls = %d, want 2", got)
	}
}

func TestPostBodyIsNeverStoredOnDisk(t *testing.T) {
	const marker = "never-on-disk-7f3a9c"
	body := []byte(`{"queries":[{"package":{"name":"` + marker + `","ecosystem":"npm"},"version":"1.0.0"}]}`)
	ts := newTestServer(t, okHandler(`{"results":[{}]}`))
	env := newTestEnv(t, ts, nil)
	if _, err := env.client.Post(context.Background(), ts.URL, body, Request{TTL: 6 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	wantHash := hex.EncodeToString(sum[:])

	var sawMeta bool
	for _, n := range entryFiles(t, env.dir) {
		data, err := os.ReadFile(filepath.Join(env.dir, n))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(marker)) {
			t.Errorf("%s contains the request body", n)
		}
		if !strings.HasSuffix(n, metaSuffix) {
			continue
		}
		sawMeta = true
		meta, err := parseMeta(data)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		if meta.Method != http.MethodPost || meta.BodySHA256 != wantHash || meta.URL != ts.URL || meta.TTL != 6*time.Hour {
			t.Errorf("metadata = %+v, want POST with body hash %s", meta, wantHash)
		}
		if !strings.Contains(string(data), `"body_sha256": "`+wantHash+`"`) {
			t.Errorf("metadata file does not record the body hash under body_sha256:\n%s", data)
		}
	}
	if !sawMeta {
		t.Fatal("no metadata file written")
	}
}

func TestPostOffline(t *testing.T) {
	ts := newTestServer(t, okHandler(`{"results":[]}`))
	dir := t.TempDir()
	online := newTestEnv(t, ts, func(o *Options) { o.Dir = dir })
	ctx := context.Background()
	u := ts.URL + "/v1/querybatch"
	if _, err := online.client.Post(ctx, u, []byte(osvQuery), Request{TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}

	offline := newTestEnv(t, ts, func(o *Options) {
		o.Dir = dir
		o.Offline = true
		o.Now = online.clock.now
		o.Transport = failingTransport{}
	})
	online.clock.advance(time.Hour) // the entry is expired, offline serves it anyway

	hit, err := offline.client.Post(ctx, u, []byte(osvQuery), Request{TTL: time.Minute})
	if err != nil {
		t.Fatalf("offline hit: %v", err)
	}
	if !hit.FromCache || string(hit.Body) != `{"results":[]}` {
		t.Fatalf("offline hit = %+v", hit)
	}

	// Another body to the same URL is another entry, so it is a miss.
	_, err = offline.client.Post(ctx, u, []byte(`{"queries":[]}`), Request{})
	if !errors.Is(err, ErrOffline) {
		t.Fatalf("offline miss err = %v, want ErrOffline", err)
	}
	if !strings.Contains(err.Error(), "POST "+u) {
		t.Errorf("offline error should name the method and URL: %v", err)
	}

	both := newTestEnv(t, ts, func(o *Options) {
		o.Dir = dir
		o.Offline = true
		o.NoCache = true
		o.Transport = failingTransport{}
	})
	if _, err := both.client.Post(ctx, u, []byte(osvQuery), Request{}); !errors.Is(err, ErrOffline) {
		t.Fatalf("offline with NoCache err = %v, want ErrOffline", err)
	}
	if got := ts.calls.Load(); got != 1 {
		t.Fatalf("server calls = %d, offline must not touch the network", got)
	}
}

func TestPostNoCache(t *testing.T) {
	ts := newTestServer(t, okHandler("live"))
	dir := t.TempDir()
	env := newTestEnv(t, ts, func(o *Options) {
		o.Dir = dir
		o.NoCache = true
	})
	ctx := context.Background()
	for range 2 {
		resp, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{})
		if err != nil {
			t.Fatal(err)
		}
		if resp.FromCache || string(resp.Body) != "live" {
			t.Fatalf("NoCache resp = %+v", resp)
		}
		if got := string(ts.body()); got != osvQuery {
			t.Errorf("body = %q", got)
		}
	}
	if got := ts.calls.Load(); got != 2 {
		t.Fatalf("server calls = %d, want 2", got)
	}
	if names := entryFiles(t, dir); len(names) != 0 {
		t.Fatalf("NoCache wrote %v", names)
	}
}

// TestPostRetriesResendTheBody covers the three retry triggers. The whole body
// must go out again on the retry: the client's own loop is the only retry a
// POST gets, since net/http does not repeat non-idempotent requests by itself.
func TestPostRetriesResendTheBody(t *testing.T) {
	tests := []struct {
		name      string
		fail      func(t *testing.T) http.HandlerFunc // what the first attempt does
		wantDelay time.Duration                       // zero means any positive backoff
	}{
		{name: "503", fail: func(*testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }
		}},
		{name: "429 with Retry-After", fail: func(*testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(http.StatusTooManyRequests)
			}
		}, wantDelay: 7 * time.Second},
		{name: "connection closed", fail: closeConnection},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var n atomic.Int32
			fail := tt.fail(t)
			ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if n.Add(1) == 1 {
					fail(w, r)
					return
				}
				echoHandler(w, r)
			})
			env := newTestEnv(t, ts, nil)
			ctx := context.Background()
			resp, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{})
			if err != nil {
				t.Fatal(err)
			}
			if string(resp.Body) != osvQuery || ts.calls.Load() != 2 {
				t.Fatalf("resp = %q, calls = %d", resp.Body, ts.calls.Load())
			}
			bodies := ts.allBodies()
			if len(bodies) != 2 || string(bodies[0]) != osvQuery || string(bodies[1]) != osvQuery {
				t.Fatalf("bodies received = %q, want the full body twice", bodies)
			}
			delays := env.sleeps.recorded()
			switch {
			case len(delays) != 1:
				t.Fatalf("sleeps = %v, want one", delays)
			case tt.wantDelay != 0 && delays[0] != tt.wantDelay:
				t.Fatalf("sleeps = %v, want [%v]", delays, tt.wantDelay)
			case delays[0] <= 0:
				t.Fatalf("sleeps = %v, want a positive backoff", delays)
			}
			// The recovered answer was cached.
			again, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{})
			if err != nil || !again.FromCache || ts.calls.Load() != 2 {
				t.Fatalf("recovered answer not cached: %+v, %v, calls %d", again, err, ts.calls.Load())
			}
		})
	}
}

func TestPostGivesUpAfterRetries(t *testing.T) {
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
			_, err := env.client.Post(context.Background(), ts.URL, []byte(osvQuery), Request{})
			var se *StatusError
			if !errors.As(err, &se) || se.StatusCode != tt.status || se.Method != http.MethodPost || se.URL != ts.URL {
				t.Fatalf("err = %v, want *StatusError for POST %s with %d", err, ts.URL, tt.status)
			}
			if !strings.HasPrefix(err.Error(), "POST ") {
				t.Errorf("error = %q, want it to name the method", err)
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

// TestPostCaches404LikeGet: a 404 is an answer and is cached, but never for
// longer than DefaultTTL, whatever the caller asked for.
func TestPostCaches404LikeGet(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"code":5,"message":"not found"}`, http.StatusNotFound)
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()

	first, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{TTL: Forever})
	if err != nil {
		t.Fatalf("404 must be a response, not an error: %v", err)
	}
	if first.StatusCode != http.StatusNotFound || first.FromCache {
		t.Fatalf("first = %+v", first)
	}
	env.clock.advance(30 * time.Minute)
	hit, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{TTL: Forever})
	if err != nil || hit.StatusCode != http.StatusNotFound || !hit.FromCache || ts.calls.Load() != 1 {
		t.Fatalf("404 within DefaultTTL: %+v, %v, calls %d", hit, err, ts.calls.Load())
	}
	env.clock.advance(2 * time.Hour)
	if _, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{TTL: Forever}); err != nil {
		t.Fatal(err)
	}
	if got := ts.calls.Load(); got != 2 {
		t.Fatalf("server calls = %d, want 2: a 404 stored under Forever was pinned", got)
	}
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

func TestPostDoesNotCacheOtherStatuses(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{name: "204", status: http.StatusNoContent},
		{name: "400", status: http.StatusBadRequest, wantErr: true},
		{name: "403", status: http.StatusForbidden, wantErr: true},
		// A POST is never conditional, so a 304 confirms nothing.
		{name: "304", status: http.StatusNotModified, wantErr: true},
		{name: "412", status: http.StatusPreconditionFailed, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			env := newTestEnv(t, ts, nil)
			ctx := context.Background()
			for i := range 2 {
				resp, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{})
				var se *StatusError
				switch {
				case tt.wantErr && (!errors.As(err, &se) || se.StatusCode != tt.status || se.Method != http.MethodPost):
					t.Fatalf("call %d: err = %v, want *StatusError for POST with %d", i+1, err, tt.status)
				case !tt.wantErr && (err != nil || resp.StatusCode != tt.status || resp.FromCache):
					t.Fatalf("call %d: resp = %+v, err = %v", i+1, resp, err)
				}
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

func TestPostBodyCap(t *testing.T) {
	const limit = 16
	ts := newTestServer(t, okHandler(strings.Repeat("x", limit+1)))
	env := newTestEnv(t, ts, nil)
	env.client.maxBody = limit
	_, err := env.client.Post(context.Background(), ts.URL, []byte(osvQuery), Request{})
	if !errors.Is(err, ErrBodyTooLarge) || !strings.HasPrefix(err.Error(), "POST "+ts.URL) {
		t.Fatalf("err = %v, want ErrBodyTooLarge under the POST prefix", err)
	}
	if ts.calls.Load() != 1 || len(env.sleeps.recorded()) != 0 || len(entryFiles(t, env.dir)) != 0 {
		t.Fatal("oversized body was retried or cached")
	}
}

func TestPostUsesTheHostLimiter(t *testing.T) {
	ts := newTestServer(t, okHandler("x"))
	env := newTestEnv(t, ts, func(o *Options) {
		o.HostRPS[ts.host(t)] = 20 // one request every 50 ms
	})
	ctx := context.Background()
	start := time.Now()
	// Get and Post share the limiter of the host: three requests in a row wait
	// twice, whichever method they use.
	if _, err := env.client.Get(ctx, ts.URL+"/a", Request{}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.Post(ctx, ts.URL+"/b", []byte(osvQuery), Request{}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.Post(ctx, ts.URL+"/c", []byte(osvQuery), Request{}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("3 requests at 20 rps took %v, want at least 100ms", elapsed)
	}
	if got := ts.calls.Load(); got != 3 {
		t.Fatalf("server calls = %d", got)
	}
}

func TestConcurrentPostsShareOneFetch(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		echoHandler(w, r)
	})
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Go(func() {
			resp, err := env.client.Post(ctx, ts.URL, []byte(osvQuery), Request{})
			if err != nil {
				errs <- err
				return
			}
			if string(resp.Body) != osvQuery {
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
		t.Fatalf("server calls = %d, want 1: concurrent Posts of one body must share the fetch", got)
	}
	if names := entryFiles(t, env.dir); len(names) != 2 {
		t.Fatalf("cache files = %v", names)
	}
}
