//go:build integration

package integration

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/version"
)

const (
	// offlineEnv, when set to a non-empty value, skips every test in this package.
	offlineEnv = "TRUSTDIFF_INTEGRATION_OFFLINE"
	// deadline bounds one test, rate limiter waits and retries included.
	deadline = 60 * time.Second
)

// live is what one test talks to: the HTTP client over a temporary cache
// directory, the transport recorder behind it, and the logger the clients share.
type live struct {
	http *httpcache.Client
	rec  *recorder
	log  *slog.Logger
}

// start skips the test when offlineEnv is set, otherwise returns the context the
// test runs under and a fresh client whose cache lives in t.TempDir(). The user
// agent is the one the binary sends, which crates.io requires to be identifying.
func start(t *testing.T) (context.Context, *live) {
	t.Helper()
	if v := os.Getenv(offlineEnv); v != "" {
		t.Skipf("%s=%q: live services are off", offlineEnv, v)
	}
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	t.Cleanup(cancel)

	log := testLogger(t)
	rec := &recorder{next: http.DefaultTransport}
	hc, err := httpcache.New(httpcache.Options{
		Dir:       t.TempDir(),
		UserAgent: version.UserAgent(),
		Transport: rec,
		Logger:    log,
	})
	if err != nil {
		t.Fatalf("httpcache.New: %v", err)
	}
	return ctx, &live{http: hc, rec: rec, log: log}
}

// sentRequest is one request that reached the network: when the transport sent
// it and where. Cache hits never get this far, so the recorder sees exactly the
// requests a service sees.
type sentRequest struct {
	at   time.Time
	host string
	// path is the escaped path as sent, which is how a test checks that a
	// scoped npm name was percent-encoded.
	path string
}

// recorder is the round tripper behind the client: it notes every request and
// hands it to the real transport.
type recorder struct {
	next http.RoundTripper
	mu   sync.Mutex
	sent []sentRequest
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.sent = append(r.sent, sentRequest{at: time.Now(), host: strings.ToLower(req.URL.Host), path: req.URL.EscapedPath()})
	r.mu.Unlock()
	return r.next.RoundTrip(req)
}

// toHost returns the requests sent to one host, in the order they left.
func (r *recorder) toHost(host string) []sentRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]sentRequest, 0, len(r.sent))
	for _, s := range r.sent {
		if s.host == host {
			out = append(out, s)
		}
	}
	return out
}

// testLogger routes the clients' diagnostics to t.Log, so a failed run shows the
// requests, retries and cache decisions behind it; go test prints them only for
// a failure or under -v. Writes after the test has finished are dropped, since
// t.Log panics then and a check the runner timed out could still be logging.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	w := &testWriter{t: t}
	t.Cleanup(func() {
		w.mu.Lock()
		w.done = true
		w.mu.Unlock()
	})
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct {
	t    *testing.T
	mu   sync.Mutex
	done bool
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.done {
		w.t.Log(strings.TrimRight(string(p), "\n"))
	}
	return len(p), nil
}
