// Package httpcache is the only way trustdiff talks to the network. Every registry
// and advisory client goes through it, so this is where the polite behavior lives:
// a disk cache keyed by URL with ETag and Last-Modified revalidation and a TTL per
// entry, a per-host rate limiter (crates.io asks for one request per second), retries
// with exponential backoff and jitter that honor Retry-After, a timeout per attempt,
// an identifying User-Agent, and the --offline and --no-cache modes.
//
// The cache is a flat directory of plain files. Each entry is a metadata file
// <sha256>.json and a body file <sha256>.body, where the hash covers the method, the
// URL and the Accept header. Both are written atomically, and an entry whose metadata
// does not parse is treated as a miss. Stat and Clear operate on such a directory;
// Clear refuses to touch a directory that holds anything this package did not write.
package httpcache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// DefaultTTL is used when a Request leaves TTL at zero.
	DefaultTTL = time.Hour
	// Forever marks immutable data, for example per-version publish times: the
	// entry is served from the cache for as long as it exists.
	Forever = time.Duration(math.MaxInt64)
	// EnvDir names the environment variable that overrides the cache directory.
	EnvDir = "TRUSTDIFF_CACHE_DIR"

	defaultTimeout = 10 * time.Second
	defaultRetries = 3
	// defaultRPS applies to every host without an explicit HostRPS entry.
	defaultRPS = 10
	// crates.io requires an identifying User-Agent with contact information and
	// asks API users to limit themselves to one request per second. Verified
	// 2026-09-09 against RFC 3463,
	// https://rust-lang.github.io/rfcs/3463-crates-io-policy-update.html.
	cratesHost = "crates.io"
	cratesRPS  = 1

	baseBackoff   = 500 * time.Millisecond
	maxBackoff    = 30 * time.Second
	maxRetryAfter = 60 * time.Second
	// maxBodyBytes bounds a single response; the largest npm packuments are a few
	// tens of megabytes and .crate archives are capped at 10 MiB by the registry.
	maxBodyBytes = 128 << 20
)

// ErrOffline is returned (wrapped) by Get when the client is offline and the URL is
// not in the cache. Callers use errors.Is and report the check as skipped.
var ErrOffline = errors.New("offline and not in the cache")

// ErrForeignFiles is returned (wrapped) by Clear when the directory contains files
// or subdirectories this package did not write, so a wrong directory is never wiped.
var ErrForeignFiles = errors.New("refusing to clear a directory trustdiff did not fill")

// StatusError is returned by Get for a final status that is neither 2xx nor 404,
// after retries were exhausted for 429 and 5xx. Callers use errors.As.
type StatusError struct {
	URL        string
	StatusCode int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("GET %s: unexpected status %d %s", e.URL, e.StatusCode, http.StatusText(e.StatusCode))
}

// Options configures a Client. The zero value of every field except UserAgent
// selects the documented default.
type Options struct {
	// Dir is the cache directory. Empty means DefaultDir().
	Dir string
	// Offline serves the cache regardless of TTL and never touches the network.
	Offline bool
	// NoCache neither reads nor writes the cache.
	NoCache bool
	// UserAgent is sent with every request and is required; callers pass
	// version.UserAgent().
	UserAgent string
	// Timeout bounds one attempt, including reading the body. Default 10 s.
	Timeout time.Duration
	// Retries is the number of additional attempts after the first one for 429,
	// 5xx and transport errors. Zero selects the default of 3; a negative value
	// disables retries.
	Retries int
	// HostRPS sets the requests per second allowed for a host (the URL host,
	// including a port when present, lowercased). Hosts without an entry get 10;
	// crates.io is built in at 1 and can be overridden here.
	HostRPS map[string]float64
	// Transport is the underlying round tripper. Default http.DefaultTransport.
	Transport http.RoundTripper
	// Logger receives diagnostics (cache hits, retries, write failures). Default
	// discards.
	Logger *slog.Logger
	// Now supplies the clock for TTLs and Retry-After dates. Default time.Now.
	Now func() time.Time
}

// Request describes one GET beyond its URL.
type Request struct {
	// Accept is the Accept header; empty means "*/*". It is part of the cache key
	// because registries serve different documents per media type.
	Accept string
	// Header holds additional headers. User-Agent and Accept always win over it.
	Header http.Header
	// TTL is how long a cached copy is served without revalidation. Zero means
	// DefaultTTL; Forever means the entry never expires.
	TTL time.Duration
}

// Response is the outcome of a Get. Body is fully read.
type Response struct {
	Body       []byte
	StatusCode int
	Header     http.Header
	// FromCache reports that the body came from the disk cache, either because the
	// entry was fresh or because the server answered a revalidation with 304.
	FromCache bool
	// FetchedAt is when the body was last confirmed by the server.
	FetchedAt time.Time
}

// Client is a cached, rate limited, retrying HTTP client. It is safe for
// concurrent use.
type Client struct {
	dir       string
	offline   bool
	noCache   bool
	userAgent string
	timeout   time.Duration
	retries   int
	hostRPS   map[string]float64
	http      *http.Client
	log       *slog.Logger
	now       func() time.Time
	// sleep waits between retries; tests replace it to assert delays.
	sleep func(ctx context.Context, d time.Duration) error

	limMu    sync.Mutex
	limiters map[string]*rate.Limiter

	// keys serializes work on one cache entry so concurrent Gets of the same URL
	// share a single fetch and never interleave their writes.
	keyMu sync.Mutex
	keys  map[string]*sync.Mutex
}

// New validates opts, fills in the defaults and creates the cache directory
// unless NoCache is set.
func New(opts Options) (*Client, error) { //nolint:gocritic // Options by value is the documented API; one copy per client

	if opts.UserAgent == "" {
		return nil, errors.New("httpcache: Options.UserAgent is required")
	}
	if opts.Timeout < 0 {
		return nil, fmt.Errorf("httpcache: Options.Timeout must not be negative, got %v", opts.Timeout)
	}
	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}
	retries := opts.Retries
	switch {
	case retries == 0:
		retries = defaultRetries
	case retries < 0:
		retries = 0
	}
	hostRPS := map[string]float64{cratesHost: cratesRPS}
	for host, rps := range opts.HostRPS {
		if rps <= 0 || math.IsNaN(rps) || math.IsInf(rps, 0) {
			return nil, fmt.Errorf("httpcache: Options.HostRPS[%q] must be positive, got %v", host, rps)
		}
		hostRPS[strings.ToLower(host)] = rps
	}
	dir := opts.Dir
	if dir == "" {
		var err error
		if dir, err = DefaultDir(); err != nil {
			return nil, fmt.Errorf("httpcache: %w", err)
		}
	}
	if !opts.NoCache {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("httpcache: creating cache directory: %w", err)
		}
	}
	transport := opts.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Client{
		dir:       dir,
		offline:   opts.Offline,
		noCache:   opts.NoCache,
		userAgent: opts.UserAgent,
		timeout:   opts.Timeout,
		retries:   retries,
		hostRPS:   hostRPS,
		http:      &http.Client{Transport: transport},
		log:       logger,
		now:       now,
		sleep:     sleepContext,
		limiters:  map[string]*rate.Limiter{},
		keys:      map[string]*sync.Mutex{},
	}, nil
}

// Dir returns the cache directory the client reads and writes.
func (c *Client) Dir() string { return c.dir }

// sleepContext waits for d or until ctx is done.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
