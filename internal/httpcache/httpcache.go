// Package httpcache is the only way trustdiff talks to the network. Every registry
// and advisory client goes through it, so this is where the polite behavior lives:
// a disk cache keyed by request with ETag and Last-Modified revalidation and a TTL
// per entry, a per-host rate limiter (crates.io asks for one request per second),
// retries with exponential backoff and jitter that honor Retry-After, one budget
// for the response headers and a second for the body, redirects that must stay on
// the host the caller named, an identifying User-Agent, and the --offline and
// --no-cache modes.
//
// Get is the common case. Post exists for the batch query endpoints (OSV
// querybatch, deps.dev versionbatch and findingsbatch), which are read-only
// lookups that take their parameters in a JSON body. Post is cached, limited and
// retried exactly like Get. The differences are that the sha256 of the body is
// part of the cache key, that the body is never written to disk, and that an
// expired entry is fetched again instead of revalidated, because conditional
// headers do not apply to POST. Post must only be used for idempotent queries,
// since a retry repeats the request.
//
// The cache is a flat directory of plain files. Each entry is a metadata file
// <sha256>.json and a body file <sha256>.body, where the hash covers the method,
// the URL, the Accept header and, for a POST, the sha256 of the request body.
// Both are written atomically, and an entry whose metadata does not parse, or
// whose body is not the length the metadata recorded, is treated as a miss. Stat
// and Clear operate on such a directory; Clear refuses to touch a directory that
// holds anything this package did not write.
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
	// entry is served from the cache for as long as it exists. A 404 is never
	// immutable, whatever the caller asked for: the version may be published or
	// replicated a moment later, so Get and Post cap its freshness at DefaultTTL.
	Forever = time.Duration(math.MaxInt64)
	// EnvDir names the environment variable that overrides the cache directory.
	EnvDir = "TRUSTDIFF_CACHE_DIR"

	// defaultHeaderTimeout bounds one attempt up to the response headers: the
	// connect, the TLS handshake and the wait for the status line. Every registry
	// answered in well under a second on 2026-09-11, so ten seconds is the margin
	// the single old budget was meant to give.
	defaultHeaderTimeout = 10 * time.Second
	// defaultBodyTimeout caps reading one body, counted from the moment the headers
	// arrive. It is a budget of its own because a slow body says the document is
	// large, not that the host is down: registry.npmjs.org/typescript was 2,007,058
	// bytes on the wire on 2026-09-11, which ten seconds could only finish above
	// 200 KiB/s, while forty five asks for 45 KiB/s.
	defaultBodyTimeout = 45 * time.Second
	defaultRetries     = 3
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

// ErrOffline is returned (wrapped) by Get and Post when the client is offline and
// the request is not in the cache. Callers use errors.Is and report the check as
// skipped.
var ErrOffline = errors.New("offline and not in the cache")

// ErrForeignFiles is returned (wrapped) by Clear when the directory contains files
// or subdirectories this package did not write, so a wrong directory is never wiped.
var ErrForeignFiles = errors.New("refusing to clear a directory trustdiff did not fill")

// ErrBodyTooLarge is returned (wrapped) by Get and Post when a response body
// exceeds the size cap. The request is not retried, because a second download
// would not be smaller, and nothing is cached. Callers use errors.Is to report
// the reason distinctly from a transport error.
var ErrBodyTooLarge = errors.New("response body too large")

// StatusError is returned by Get and Post for a final status that is neither 2xx
// nor 404, after retries were exhausted for 429 and 5xx. Callers use errors.As.
type StatusError struct {
	// Method is GET or POST. The package always sets it; a value built without
	// one reads as a GET.
	Method     string
	URL        string
	StatusCode int
}

func (e *StatusError) Error() string {
	method := e.Method
	if method == "" {
		method = http.MethodGet
	}
	return fmt.Sprintf("%s %s: unexpected status %d %s", method, e.URL, e.StatusCode, http.StatusText(e.StatusCode))
}

// Options configures a Client. The zero value of every field except UserAgent
// selects the documented default.
type Options struct {
	// Dir is the cache directory. Empty means DefaultDir(), resolved only when the
	// cache is used, so a NoCache client works without a user cache directory.
	Dir string
	// Offline serves the cache regardless of TTL and never touches the network.
	Offline bool
	// NoCache neither reads nor writes the cache.
	NoCache bool
	// UserAgent is sent with every request and is required; callers pass
	// version.UserAgent().
	UserAgent string
	// HeaderTimeout bounds one attempt up to the response headers. Default 10 s.
	HeaderTimeout time.Duration
	// BodyTimeout bounds reading one response body once the headers are in.
	// Default 45 s. It is separate because a slow body means a large document
	// rather than a host that is not answering, and abandoning it early throws
	// away the bytes that already arrived.
	BodyTimeout time.Duration
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

// Request describes one Get or Post beyond its URL and, for a Post, its body.
type Request struct {
	// Accept is the Accept header; empty means "*/*". It is part of the cache key
	// because registries serve different documents per media type.
	Accept string
	// Header holds additional headers. User-Agent, Accept and, for a Post,
	// Content-Type always win over it.
	Header http.Header
	// TTL is how long a cached copy is served without revalidation. Zero means
	// DefaultTTL; Forever means the entry never expires. The TTL of the current
	// request decides freshness, so a caller asking for a short TTL revalidates an
	// entry that another caller stored under a longer one. A 404 is capped at
	// DefaultTTL, see Forever.
	TTL time.Duration
}

// Response is the outcome of a Get or Post. Body is fully read.
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
	dir           string
	offline       bool
	noCache       bool
	userAgent     string
	headerTimeout time.Duration
	bodyTimeout   time.Duration
	retries       int
	// maxBody caps one response body; it is maxBodyBytes outside tests.
	maxBody int64
	hostRPS map[string]float64
	http    *http.Client
	log     *slog.Logger
	now     func() time.Time
	// sleep waits between retries; tests replace it to assert delays.
	sleep func(ctx context.Context, d time.Duration) error

	limMu    sync.Mutex
	limiters map[string]*rate.Limiter

	// keys serializes work on one cache entry so concurrent requests for the
	// same entry share a single fetch and never interleave their writes.
	keyMu sync.Mutex
	keys  map[string]*sync.Mutex
}

// New validates opts, fills in the defaults and creates the cache directory
// unless NoCache is set.
func New(opts Options) (*Client, error) { //nolint:gocritic // Options by value is the documented API; one copy per client

	if opts.UserAgent == "" {
		return nil, errors.New("httpcache: Options.UserAgent is required")
	}
	if opts.HeaderTimeout < 0 {
		return nil, fmt.Errorf("httpcache: Options.HeaderTimeout must not be negative, got %v", opts.HeaderTimeout)
	}
	if opts.HeaderTimeout == 0 {
		opts.HeaderTimeout = defaultHeaderTimeout
	}
	if opts.BodyTimeout < 0 {
		return nil, fmt.Errorf("httpcache: Options.BodyTimeout must not be negative, got %v", opts.BodyTimeout)
	}
	if opts.BodyTimeout == 0 {
		opts.BodyTimeout = defaultBodyTimeout
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
	// The directory is only resolved when it will be used: a NoCache client must
	// work where the platform cache directory cannot be located, such as a
	// minimal container without a home directory.
	dir := opts.Dir
	if dir == "" && !opts.NoCache {
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
		dir:           dir,
		offline:       opts.Offline,
		noCache:       opts.NoCache,
		userAgent:     opts.UserAgent,
		headerTimeout: opts.HeaderTimeout,
		bodyTimeout:   opts.BodyTimeout,
		retries:       retries,
		maxBody:       maxBodyBytes,
		hostRPS:       hostRPS,
		http:          &http.Client{Transport: transport, CheckRedirect: checkRedirect(logger)},
		log:           logger,
		now:           now,
		sleep:         sleepContext,
		limiters:      map[string]*rate.Limiter{},
		keys:          map[string]*sync.Mutex{},
	}, nil
}

// maxRedirects bounds one request's redirect chain. A custom CheckRedirect replaces
// the limit net/http would apply rather than adding to it (checked on Go 1.26 on
// 2026-09-11: a policy that refused only past hop 25 followed 26), so the bound has
// to live here. Nothing trustdiff fetches redirects at all, so five is already more
// than any of it needs.
const maxRedirects = 5

// checkRedirect refuses a redirect that leaves the host the caller named. The cache
// stores an entry under the URL that was requested, not the one that answered, and
// the per-host rate limiter only ever saw the requested host, so a body fetched
// from somewhere else would be written down and later served as that registry's
// answer. A POST is worse: net/http replays the request body on a 307 or a 308, so
// an OSV or deps.dev query would be handed to the redirect target (reproduced on Go
// 1.26 on 2026-09-11).
//
// A hop that stays on the host and does not give up https is followed, so a
// registry that starts normalizing a path does not break a scan. Nothing trustdiff
// talks to redirects today: registry.npmjs.org, api.npmjs.org, crates.io,
// static.crates.io, pypi.org, api.jsr.io, jsr.io, api.osv.dev, api.deps.dev,
// raw.githubusercontent.com and hugovk.dev each answered directly on both the found
// and the not-found path, checked 2026-09-11. crates.io does redirect
// /api/v1/crates/<name>/<version>/download to static.crates.io, but the archive
// client builds the static URL itself and never asks for that one.
//
// The host is the unit, not the registered domain, because the two moves a
// registry could make across a domain, pypi.org to files.pythonhosted.org and
// crates.io to static.crates.io, cross it anyway, so a domain rule would buy
// nothing and give up the property being defended.
//
// http.ErrUseLastResponse hands the 3xx back rather than raising a transport error,
// so a refusal reaches the caller as a StatusError naming the status, is not
// retried, and is not cached.
func checkRedirect(log *slog.Logger) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		// net/http calls this only for a redirect, so via always holds at least the
		// request that was answered with one.
		first := via[0].URL
		switch {
		case !strings.EqualFold(req.URL.Host, first.Host):
			log.Warn("refusing a redirect to another host", "from", first.String(), "to", req.URL.String())
		case first.Scheme == "https" && req.URL.Scheme != "https":
			log.Warn("refusing a redirect off https", "from", first.String(), "to", req.URL.String())
		case len(via) > maxRedirects:
			log.Warn("refusing a redirect chain that does not end", "from", first.String(), "hops", len(via))
		default:
			return nil
		}
		return http.ErrUseLastResponse
	}
}

// Dir returns the cache directory the client reads and writes. It is empty for a
// NoCache client that did not set Options.Dir, since no directory was resolved.
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
