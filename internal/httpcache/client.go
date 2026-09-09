package httpcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Get fetches rawURL through the cache. A fresh entry, under the TTL of this
// request, is served without a request; an expired one is revalidated with
// If-None-Match or If-Modified-Since and a 304 refreshes it. Status 200 and 404
// responses are cached (a 404 is a real answer from a registry, though never for
// longer than DefaultTTL); other 2xx statuses are returned but not cached;
// everything else is a *StatusError after retries. In offline mode the cache is
// served regardless of TTL and a miss is ErrOffline.
func (c *Client) Get(ctx context.Context, rawURL string, req Request) (*Response, error) {
	cl, err := newCall(http.MethodGet, rawURL, nil, req)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, cl)
}

// Post sends body to rawURL as application/json and caches the answer like Get:
// the cache key folds in the method and the sha256 of the body, so two queries
// to one URL with different bodies never share an entry, and the same TTL,
// Offline, NoCache, size cap, per-host rate limiter and retry rules apply,
// including the 404 handling. The body is sent as is, on every attempt, and is
// never written to disk; only its hash is recorded in the entry metadata.
//
// Post is for idempotent query endpoints only, such as OSV querybatch and the
// deps.dev versionbatch and findingsbatch: a 429, a 5xx or a transport error is
// retried with the same body, which is only safe when repeating the request has
// no effect beyond the answer. An expired entry is fetched again rather than
// revalidated: an If-None-Match makes an origin answer a POST with 412 instead
// of 304 (RFC 9110 section 13.1.2) and If-Modified-Since is ignored for any
// method but GET and HEAD (section 13.1.3), both verified 2026-09-09. None of
// the three endpoints sends an ETag or Last-Modified anyway (checked live the
// same day), so nothing is lost.
func (c *Client) Post(ctx context.Context, rawURL string, body []byte, req Request) (*Response, error) {
	cl, err := newCall(http.MethodPost, rawURL, body, req)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, cl)
}

// call is one Get or Post after validation and defaulting, carried through every
// stage from the cache lookup to the retry loop.
type call struct {
	method string
	rawURL string
	host   string
	accept string
	header http.Header
	// body is sent with a POST on every attempt and never written to disk; it is
	// nil for a GET.
	body []byte
	// bodyHash is the hex sha256 of body for a POST and empty for a GET. It is
	// folded into the cache key and recorded in the metadata, so entries for
	// different bodies never collide and a read can confirm the match.
	bodyHash string
	ttl      time.Duration
}

// newCall validates the URL and applies the Request defaults.
func newCall(method, rawURL string, body []byte, req Request) (*call, error) {
	u, err := parseURL(method, rawURL)
	if err != nil {
		return nil, err
	}
	cl := &call{
		method: method,
		rawURL: rawURL,
		host:   strings.ToLower(u.Host),
		accept: req.Accept,
		header: req.Header,
		ttl:    req.TTL,
	}
	if cl.accept == "" {
		cl.accept = "*/*"
	}
	if cl.ttl <= 0 {
		cl.ttl = DefaultTTL
	}
	if method == http.MethodPost {
		sum := sha256.Sum256(body)
		cl.body = body
		cl.bodyHash = hex.EncodeToString(sum[:])
	}
	return cl, nil
}

// key is the cache entry file stem for the call.
func (cl *call) key() string {
	return cacheKey(cl.method, cl.rawURL, cl.accept, cl.bodyHash)
}

// wrap prefixes err with the method and URL, the form every error of Get and
// Post takes.
func (cl *call) wrap(err error) error {
	return fmt.Errorf("%s %s: %w", cl.method, cl.rawURL, err)
}

// statusError builds the error for a final unacceptable status.
func (cl *call) statusError(status int) *StatusError {
	return &StatusError{Method: cl.method, URL: cl.rawURL, StatusCode: status}
}

// do is the path Get and Post share: the cache lookup, the offline rules, the
// fetch with retries, and the cache write.
func (c *Client) do(ctx context.Context, cl *call) (*Response, error) {
	if c.noCache {
		if c.offline {
			return nil, cl.wrap(ErrOffline)
		}
		return c.fetch(ctx, cl, nil)
	}

	key := cl.key()
	unlock := c.lockKey(key)
	defer unlock()

	cached := c.readEntry(key, cl)
	if cached != nil && (c.offline || cached.meta.fresh(c.now(), effectiveTTL(cl.ttl, cached.meta.Status))) {
		c.log.Debug("cache hit", "method", cl.method, "url", cl.rawURL, "fetched_at", cached.meta.FetchedAt)
		return cached.response(), nil
	}
	if c.offline {
		return nil, cl.wrap(ErrOffline)
	}

	// Only a GET revalidates; see Post for why a POST is fetched again instead.
	var validators *entryMeta
	switch {
	case cached == nil:
		c.log.Debug("cache miss", "method", cl.method, "url", cl.rawURL)
	case cl.method == http.MethodGet:
		validators = &cached.meta
		c.log.Debug("cache expired, revalidating", "method", cl.method, "url", cl.rawURL, "fetched_at", cached.meta.FetchedAt)
	default:
		c.log.Debug("cache expired, fetching again", "method", cl.method, "url", cl.rawURL, "fetched_at", cached.meta.FetchedAt)
	}
	resp, err := c.fetch(ctx, cl, validators)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotModified {
		// fetch admits a 304 only for a conditional request, and validators are
		// sent only when cached is set, so the entry is always there to refresh.
		c.refreshEntry(key, cl, cached, resp)
		return cached.response(), nil
	}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		c.storeEntry(key, cl, resp)
	}
	return resp, nil
}

// refreshEntry records a 304: the entry is confirmed as of now under the TTL of
// this call, and any validator the server repeated replaces the stored one.
func (c *Client) refreshEntry(key string, cl *call, cached *entry, resp *Response) {
	cached.meta.FetchedAt = resp.FetchedAt
	cached.meta.TTL = effectiveTTL(cl.ttl, cached.meta.Status)
	if v := resp.Header.Get("ETag"); v != "" {
		cached.meta.ETag = v
	}
	if v := resp.Header.Get("Last-Modified"); v != "" {
		cached.meta.LastModified = v
	}
	if err := c.writeMeta(key, &cached.meta); err != nil {
		c.log.Warn("cache metadata not refreshed", "method", cl.method, "url", cl.rawURL, "error", err)
	}
}

// storeEntry writes a 200 or 404 answer. The metadata identifies the call by
// method, URL, Accept and, for a POST, the hash of the body; the request body
// itself is never written.
func (c *Client) storeEntry(key string, cl *call, resp *Response) {
	meta := &entryMeta{
		Method:       cl.method,
		URL:          cl.rawURL,
		Accept:       cl.accept,
		BodySHA256:   cl.bodyHash,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		FetchedAt:    resp.FetchedAt,
		TTL:          effectiveTTL(cl.ttl, resp.StatusCode),
		Status:       resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
	}
	if err := c.writeEntry(key, meta, resp.Body); err != nil {
		c.log.Warn("cache entry not written", "method", cl.method, "url", cl.rawURL, "error", err)
	}
}

// effectiveTTL is the freshness window for an answer with the given status under
// the TTL the caller asked for. A "not found" is never immutable, whatever the
// caller's TTL: the version may be published or replicated a moment later, and
// the caller cannot choose a TTL per status because it picks one before the
// status is known. So a 404 is revalidated after DefaultTTL at the latest.
func effectiveTTL(ttl time.Duration, status int) time.Duration {
	if status == http.StatusNotFound {
		return min(ttl, DefaultTTL)
	}
	return ttl
}

// fetch performs the request with rate limiting and retries. It returns the final
// response for 2xx, 304 and 404, and an error otherwise. A POST is retried under
// the same rules as a GET, which is why Post is restricted to idempotent queries.
func (c *Client) fetch(ctx context.Context, cl *call, validators *entryMeta) (*Response, error) {
	limiter := c.limiterFor(cl.host)
	for attempt := 0; ; attempt++ {
		if err := limiter.Wait(ctx); err != nil {
			return nil, cl.wrap(fmt.Errorf("waiting for the %s rate limiter: %w", cl.host, err))
		}
		resp, err := c.attempt(ctx, cl, validators)
		if err == nil && !retryableStatus(resp.StatusCode) {
			if acceptableStatus(resp.StatusCode, validators != nil) {
				return resp, nil
			}
			return nil, cl.statusError(resp.StatusCode)
		}
		if errors.Is(err, ErrBodyTooLarge) {
			return nil, cl.wrap(err)
		}
		// Never retry once the caller gave up; a per-attempt timeout is retried
		// because it leaves the parent context intact.
		if ctx.Err() != nil {
			if err == nil {
				err = ctx.Err()
			}
			return nil, cl.wrap(err)
		}
		if attempt >= c.retries {
			if err != nil {
				return nil, cl.wrap(fmt.Errorf("after %d attempts: %w", attempt+1, err))
			}
			return nil, cl.statusError(resp.StatusCode)
		}
		var retryAfter time.Duration
		reason := "transport error"
		if err == nil {
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), c.now())
			reason = "status " + strconv.Itoa(resp.StatusCode)
		}
		delay := c.backoff(attempt, retryAfter)
		c.log.Warn("retrying request", "method", cl.method, "url", cl.rawURL, "attempt", attempt+1, "reason", reason, "error", err, "delay", delay)
		if err := c.sleep(ctx, delay); err != nil {
			return nil, cl.wrap(err)
		}
	}
}

// attempt performs one request within the per-attempt timeout and reads the body.
func (c *Client) attempt(ctx context.Context, cl *call, validators *entryMeta) (*Response, error) {
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var body io.Reader = http.NoBody
	if cl.method == http.MethodPost {
		// A fresh reader per attempt, so a retry sends the whole body again.
		body = bytes.NewReader(cl.body)
	}
	req, err := http.NewRequestWithContext(actx, cl.method, cl.rawURL, body)
	if err != nil {
		return nil, err
	}
	for name, values := range cl.header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", cl.accept)
	if cl.method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if validators != nil {
		if validators.ETag != "" {
			req.Header.Set("If-None-Match", validators.ETag)
		}
		if validators.LastModified != "" {
			req.Header.Set("If-Modified-Since", validators.LastModified)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// One byte past the cap tells an oversized body from one that is exactly at it.
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if int64(len(data)) > c.maxBody {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrBodyTooLarge, c.maxBody)
	}
	return &Response{
		Body:       data,
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		FetchedAt:  c.now(),
	}, nil
}

// acceptableStatus reports whether a status is returned to the caller as a
// Response. A 304 counts only for a conditional request: without validators there
// is nothing it could confirm, so it is a server error like any other.
func acceptableStatus(status int, conditional bool) bool {
	return (status >= 200 && status < 300) || (conditional && status == http.StatusNotModified) || status == http.StatusNotFound
}

// retryableStatus reports whether a status is worth another attempt.
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// backoff returns the delay before the next attempt: Retry-After when the server
// sent one (capped), otherwise exponential growth from baseBackoff with jitter in
// the upper half of the window, capped at maxBackoff.
func (c *Client) backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, maxRetryAfter)
	}
	d := maxBackoff
	if attempt < 8 {
		d = min(baseBackoff<<attempt, maxBackoff)
	}
	half := int64(d / 2)
	jitter := rand.Int64N(half + 1) // #nosec G404 -- retry spacing needs no cryptographic randomness
	return time.Duration(half + jitter)
}

// parseRetryAfter handles both forms of the header, seconds and an HTTP date.
// Anything unparsable or in the past yields zero, which means "use backoff".
// Seconds are clamped to maxRetryAfter before the multiplication, so a huge value
// cannot overflow into a negative duration; backoff caps them there anyway.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	secs, err := strconv.ParseInt(value, 10, 64)
	if err == nil || errors.Is(err, strconv.ErrRange) {
		// ParseInt saturates on ErrRange, so the sign of an out-of-range value
		// survives and it is treated like any other very large or negative one.
		if secs <= 0 {
			return 0
		}
		return time.Duration(min(secs, int64(maxRetryAfter/time.Second))) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		if d := at.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// limiterFor returns the rate limiter for a host, creating it on first use with
// a burst of one so requests are spread evenly instead of arriving in bursts.
func (c *Client) limiterFor(host string) *rate.Limiter {
	host = strings.ToLower(host)
	c.limMu.Lock()
	defer c.limMu.Unlock()
	if lim, ok := c.limiters[host]; ok {
		return lim
	}
	rps, ok := c.hostRPS[host]
	if !ok {
		rps = defaultRPS
	}
	lim := rate.NewLimiter(rate.Limit(rps), 1)
	c.limiters[host] = lim
	return lim
}

// lockKey takes the per-entry mutex and returns the function that releases it.
func (c *Client) lockKey(key string) func() {
	c.keyMu.Lock()
	m, ok := c.keys[key]
	if !ok {
		m = &sync.Mutex{}
		c.keys[key] = m
	}
	c.keyMu.Unlock()
	m.Lock()
	return m.Unlock
}

// parseURL accepts absolute http and https URLs only. method names the caller
// in the error.
func parseURL(method, rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%s %q: %w", method, rawURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%s %q: not an absolute http or https URL", method, rawURL)
	}
	return u, nil
}

// cacheKey hashes the method, URL and Accept header into the entry file stem,
// plus the sha256 of the body for a POST. A GET passes an empty bodyHash and
// hashes exactly the bytes it did before Post existed, so entries written by
// earlier releases stay valid.
func cacheKey(method, rawURL, accept, bodyHash string) string {
	s := method + "\n" + rawURL + "\n" + accept
	if bodyHash != "" {
		s += "\n" + bodyHash
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
