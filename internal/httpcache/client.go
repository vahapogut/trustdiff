package httpcache

import (
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
	u, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	if req.TTL <= 0 {
		req.TTL = DefaultTTL
	}
	accept := req.Accept
	if accept == "" {
		accept = "*/*"
	}
	if c.noCache {
		if c.offline {
			return nil, fmt.Errorf("GET %s: %w", rawURL, ErrOffline)
		}
		return c.fetch(ctx, u, rawURL, accept, req.Header, nil)
	}

	key := cacheKey(http.MethodGet, rawURL, accept)
	unlock := c.lockKey(key)
	defer unlock()

	cached := c.readEntry(key, rawURL, accept)
	if cached != nil && (c.offline || cached.meta.fresh(c.now(), effectiveTTL(req.TTL, cached.meta.Status))) {
		c.log.Debug("cache hit", "url", rawURL, "fetched_at", cached.meta.FetchedAt)
		return cached.response(), nil
	}
	if c.offline {
		return nil, fmt.Errorf("GET %s: %w", rawURL, ErrOffline)
	}

	var validators *entryMeta
	if cached != nil {
		validators = &cached.meta
		c.log.Debug("cache expired, revalidating", "url", rawURL, "fetched_at", cached.meta.FetchedAt)
	} else {
		c.log.Debug("cache miss", "url", rawURL)
	}
	resp, err := c.fetch(ctx, u, rawURL, accept, req.Header, validators)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotModified {
		// fetch admits a 304 only for a conditional request, and validators are
		// sent only when cached is set, so the entry is always there to refresh.
		cached.meta.FetchedAt = resp.FetchedAt
		cached.meta.TTL = effectiveTTL(req.TTL, cached.meta.Status)
		if v := resp.Header.Get("ETag"); v != "" {
			cached.meta.ETag = v
		}
		if v := resp.Header.Get("Last-Modified"); v != "" {
			cached.meta.LastModified = v
		}
		if err := c.writeMeta(key, &cached.meta); err != nil {
			c.log.Warn("cache metadata not refreshed", "url", rawURL, "error", err)
		}
		return cached.response(), nil
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		meta := &entryMeta{
			URL:          rawURL,
			Accept:       accept,
			ETag:         resp.Header.Get("ETag"),
			LastModified: resp.Header.Get("Last-Modified"),
			FetchedAt:    resp.FetchedAt,
			TTL:          effectiveTTL(req.TTL, resp.StatusCode),
			Status:       resp.StatusCode,
			ContentType:  resp.Header.Get("Content-Type"),
		}
		if err := c.writeEntry(key, meta, resp.Body); err != nil {
			c.log.Warn("cache entry not written", "url", rawURL, "error", err)
		}
	}
	return resp, nil
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
// response for 2xx, 304 and 404, and an error otherwise.
func (c *Client) fetch(ctx context.Context, u *url.URL, rawURL, accept string, extra http.Header, validators *entryMeta) (*Response, error) {
	host := strings.ToLower(u.Host)
	limiter := c.limiterFor(host)
	for attempt := 0; ; attempt++ {
		if err := limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("GET %s: waiting for the %s rate limiter: %w", rawURL, host, err)
		}
		resp, err := c.attempt(ctx, rawURL, accept, extra, validators)
		if err == nil && !retryableStatus(resp.StatusCode) {
			if acceptableStatus(resp.StatusCode, validators != nil) {
				return resp, nil
			}
			return nil, &StatusError{URL: rawURL, StatusCode: resp.StatusCode}
		}
		if errors.Is(err, ErrBodyTooLarge) {
			return nil, fmt.Errorf("GET %s: %w", rawURL, err)
		}
		// Never retry once the caller gave up; a per-attempt timeout is retried
		// because it leaves the parent context intact.
		if ctx.Err() != nil {
			if err == nil {
				err = ctx.Err()
			}
			return nil, fmt.Errorf("GET %s: %w", rawURL, err)
		}
		if attempt >= c.retries {
			if err != nil {
				return nil, fmt.Errorf("GET %s: after %d attempts: %w", rawURL, attempt+1, err)
			}
			return nil, &StatusError{URL: rawURL, StatusCode: resp.StatusCode}
		}
		var retryAfter time.Duration
		reason := "transport error"
		if err == nil {
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), c.now())
			reason = "status " + strconv.Itoa(resp.StatusCode)
		}
		delay := c.backoff(attempt, retryAfter)
		c.log.Warn("retrying request", "url", rawURL, "attempt", attempt+1, "reason", reason, "error", err, "delay", delay)
		if err := c.sleep(ctx, delay); err != nil {
			return nil, fmt.Errorf("GET %s: %w", rawURL, err)
		}
	}
}

// attempt performs one request within the per-attempt timeout and reads the body.
func (c *Client) attempt(ctx context.Context, rawURL, accept string, extra http.Header, validators *entryMeta) (*Response, error) {
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(actx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	for name, values := range extra {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", accept)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if int64(len(body)) > c.maxBody {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrBodyTooLarge, c.maxBody)
	}
	return &Response{
		Body:       body,
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

// parseURL accepts absolute http and https URLs only.
func parseURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("GET %q: %w", rawURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("GET %q: not an absolute http or https URL", rawURL)
	}
	return u, nil
}

// cacheKey hashes the method, URL and Accept header into the entry file stem.
func cacheKey(method, rawURL, accept string) string {
	sum := sha256.Sum256([]byte(method + "\n" + rawURL + "\n" + accept))
	return hex.EncodeToString(sum[:])
}
