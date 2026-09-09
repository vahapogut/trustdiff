package osvindex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

// download fetches one archive into a temporary file under dir and reports what
// it got. It is deliberately small: one request, no retries, because "cache
// refresh" is a command a person runs again, and a re-run after a failure costs
// one conditional request when the archive has not changed since.
//
// prev, when not nil, supplies the ETag and Last-Modified of the copy that built
// the index on disk. They are replayed as If-None-Match and If-Modified-Since,
// so an unchanged archive answers 304 and the caller keeps the index it has: a
// refresh that finds nothing new transfers nothing and rewrites nothing.
//
// The size cap is applied twice. Content-Length is checked before the body is
// touched, which is the case that matters: an archive that is far larger than it
// should be is refused with a message naming the URL and both sizes, and not a
// byte of it is read. A server that sends no Content-Length, or a wrong one, is
// caught by the io.LimitReader around the body, which stops one byte past the
// cap. Nothing is ever buffered whole in memory: the body streams to a file,
// because the npm archive was 204.9 MiB on 2026-09-10 and that is also why this
// download cannot go through internal/httpcache, which buffers and refuses
// anything over 128 MiB.
func download(ctx context.Context, client *http.Client, url, userAgent, dir string, prev *Meta, max int64, log *slog.Logger) (*downloaded, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("osvindex: %s: %w", url, err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/zip")
	if prev != nil {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osvindex: %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		// A 304 to a request that carried no validator is a server or a proxy
		// answering something nobody asked, and there is no previous index to keep,
		// so it is an error rather than an unchanged archive. Reading prev here
		// unconditionally used to panic on exactly that.
		if prev == nil {
			return nil, fmt.Errorf("osvindex: %s: answered 304 although nothing was sent to match against", url)
		}
		log.Debug("osv archive unchanged", "url", url)
		return &downloaded{Unchanged: true, ETag: prev.ETag, LastModified: prev.LastModified}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osvindex: %s: unexpected status %d %s", url, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	if resp.ContentLength > max {
		return nil, fmt.Errorf("osvindex: %s: %w: the server offers %d bytes, the limit is %d",
			url, ErrTooLarge, resp.ContentLength, max)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("osvindex: creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, archiveTempName+".*.tmp")
	if err != nil {
		return nil, fmt.Errorf("osvindex: creating a temporary file in %s: %w", dir, err)
	}
	path := tmp.Name()
	discard := func(cause error) (*downloaded, error) {
		_ = tmp.Close()
		_ = os.Remove(path)
		return nil, cause
	}

	sum := sha256.New()
	// One byte past the cap, so a body that is exactly the cap can be told from
	// one that is over it.
	n, err := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(resp.Body, max+1))
	if err != nil {
		return discard(fmt.Errorf("osvindex: %s: %w", url, err))
	}
	if n > max {
		return discard(fmt.Errorf("osvindex: %s: %w: more than %d bytes", url, ErrTooLarge, max))
	}
	if err := tmp.Sync(); err != nil {
		return discard(fmt.Errorf("osvindex: writing %s: %w", path, err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("osvindex: closing %s: %w", path, err)
	}
	log.Debug("osv archive downloaded", "url", url, "bytes", n, "file", path)
	return &downloaded{
		Path:         path,
		Bytes:        n,
		SHA256:       hex.EncodeToString(sum.Sum(nil)),
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

// downloaded is what one archive request produced. Unchanged means the server
// answered 304 and Path is empty: there is nothing to read and nothing to
// remove.
type downloaded struct {
	Path         string
	Unchanged    bool
	Bytes        int64
	SHA256       string
	ETag         string
	LastModified string
}
