package osvindex

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// DefaultTimeout bounds one ecosystem's download and build. The npm archive was
// 204.9 MiB on 2026-09-10, which is minutes on a slow link, so the budget is
// generous; it exists to end a stalled connection, not to hurry anyone.
const DefaultTimeout = 15 * time.Minute

// Options configure a Refresh. UserAgent is the only required field; every zero
// value selects the documented default.
type Options struct {
	// BaseURL is the bucket the archives are fetched from. Empty means
	// SourceBaseURL; the tests point it at an httptest server.
	BaseURL string
	// UserAgent identifies trustdiff to the server and is required. Callers pass
	// version.UserAgent(), the same string every other client sends.
	UserAgent string
	// Transport is the round tripper. Default http.DefaultTransport.
	Transport http.RoundTripper
	// Timeout bounds one ecosystem, download and build together. Default
	// DefaultTimeout.
	Timeout time.Duration
	// Limits bound what is read out of an archive. The zero value is the
	// documented set of defaults.
	Limits Limits
	// Logger receives diagnostics. Default discards.
	Logger *slog.Logger
	// Now supplies the clock recorded in the metadata. Default time.Now.
	Now func() time.Time
}

// Result is what a refresh did for one ecosystem. Err is set when that ecosystem
// failed, and the others in the same call still carry their own outcome: one
// archive that will not download must not lose the two that did.
type Result struct {
	Ecosystem model.Ecosystem
	// Meta is the metadata now on disk, zero when the ecosystem failed.
	Meta Meta
	// Unchanged is true when the server answered 304 and the index on disk was
	// kept as it was; only its confirmation time moved forward.
	Unchanged bool
	// WroteShards and RemovedShards say how much of the index actually changed.
	// Both are zero for an archive that was downloaded again but produced
	// identical shards, which is the point of building deterministically.
	WroteShards   int
	RemovedShards int
	Err           error
}

// Refresh downloads the OSV archive of each ecosystem and rebuilds its index
// under cacheDir. It returns one Result per ecosystem in the order given, with
// per-ecosystem failures inside the results; the error return is only for a
// request it cannot start at all, such as an ecosystem OSV does not publish.
//
// The ecosystems are done one at a time. That is the rate limit: three sequential
// requests to one storage bucket need no pacing, and doing them in parallel would
// mean holding two archives at once for no gain on the link that matters.
func Refresh(ctx context.Context, cacheDir string, ecosystems []model.Ecosystem, opts Options) ([]Result, error) { //nolint:gocritic // Options by value is the documented API, matching httpcache.New; one copy per call

	if opts.UserAgent == "" {
		return nil, errors.New("osvindex: Options.UserAgent is required")
	}
	if len(ecosystems) == 0 {
		return nil, errors.New("osvindex: no ecosystem to refresh")
	}
	for _, eco := range ecosystems {
		if OSVEcosystem(eco) == "" {
			return nil, fmt.Errorf("osvindex: OSV publishes no advisory archive for %s", eco)
		}
	}
	base := opts.BaseURL
	if base == "" {
		base = SourceBaseURL
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	limits := opts.Limits.withDefaults()
	client := &http.Client{Transport: opts.Transport}

	results := make([]Result, 0, len(ecosystems))
	for _, eco := range ecosystems {
		res := refreshOne(ctx, client, cacheDir, eco, base, opts.UserAgent, timeout, limits, now, log)
		results = append(results, res)
		if done(ctx) {
			// A canceled run stops here; the ecosystems already done keep their
			// results and their files.
			break
		}
	}
	return results, nil
}

// done reports whether ctx has been canceled or has timed out.
func done(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// refreshOne downloads and rebuilds one ecosystem, never returning an error of
// its own: whatever went wrong is in Result.Err.
func refreshOne(ctx context.Context, client *http.Client, cacheDir string, eco model.Ecosystem,
	base, userAgent string, timeout time.Duration, limits Limits, now func() time.Time, log *slog.Logger) Result {
	res := Result{Ecosystem: eco}
	url := ArchiveURL(base, eco)
	dir := ecosystemDir(cacheDir, eco)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	prev := usablePrevious(cacheDir, eco, log)
	got, err := download(ctx, client, url, userAgent, dir, prev, limits.MaxArchiveBytes, log)
	if err != nil {
		res.Err = err
		return res
	}
	if got.Unchanged {
		if prev == nil {
			// download refuses a 304 with nothing to match against, so this cannot
			// happen; the guard is here because the alternative is a panic in a
			// command people run on a schedule.
			res.Err = fmt.Errorf("osvindex: %s: unchanged with no index to keep", eco)
			return res
		}
		meta := *prev
		meta.DownloadedAt = now().UTC()
		if err := writeMeta(cacheDir, &meta); err != nil {
			res.Err = err
			return res
		}
		log.Debug("osv index kept", "ecosystem", eco, "url", url, "advisories", meta.Advisories)
		res.Meta, res.Unchanged = meta, true
		return res
	}
	defer func() {
		if _, err := removeIfPresent(got.Path); err != nil {
			log.Debug("could not remove the downloaded archive", "file", got.Path, "error", err)
		}
	}()

	built, err := BuildFromZip(got.Path, eco, limits, log)
	if err != nil {
		res.Err = err
		return res
	}
	written, removed, err := WriteShards(cacheDir, built)
	if err != nil {
		res.Err = err
		return res
	}
	meta := Meta{
		Schema:        Schema,
		Ecosystem:     eco,
		OSVEcosystem:  OSVEcosystem(eco),
		SourceURL:     url,
		ETag:          got.ETag,
		LastModified:  got.LastModified,
		DownloadedAt:  now().UTC(),
		ArchiveBytes:  got.Bytes,
		ArchiveSHA256: got.SHA256,
		Advisories:    built.Advisories,
		Withdrawn:     built.Withdrawn,
		Packages:      built.Packages,
		Shards:        len(built.Shards),
		Unusable:      built.Unusable,
		IndexBytes:    built.Bytes,
	}
	if err := writeMeta(cacheDir, &meta); err != nil {
		res.Err = err
		return res
	}
	log.Info("osv index refreshed", "ecosystem", eco, "advisories", meta.Advisories, "packages", meta.Packages,
		"shards", meta.Shards, "written", written, "removed", removed)
	res.Meta, res.WroteShards, res.RemovedShards = meta, written, removed
	return res
}

// usablePrevious returns the metadata of the index on disk, and nil when there is
// nothing on disk to revalidate against. readMeta answers that question for the
// whole package: it reports an ecosystem as indexed only when the shard files the
// metadata counts are there too. Revalidating against a metadata file whose
// shards someone deleted would answer 304 and leave the ecosystem permanently
// empty, so in that case the archive is downloaded in full.
func usablePrevious(cacheDir string, eco model.Ecosystem, log *slog.Logger) *Meta {
	meta, err := readMeta(cacheDir, eco)
	if err != nil || meta == nil {
		log.Debug("no usable index on disk, downloading the archive in full", "ecosystem", eco, "error", err)
		return nil
	}
	return meta
}

// shardFileName matches a finished shard file, which is what countShards counts.
var shardFileName = regexp.MustCompile(`^[0-9a-f]{2}\.json$`)

// countShards counts the finished shard files of one ecosystem directory. A
// directory that is missing, or that cannot be listed at all, counts as none:
// that is the answer every caller wants, since shard files nobody can list are
// shard files nobody can read either, and the ecosystem is then not indexed.
func countShards(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && shardFileName.MatchString(e.Name()) {
			n++
		}
	}
	return n
}
