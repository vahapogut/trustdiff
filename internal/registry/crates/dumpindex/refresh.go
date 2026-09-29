package dumpindex

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// URL is the public database export, verified with the crates.io data-access
// page and crates_io_database_dump at commit 0498d51e0f06f379c8e570db1628763ad4be7927
// on 2026-09-29. The tar contains <timestamp>/metadata.json and data/*.csv.
const URL = "https://static.crates.io/db-dump.tar.gz"

// Options controls a refresh. Zero limits select the production bounds. URL and
// HTTPClient allow offline httptest fixtures without changing the production URL.
type Options struct {
	URL              string
	HTTPClient       *http.Client
	UserAgent        string
	Now              func() time.Time
	MaxDownloadBytes int64
	MaxExpandedBytes int64
	MaxIndexBytes    int64
	MaxRowBytes      int64
	MaxRecords       int
}

func (o *Options) defaults() {
	if o.URL == "" {
		o.URL = URL
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Minute}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxDownloadBytes <= 0 {
		o.MaxDownloadBytes = 4 << 30
	}
	if o.MaxExpandedBytes <= 0 {
		o.MaxExpandedBytes = 64 << 30
	}
	if o.MaxIndexBytes <= 0 {
		o.MaxIndexBytes = 4 << 30
	}
	if o.MaxRowBytes <= 0 {
		o.MaxRowBytes = 16 << 20
	}
	if o.MaxRecords <= 0 {
		o.MaxRecords = 30_000_000
	}
}

// Refresh downloads once, validates a complete new generation, then atomically
// replaces current.json. It never extracts an archive-supplied filesystem path.
func Refresh(ctx context.Context, cacheDir string, options *Options) (*Meta, error) {
	var o Options
	if options != nil {
		o = *options
	}
	o.defaults()
	dir := Dir(cacheDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := realDir(dir); err != nil {
		return nil, err
	}
	// #nosec G304 -- dir is the selected cache directory; the lock filename is fixed and O_EXCL rejects links.
	lock, err := os.OpenFile(filepath.Join(dir, "refresh.lock"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("crates dump refresh lock (another refresh may be running): %w", err)
	}
	_ = lock.Close()
	defer os.Remove(filepath.Join(dir, "refresh.lock"))
	stage, err := os.MkdirTemp(dir, "build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage) // stage is created by MkdirTemp below this index directory.
	archive, size, digest, err := download(ctx, stage, &o)
	if err != nil {
		return nil, fmt.Errorf("crates dump download: %w", err)
	}
	if err := extract(ctx, archive, stage, &o); err != nil {
		return nil, fmt.Errorf("crates dump archive: %w", err)
	}
	meta, err := build(ctx, stage, &o)
	if err != nil {
		return nil, fmt.Errorf("crates dump index: %w", err)
	}
	meta.Source, meta.ArchiveBytes, meta.ArchiveSHA256 = o.URL, size, digest
	meta.Generation, meta.FetchedAt, meta.Format = "g-"+digest, o.Now().UTC(), 1
	if meta.SnapshotAt.After(meta.FetchedAt.Add(5 * time.Minute)) {
		return nil, errors.New("crates dump snapshot is dated in the future")
	}
	if previous, err := ReadMeta(cacheDir); err == nil && previous.SnapshotAt.After(meta.SnapshotAt) {
		return nil, errors.New("crates dump refresh refuses an older upstream snapshot")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	gen := filepath.Join(dir, meta.Generation)
	if _, err := os.Lstat(gen); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(filepath.Join(stage, "index"), gen); err != nil {
			return nil, fmt.Errorf("installing crates dump generation: %w", err)
		}
	} else {
		// Repeated identical downloads may reuse a generation only after checking
		// all its bytes. A corrupted old generation cannot be published as fresh.
		if err := verifyGeneration(ctx, gen, meta); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(dir, "current-*.tmp")
	if err != nil {
		return nil, err
	}
	defer os.Remove(temp.Name())
	_, writeErr := temp.Write(append(b, '\n'))
	err = errors.Join(writeErr, temp.Sync(), temp.Close())
	if err != nil {
		return nil, err
	}
	if err := os.Rename(temp.Name(), filepath.Join(dir, "current.json")); err != nil {
		return nil, fmt.Errorf("publishing crates dump index: %w", err)
	}
	return meta, nil
}

func download(ctx context.Context, stage string, o *Options) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.URL, nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("User-Agent", o.UserAgent)
	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if resp.ContentLength > o.MaxDownloadBytes {
		return "", 0, "", errors.New("download exceeds compressed byte limit")
	}
	// #nosec G304 -- stage is a private MkdirTemp directory and the filename is fixed.
	f, err := os.OpenFile(filepath.Join(stage, "archive.tar.gz"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, "", err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(&contextReader{ctx: ctx, reader: resp.Body}, o.MaxDownloadBytes+1))
	err = errors.Join(copyErr, f.Close())
	if err != nil {
		return "", 0, "", err
	}
	if n > o.MaxDownloadBytes {
		return "", 0, "", errors.New("download exceeds compressed byte limit")
	}
	return f.Name(), n, hex.EncodeToString(h.Sum(nil)), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func extract(ctx context.Context, archive, stage string, o *Options) error {
	// #nosec G304 -- archive is the file download just created inside its private staging directory.
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	// This limit covers all expanded bytes, including ignored files and tar
	// headers. Entry-count and logical CSV-row limits cover tiny-file and row bombs.
	expanded := &io.LimitedReader{R: &contextReader{ctx: ctx, reader: gz}, N: o.MaxExpandedBytes + 1}
	tr := tar.NewReader(expanded)
	selected := map[string]bool{"metadata.json": true, "data/crates.csv": true, "data/users.csv": true, "data/versions.csv": true, "data/teams.csv": true, "data/crate_owners.csv": true}
	seen := map[string]bool{}
	root := ""
	for entries := 0; ; entries++ {
		if entries >= 1024 {
			return errors.New("archive has too many entries")
		}
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || strings.ContainsAny(name, "\\\x00:") || path.IsAbs(name) || path.Clean(name) != name || strings.HasPrefix(name, "../") {
			return fmt.Errorf("unsafe archive path %q", h.Name)
		}
		parts := strings.SplitN(name, "/", 2)
		if root == "" {
			root = parts[0]
		}
		if parts[0] != root {
			return errors.New("archive has multiple roots")
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("archive has unsupported entry type for %q", h.Name)
		}
		if h.Size < 0 || h.Size > o.MaxExpandedBytes {
			return errors.New("archive entry exceeds expanded byte limit")
		}
		if len(parts) != 2 || !selected[parts[1]] {
			continue
		}
		if seen[parts[1]] {
			return fmt.Errorf("duplicate archive table %s", parts[1])
		}
		seen[parts[1]] = true
		if parts[1] == "metadata.json" && h.Size > maxMeta {
			return errors.New("archive metadata exceeds limit")
		}
		// #nosec G304 -- parts[1] matched the fixed selected-table allowlist; only its basename is used.
		out, err := os.OpenFile(filepath.Join(stage, path.Base(parts[1])), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(tr, h.Size))
		if err := errors.Join(copyErr, out.Close()); err != nil {
			return err
		}
	}
	// Read through the gzip trailer so a truncated stream or bad CRC cannot
	// publish a complete-looking index; trailing bytes share the expansion cap.
	if _, err := io.Copy(io.Discard, expanded); err != nil {
		return err
	}
	if expanded.N <= 0 {
		return errors.New("archive exceeds expanded byte limit")
	}
	for _, name := range []string{"metadata.json", "data/crates.csv", "data/users.csv", "data/versions.csv"} {
		if !seen[name] {
			return fmt.Errorf("archive lacks %s", name)
		}
	}
	return nil
}

func verifyGeneration(ctx context.Context, dir string, meta *Meta) error {
	if err := realDir(dir); err != nil {
		return err
	}
	for name, pin := range meta.Shards {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, err := readRegular(filepath.Join(dir, name), pin.Bytes)
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		if int64(len(b)) != pin.Bytes || hex.EncodeToString(h[:]) != pin.SHA256 {
			return errors.New("existing crates dump generation is corrupt; clear the cache before refreshing")
		}
	}
	return nil
}
