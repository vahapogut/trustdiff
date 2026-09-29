// Package dumpindex reads and builds the plain-file crates.io database index
// used by bulk Cargo scans. It never makes per-crate requests.
package dumpindex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
	"github.com/vahapogut/trustdiff/internal/registry"
)

const (
	// Subdir is reserved under the HTTP cache for this index.
	Subdir = "crates-dump"
	// StaleAfter is the maximum snapshot age used automatically by scans.
	StaleAfter = 48 * time.Hour
	maxMeta    = 128 << 10
	maxShard   = 128 << 20
)

var generationName = regexp.MustCompile(`^g-[0-9a-f]{64}$`)
var shardName = regexp.MustCompile(`^[0-9a-f]{2}\.json$`)

// ErrSnapshotMiss means the selected snapshot cannot answer, not that the live
// registry has no such crate or version. New releases may postdate the dump.
var ErrSnapshotMiss = errors.New("not present in the crates dump snapshot; refresh the index")

// Meta describes an immutable index generation and its upstream snapshot.
type Meta struct {
	Format         int              `json:"format"`
	Generation     string           `json:"generation"`
	Source         string           `json:"source"`
	SnapshotAt     time.Time        `json:"snapshot_at"`
	FetchedAt      time.Time        `json:"fetched_at"`
	UpstreamCommit string           `json:"crates_io_commit"`
	ArchiveSHA256  string           `json:"archive_sha256"`
	ArchiveBytes   int64            `json:"archive_bytes"`
	IndexBytes     int64            `json:"index_bytes"`
	Crates         int              `json:"crates"`
	Versions       int              `json:"versions"`
	Shards         map[string]Shard `json:"shards"`
}

// Shard pins both the size and checksum of a shard.
type Shard struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Age returns the upstream snapshot's age, not the last download's age.
func (m *Meta) Age(now time.Time) time.Duration { return max(0, now.Sub(m.SnapshotAt)) }

// Stale reports whether a scan should use the ordinary API/cache instead.
func (m *Meta) Stale(now time.Time) bool { return m.Age(now) >= StaleAfter }

// Record stores the facts available without additional registry requests.
type Record struct {
	Name        string            `json:"name"`
	Created     time.Time         `json:"created"`
	Modified    time.Time         `json:"modified"`
	Versions    []Version         `json:"versions"`
	Owners      []model.Publisher `json:"owners,omitempty"`
	OwnersKnown bool              `json:"owners_known"`
}

// Version is a compact dump row. A missing Publisher is unknown, not anonymous.
type Version struct {
	Num       string    `json:"v"`
	Published time.Time `json:"at"`
	Publisher string    `json:"by,omitempty"`
	Yanked    bool      `json:"y,omitempty"`
	Checksum  string    `json:"sha,omitempty"`
}

// Index reads verified shards on demand and memoizes only requested crates.
type Index struct {
	dir      string
	Meta     Meta
	mu       sync.Mutex
	records  map[string]*Record
	failures map[string]error
}

// Dir locates the index under a cache directory.
func Dir(cacheDir string) string { return filepath.Join(cacheDir, Subdir) }

// Open validates metadata and freshness. Shard hashes are verified on lookup;
// a damaged selected shard is unavailable data, not an API fallback.
func Open(cacheDir string, now time.Time) (*Index, error) {
	meta, err := ReadMeta(cacheDir)
	if err != nil {
		return nil, err
	}
	if meta.Stale(now) {
		return nil, fmt.Errorf("crates dump snapshot is stale (%s); run trustdiff cache refresh --crates-dump", meta.Age(now).Round(time.Hour))
	}
	if meta.SnapshotAt.After(now.Add(5 * time.Minute)) {
		return nil, errors.New("crates dump snapshot is dated in the future")
	}
	dir := filepath.Join(Dir(cacheDir), meta.Generation)
	if err := realDir(dir); err != nil {
		return nil, err
	}
	return &Index{dir: dir, Meta: *meta, records: map[string]*Record{}, failures: map[string]error{}}, nil
}

// ReadMeta reads bounded metadata without treating stale data as absent.
func ReadMeta(cacheDir string) (*Meta, error) {
	if err := realDir(Dir(cacheDir)); err != nil {
		return nil, err
	}
	data, err := readRegular(filepath.Join(Dir(cacheDir), "current.json"), maxMeta)
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("crates dump metadata: %w", err)
	}
	if m.Format != 1 || !generationName.MatchString(m.Generation) || m.SnapshotAt.IsZero() || m.FetchedAt.IsZero() || m.Crates < 1 || m.Versions < 1 || len(m.Shards) == 0 || len(m.Shards) > 256 {
		return nil, errors.New("crates dump metadata is incomplete or unsupported")
	}
	var total int64
	for name, s := range m.Shards {
		if !shardName.MatchString(name) || s.Bytes < 2 || s.Bytes > maxShard || !validHash(s.SHA256) {
			return nil, errors.New("crates dump metadata has an invalid shard")
		}
		total += s.Bytes
	}
	if m.IndexBytes != total || !validHash(m.ArchiveSHA256) || m.Generation != "g-"+m.ArchiveSHA256 {
		return nil, errors.New("crates dump metadata has inconsistent size or digest")
	}
	return &m, nil
}

func realDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("crates dump: refusing non-directory or symlink %s", dir)
	}
	return nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("crates dump: invalid file or size: %s", path)
	}
	// #nosec G304 -- callers use fixed metadata/table names or validated shard names; Lstat rejects links above.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = errors.New("crates dump file exceeds its size limit")
	}
	return b, err
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func canonical(name string) string { return strings.ReplaceAll(strings.ToLower(name), "-", "_") }
func shardFor(name string) string {
	sum := sha256.Sum256([]byte(canonical(name)))
	return fmt.Sprintf("%02x.json", sum[0])
}

func (i *Index) lookup(ctx context.Context, name string) (*Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validName(name) {
		return nil, fmt.Errorf("invalid crate name %q: %w", name, registry.ErrNotFound)
	}
	key := canonical(name)
	i.mu.Lock()
	defer i.mu.Unlock()
	if r, ok := i.records[key]; ok {
		return r, nil
	}
	if err := i.failures[key]; err != nil {
		return nil, err
	}
	records, err := i.loadShard(ctx, shardFor(name))
	if err != nil {
		return nil, err
	}
	r, err := selectedRecord(records, key)
	if err != nil {
		return nil, err
	}
	i.records[key] = r
	return r, nil
}

func (i *Index) loadShard(ctx context.Context, shard string) (map[string]*Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pin, exists := i.Meta.Shards[shard]
	if !exists {
		return map[string]*Record{}, nil
	}
	b, err := readRegular(filepath.Join(i.dir, shard), pin.Bytes)
	if err != nil {
		return nil, fmt.Errorf("reading crates dump shard: %w", err)
	}
	hash := sha256.Sum256(b)
	if int64(len(b)) != pin.Bytes || hex.EncodeToString(hash[:]) != pin.SHA256 {
		return nil, errors.New("crates dump shard checksum mismatch; refresh the index")
	}
	var records map[string]*Record
	if err := json.Unmarshal(b, &records); err != nil {
		return nil, fmt.Errorf("decoding crates dump shard: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func selectedRecord(records map[string]*Record, key string) (*Record, error) {
	r, ok := records[key]
	if !ok {
		return nil, fmt.Errorf("crate %s: %w", key, ErrSnapshotMiss)
	}
	if r == nil || canonical(r.Name) != key {
		return nil, errors.New("crates dump record name mismatch")
	}
	return r, nil
}

// PrefetchVersions groups scan inputs by shard and reads each shard once, while
// retaining only requested crates. This bounds memory to the scan's metadata
// plus one shard and avoids reparsing the whole index for each locked package.
// Errors are kept per requested crate and later returned by Versions; a failed
// prefetch never silently falls back to the per-crate API.
func (i *Index) PrefetchVersions(ctx context.Context, names []string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	groups := map[string][]string{}
	seen := map[string]bool{}
	for _, name := range names {
		key := canonical(name)
		if seen[key] || i.records[key] != nil || i.failures[key] != nil {
			continue
		}
		seen[key] = true
		shard := shardFor(key)
		groups[shard] = append(groups[shard], key)
	}
	for shard, keys := range groups {
		if ctx.Err() != nil {
			return
		}
		records, err := i.loadShard(ctx, shard)
		if ctx.Err() != nil {
			return
		}
		for _, key := range keys {
			if err != nil {
				i.failures[key] = err
				continue
			}
			r, err := selectedRecord(records, key)
			if err != nil {
				i.failures[key] = err
			} else {
				i.records[key] = r
			}
		}
	}
}

// Ecosystem implements registry.Source.
func (i *Index) Ecosystem() model.Ecosystem { return model.Cargo }

// Versions implements registry.Source using only the selected snapshot.
func (i *Index) Versions(ctx context.Context, name string) (*registry.VersionList, error) {
	r, err := i.lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	list := &registry.VersionList{Ecosystem: model.Cargo, Name: r.Name, Created: r.Created, Modified: r.Modified, Versions: make([]model.VersionInfo, 0, len(r.Versions))}
	for _, v := range r.Versions {
		info := versionInfo(r.Name, &v)
		list.Versions = append(list.Versions, info)
		cmp, _ := version.Compare(model.Cargo, v.Num, list.Latest)
		if !info.Yanked && !info.Prerelease && (list.Latest == "" || cmp > 0) {
			list.Latest = v.Num
		}
	}
	return list, nil
}

func versionInfo(name string, v *Version) model.VersionInfo {
	info := model.VersionInfo{Ref: model.PackageRef{Ecosystem: model.Cargo, Name: name, Version: v.Num}, PublishedAt: v.Published, Prerelease: version.IsPrerelease(model.Cargo, v.Num), Yanked: v.Yanked, Integrity: v.Checksum, WeeklyDownloads: -1}
	if v.Publisher != "" {
		info.Publisher = &model.Publisher{Name: v.Publisher}
	}
	info.SetUnknown(model.FacetScripts, "crates dump mode does not inspect crate archives")
	info.SetUnknown(model.FacetDependencies, "crates dump index does not include dependency rows")
	info.SetUnknown(model.FacetProvenance, "crates.io excludes trustpub_data from its public database dump")
	return info
}

// VersionInfo implements registry.Source without an archive or API request.
func (i *Index) VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	if ref.Ecosystem != "" && ref.Ecosystem != model.Cargo {
		return nil, fmt.Errorf("crates dump: %s is not a Cargo package", ref)
	}
	r, err := i.lookup(ctx, ref.Name)
	if err != nil {
		return nil, err
	}
	for _, v := range r.Versions {
		if v.Num == ref.Version {
			info := versionInfo(r.Name, &v)
			return &info, nil
		}
	}
	return nil, fmt.Errorf("version %s: %w", ref, ErrSnapshotMiss)
}

// Owners returns the current owner set, never an inferred historical owner set.
func (i *Index) Owners(ctx context.Context, name string) ([]model.Publisher, error) {
	r, err := i.lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	if !r.OwnersKnown {
		return nil, fmt.Errorf("crates dump owner identity unavailable: %w", registry.ErrUnsupported)
	}
	return append([]model.Publisher(nil), r.Owners...), nil
}

// Downloads explicitly reports that download rows are not indexed.
func (i *Index) Downloads(_ context.Context, _ string) (int64, error) {
	return 0, fmt.Errorf("crates dump index does not include download counts: %w", registry.ErrUnsupported)
}

var _ registry.Source = (*Index)(nil)
