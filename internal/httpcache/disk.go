package httpcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	metaSuffix = ".json"
	bodySuffix = ".body"
)

// entryFileName matches every file this package writes: the two entry files and
// the temporary files os.CreateTemp creates for them (a decimal suffix, see
// os.CreateTemp, verified 2026-09-09 on go1.26). Clear removes nothing else.
var entryFileName = regexp.MustCompile(`^[0-9a-f]{64}\.(json|body)(\.[0-9]+\.tmp)?$`)

// entryMeta is the metadata half of a cache entry. TTL records what the writer
// asked for, for cache status; freshness is decided by the current request.
type entryMeta struct {
	// Method is GET or POST. Entries written before Post existed carry none and
	// are GETs, see matches.
	Method string
	URL    string
	Accept string
	// BodySHA256 is the hex sha256 of the request body of a POST, and empty for
	// a GET. The body itself is never stored.
	BodySHA256   string
	ETag         string
	LastModified string
	FetchedAt    time.Time
	TTL          time.Duration
	Status       int
	ContentType  string
	// Length is the body size in bytes. A body file of any other length was
	// truncated by a power loss or interleaved with another process's write, and
	// is a miss.
	Length int64
}

// metaJSON is the on-disk form of entryMeta. The TTL is a duration string so the
// file stays readable; Forever is written as the word.
type metaJSON struct {
	Method       string    `json:"method,omitempty"`
	URL          string    `json:"url"`
	Accept       string    `json:"accept"`
	BodySHA256   string    `json:"body_sha256,omitempty"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
	TTL          string    `json:"ttl"`
	Status       int       `json:"status"`
	ContentType  string    `json:"content_type,omitempty"`
	Length       int64     `json:"length"`
}

const foreverWord = "forever"

func (m *entryMeta) marshal() ([]byte, error) {
	ttl := m.TTL.String()
	if m.TTL == Forever {
		ttl = foreverWord
	}
	data, err := json.MarshalIndent(metaJSON{
		Method:       m.Method,
		URL:          m.URL,
		Accept:       m.Accept,
		BodySHA256:   m.BodySHA256,
		ETag:         m.ETag,
		LastModified: m.LastModified,
		FetchedAt:    m.FetchedAt,
		TTL:          ttl,
		Status:       m.Status,
		ContentType:  m.ContentType,
		Length:       m.Length,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding cache metadata: %w", err)
	}
	return append(data, '\n'), nil
}

// parseMeta decodes a metadata file and rejects incomplete ones, so a truncated
// or foreign file is a miss rather than an entry with zero values.
func parseMeta(data []byte) (entryMeta, error) {
	var w metaJSON
	if err := json.Unmarshal(data, &w); err != nil {
		return entryMeta{}, fmt.Errorf("decoding cache metadata: %w", err)
	}
	if w.URL == "" || w.FetchedAt.IsZero() || w.Status == 0 || w.TTL == "" {
		return entryMeta{}, errors.New("decoding cache metadata: missing url, fetched_at, ttl or status")
	}
	if w.Length < 0 {
		return entryMeta{}, fmt.Errorf("decoding cache metadata: negative length %d", w.Length)
	}
	ttl := Forever
	if w.TTL != foreverWord {
		var err error
		if ttl, err = time.ParseDuration(w.TTL); err != nil {
			return entryMeta{}, fmt.Errorf("decoding cache metadata ttl: %w", err)
		}
	}
	return entryMeta{
		Method:       w.Method,
		URL:          w.URL,
		Accept:       w.Accept,
		BodySHA256:   w.BodySHA256,
		ETag:         w.ETag,
		LastModified: w.LastModified,
		FetchedAt:    w.FetchedAt,
		TTL:          ttl,
		Status:       w.Status,
		ContentType:  w.ContentType,
		Length:       w.Length,
	}, nil
}

// matches reports whether the entry was written for exactly this request: same
// method, URL, Accept header and, for a POST, the same body hash. It is the
// guard against a hash collision or a file that ended up under the wrong name.
// Entries written before Post existed carry no method and are GETs.
func (m *entryMeta) matches(method, rawURL, accept, bodyHash string) bool {
	stored := m.Method
	if stored == "" {
		stored = http.MethodGet
	}
	return stored == method && m.URL == rawURL && m.Accept == accept && m.BodySHA256 == bodyHash
}

// fresh reports whether the entry may be served at now without revalidation
// under the freshness ttl the current caller asked for. The TTL stored with the
// entry is not consulted: another caller may have asked for a longer one.
func (m *entryMeta) fresh(now time.Time, ttl time.Duration) bool {
	if ttl == Forever {
		return true
	}
	return now.Before(m.FetchedAt.Add(ttl))
}

// entry is a complete cache entry read from disk.
type entry struct {
	meta entryMeta
	body []byte
}

// response builds the Response for a cache hit.
func (e *entry) response() *Response {
	h := http.Header{}
	if e.meta.ETag != "" {
		h.Set("ETag", e.meta.ETag)
	}
	if e.meta.LastModified != "" {
		h.Set("Last-Modified", e.meta.LastModified)
	}
	if e.meta.ContentType != "" {
		h.Set("Content-Type", e.meta.ContentType)
	}
	return &Response{
		Body:       e.body,
		StatusCode: e.meta.Status,
		Header:     h,
		FromCache:  true,
		FetchedAt:  e.meta.FetchedAt,
	}
}

// readCacheFile reads one file this package named. dir is the cache directory and
// name is a hash-shaped entry file name (a key this package computed, or a name
// that matched entryFileName), so the path cannot point outside the directory.
func readCacheFile(dir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- see the doc comment: name is hash-shaped and cannot escape dir
}

// readEntry returns the entry for key, or nil on a miss. Anything unreadable or
// inconsistent (corrupt metadata, missing body, a hash collision) is a miss and is
// logged at debug level, never an error: the network answer will replace it.
func (c *Client) readEntry(key string, cl *call) *entry {
	metaName := key + metaSuffix
	data, err := readCacheFile(c.dir, metaName)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.log.Debug("cache metadata unreadable", "path", filepath.Join(c.dir, metaName), "error", err)
		}
		return nil
	}
	meta, err := parseMeta(data)
	if err != nil {
		c.log.Debug("ignoring corrupt cache entry", "path", filepath.Join(c.dir, metaName), "error", err)
		return nil
	}
	if !meta.matches(cl.method, cl.rawURL, cl.accept, cl.bodyHash) {
		c.log.Debug("ignoring cache entry for a different request", "path", filepath.Join(c.dir, metaName), "method", meta.Method, "url", meta.URL)
		return nil
	}
	body, err := readCacheFile(c.dir, key+bodySuffix)
	if err != nil {
		c.log.Debug("cache body unreadable", "path", filepath.Join(c.dir, key+bodySuffix), "error", err)
		return nil
	}
	if int64(len(body)) != meta.Length {
		c.log.Debug("ignoring cache entry with a mismatched body", "path", filepath.Join(c.dir, key+bodySuffix), "want", meta.Length, "got", len(body))
		return nil
	}
	return &entry{meta: meta, body: body}
}

// writeEntry stores body then metadata, each atomically, so a reader that finds
// valid metadata always finds the body it describes. The metadata records the
// body length, so a body that was truncated or overwritten by another process
// after the fact is detected on read.
func (c *Client) writeEntry(key string, meta *entryMeta, body []byte) error {
	meta.Length = int64(len(body))
	if err := writeFileAtomic(c.dir, key+bodySuffix, body); err != nil {
		return err
	}
	return c.writeMeta(key, meta)
}

func (c *Client) writeMeta(key string, meta *entryMeta) error {
	data, err := meta.marshal()
	if err != nil {
		return err
	}
	return writeFileAtomic(c.dir, key+metaSuffix, data)
}

// writeFileAtomic writes data to a temporary file in dir and renames it over
// name, so readers see either the old content or the new one, never a partial
// file. The data is synced before the rename: the rename alone protects against a
// process crash, but after a power loss the file system may have made the rename
// durable before the data, leaving an empty or truncated file under a valid name.
func writeFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("syncing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("renaming %s: %w", tmpName, err)
	}
	return nil
}

// DefaultDir returns the cache directory: $TRUSTDIFF_CACHE_DIR when set, otherwise
// the trustdiff directory under the user cache directory of the platform.
func DefaultDir() (string, error) {
	if dir := os.Getenv(EnvDir); dir != "" {
		return dir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating the user cache directory: %w", err)
	}
	return filepath.Join(base, "trustdiff"), nil
}

// Stats summarizes a cache directory.
type Stats struct {
	// Entries is the number of entries with valid metadata.
	Entries int
	// Bytes is the size of every file this package wrote, including leftovers.
	Bytes int64
	// OldestFetchedAt and NewestFetchedAt are zero when there are no entries.
	OldestFetchedAt time.Time
	NewestFetchedAt time.Time
}

// Stat summarizes dir. A directory that does not exist is an empty cache.
// Files this package did not write are ignored.
func Stat(dir string) (Stats, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return Stats{}, nil
	}
	if err != nil {
		return Stats{}, fmt.Errorf("reading cache directory %s: %w", dir, err)
	}
	var s Stats
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !entryFileName.MatchString(name) {
			continue
		}
		info, err := e.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue // removed between listing and stat
		}
		if err != nil {
			return Stats{}, fmt.Errorf("reading %s: %w", filepath.Join(dir, name), err)
		}
		s.Bytes += info.Size()
		if !strings.HasSuffix(name, metaSuffix) {
			continue
		}
		data, err := readCacheFile(dir, name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return Stats{}, fmt.Errorf("reading %s: %w", filepath.Join(dir, name), err)
		}
		meta, err := parseMeta(data)
		if err != nil {
			continue // a corrupt entry is a miss for Get and not an entry here
		}
		s.Entries++
		if s.OldestFetchedAt.IsZero() || meta.FetchedAt.Before(s.OldestFetchedAt) {
			s.OldestFetchedAt = meta.FetchedAt
		}
		if meta.FetchedAt.After(s.NewestFetchedAt) {
			s.NewestFetchedAt = meta.FetchedAt
		}
	}
	return s, nil
}

// Clear removes every file this package wrote in dir and leaves the directory in
// place. It refuses, with ErrForeignFiles, when dir holds any other file or a
// subdirectory, so a mistyped directory never loses user data. A directory that
// does not exist is already clear.
func Clear(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading cache directory %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !entryFileName.MatchString(e.Name()) {
			return fmt.Errorf("%w: %s contains %q", ErrForeignFiles, dir, e.Name())
		}
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing %s: %w", path, err)
		}
	}
	return nil
}
