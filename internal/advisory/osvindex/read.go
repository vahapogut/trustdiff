package osvindex

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
)

// Reader answers lookups from an index on disk. It is what an offline run reads
// instead of the network, and it reads nothing else: a ref of an ecosystem the
// index does not hold gets ErrNoIndex, never an empty answer that would look
// like "no advisories".
//
// A shard is parsed the first time a lookup lands in it and kept afterwards, so
// evaluating one ref costs one shard and evaluating a whole lockfile costs each
// shard at most once. A Reader is safe for concurrent use, which the runner
// needs: checks run in parallel across subjects.
type Reader struct {
	dir   string
	metas map[model.Ecosystem]*Meta

	mu     sync.Mutex
	shards map[string]map[string]*packageEntry
}

// Open reads the metadata of every indexed ecosystem under a cache directory.
// It returns ErrNoIndex when nothing is indexed, so a caller can report the
// checks as skipped with that reason rather than run them against nothing. An
// ecosystem whose metadata is unreadable or was written by another schema is
// left out, which is the same answer as never having downloaded it.
func Open(cacheDir string) (*Reader, error) {
	r := &Reader{
		dir:    cacheDir,
		metas:  map[model.Ecosystem]*Meta{},
		shards: map[string]map[string]*packageEntry{},
	}
	for _, eco := range Indexable() {
		meta, err := readMeta(cacheDir, eco)
		if err != nil || meta == nil {
			continue
		}
		r.metas[eco] = meta
	}
	if len(r.metas) == 0 {
		return nil, fmt.Errorf("%w under %s, run \"trustdiff cache refresh\"", ErrNoIndex, Dir(cacheDir))
	}
	return r, nil
}

// Ecosystems lists the indexed ecosystems in the order Indexable gives.
func (r *Reader) Ecosystems() []model.Ecosystem {
	out := make([]model.Ecosystem, 0, len(r.metas))
	for _, eco := range Indexable() {
		if _, ok := r.metas[eco]; ok {
			out = append(out, eco)
		}
	}
	return out
}

// Meta returns the metadata of one indexed ecosystem, or nil when it is not
// indexed.
func (r *Reader) Meta(eco model.Ecosystem) *Meta { return r.metas[eco] }

// Stale reports the indexed ecosystems whose download is older than StaleAfter.
func (r *Reader) Stale(now time.Time) []model.Ecosystem {
	var out []model.Ecosystem
	for _, eco := range r.Ecosystems() {
		if r.metas[eco].Stale(now) {
			out = append(out, eco)
		}
	}
	return out
}

// Lookup returns the advisories that affect name at version, sorted by advisory
// id. An empty version asks for every advisory of the package, which is what a
// ref without a version means everywhere else.
//
// Withdrawn advisories are never returned: OSV withdrew them, so they are not a
// finding. An ecosystem that is not indexed is ErrNoIndex rather than an empty
// slice, so a caller cannot mistake "not downloaded" for "nothing affects it".
func (r *Reader) Lookup(eco model.Ecosystem, name, ver string) ([]Record, error) {
	if _, ok := r.metas[eco]; !ok {
		return nil, fmt.Errorf("%w for %s under %s, run \"trustdiff cache refresh\"", ErrNoIndex, eco, Dir(r.dir))
	}
	key := lookupKey(eco, name)
	if key == "" {
		return nil, nil
	}
	entry, err := r.packageEntry(eco, key)
	if err != nil || entry == nil {
		return nil, err
	}
	out := make([]Record, 0, len(entry.Advisories))
	for i := range entry.Advisories {
		rec := &entry.Advisories[i]
		if !rec.Withdrawn.IsZero() {
			continue
		}
		if ver != "" && !Affects(eco, rec, ver) {
			continue
		}
		clone := *rec
		clone.Aliases = slices.Clone(rec.Aliases)
		clone.Ranges = slices.Clone(rec.Ranges)
		clone.Versions = slices.Clone(rec.Versions)
		out = append(out, clone)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// packageEntry returns the entry for a lookup key, parsing its shard the first
// time and remembering it afterwards. A shard file that is absent means no
// package of that shard is affected, which is not an error.
func (r *Reader) packageEntry(eco model.Ecosystem, key string) (*packageEntry, error) {
	name := shardName(shardOf(key))
	r.mu.Lock()
	defer r.mu.Unlock()
	cacheKey := string(eco) + "/" + name
	entries, loaded := r.shards[cacheKey]
	if !loaded {
		var err error
		entries, err = r.readShard(eco, name)
		if err != nil {
			return nil, err
		}
		r.shards[cacheKey] = entries
	}
	return entries[key], nil
}

// readShard parses one shard file into a map by lookup key. The file stores the
// packages as a sorted array, which is what makes the bytes deterministic; the
// map is built once here because a run that touches a shard usually touches it
// for several packages.
func (r *Reader) readShard(eco model.Ecosystem, name string) (map[string]*packageEntry, error) {
	path := filepath.Join(ecosystemDir(r.dir, eco), name+".json")
	// #nosec G304 -- the path is <cache>/advisories/osv/<ecosystem>/<shard>.json,
	// built from constants, a known ecosystem and a two hex digit shard name this
	// package computed from the hash of the lookup key.
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]*packageEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("osvindex: reading %s: %w", path, err)
	}
	var file shardFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("osvindex: reading %s: %w", path, err)
	}
	if file.Schema != Schema {
		return nil, fmt.Errorf("osvindex: reading %s: schema %d, want %d, run \"trustdiff cache refresh\"", path, file.Schema, Schema)
	}
	out := make(map[string]*packageEntry, len(file.Packages))
	for i := range file.Packages {
		out[file.Packages[i].Name] = &file.Packages[i]
	}
	return out, nil
}

// Affects reports whether ver is one of the versions the record covers: it is
// listed explicitly, or it falls in one of the ranges. Versions are compared
// with the ecosystem's own scheme through internal/model/version, so npm and
// crates.io ranges are semantic versions and PyPI ranges are PEP 440.
//
// A range is [Introduced, Fixed) or [Introduced, LastAffected], which is what
// the OSV schema means by those events, so the fixed version itself is not
// affected and the last affected one is.
//
// A record that ended up with neither a range nor a listed version for this
// package therefore matches nothing, and only a lookup with no version at all
// sees it. That is rare and deliberate: 21 of the 30,865 affected blocks in the
// PyPI archive of 2026-09-10 named a package without saying which versions it
// covers (a further 2 said so only in GIT commits), and a record that does not
// name a version cannot be reported against one without inventing the range. The
// online path answers the same way, and offline agreeing with online matters
// more here than either answer on its own.
func Affects(eco model.Ecosystem, rec *Record, ver string) bool {
	ver = strings.TrimSpace(ver)
	if ver == "" {
		return true
	}
	if slices.Contains(rec.Versions, ver) {
		return true
	}
	for i := range rec.Ranges {
		if inRange(eco, &rec.Ranges[i], ver) {
			return true
		}
	}
	return false
}

// inRange applies one range. A bound that does not parse as a version of this
// ecosystem cannot be ordered, so the range only matches on an exact spelling
// match with the introduced version: guessing either way would be worse than
// saying so, and reporting a vulnerability that does not apply is as damaging
// here as missing one.
func inRange(eco model.Ecosystem, r *Range, ver string) bool {
	if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
		return false
	}
	if r.Introduced != "" {
		cmp, err := version.Compare(eco, ver, r.Introduced)
		if err != nil {
			return ver == r.Introduced
		}
		if cmp < 0 {
			return false
		}
	}
	if r.Fixed != "" {
		cmp, err := version.Compare(eco, ver, r.Fixed)
		if err != nil || cmp >= 0 {
			return false
		}
	}
	if r.LastAffected != "" {
		cmp, err := version.Compare(eco, ver, r.LastAffected)
		if err != nil || cmp > 0 {
			return false
		}
	}
	return true
}

// readMeta reads one ecosystem's meta.json. A missing file, an unreadable one or
// one written by another schema all return a nil Meta without an error: the
// answer in each case is that the ecosystem is not indexed, and a refresh fixes
// it.
func readMeta(cacheDir string, eco model.Ecosystem) (*Meta, error) {
	path := filepath.Join(ecosystemDir(cacheDir, eco), metaName)
	// #nosec G304 -- the path is <cache>/advisories/osv/<ecosystem>/meta.json,
	// built from constants and one of the ecosystems this package indexes.
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("osvindex: reading %s: %w", path, err)
	}
	var meta Meta
	usable := json.Unmarshal(data, &meta) == nil && meta.Schema == Schema && meta.Ecosystem == eco
	if !usable {
		// A metadata file this build cannot use says the same thing as a missing
		// one: the ecosystem is not indexed, and a refresh fixes it. It is not a
		// failure to report, because there is nothing the caller could do with
		// it that a refresh would not.
		return nil, nil
	}
	return &meta, nil
}

// writeMeta stores one ecosystem's meta.json, indented because a person reads
// it to see where the index came from.
func writeMeta(cacheDir string, meta *Meta) error {
	dir := ecosystemDir(cacheDir, meta.Ecosystem)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("osvindex: creating %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("osvindex: encoding %s: %w", filepath.Join(dir, metaName), err)
	}
	return writeFileAtomic(dir, metaName, append(data, '\n'))
}

// Stats is what "cache status" prints about the index: the metadata of every
// indexed ecosystem, in the order Indexable gives, and the bytes the whole index
// occupies.
type Stats struct {
	// Dir is the index directory, whether or not it exists.
	Dir string
	// Ecosystems holds one entry per indexed ecosystem.
	Ecosystems []Meta
	// Bytes is the size of every file the index owns, meta files included.
	Bytes int64
}

// Stat summarizes the index under a cache directory. A directory that does not
// exist is an empty index, not an error, so "cache status" works before the
// first refresh.
func Stat(cacheDir string) (Stats, error) {
	s := Stats{Dir: Dir(cacheDir)}
	for _, eco := range Indexable() {
		dir := ecosystemDir(cacheDir, eco)
		bytes, err := dirBytes(dir)
		if err != nil {
			return Stats{}, err
		}
		s.Bytes += bytes
		meta, err := readMeta(cacheDir, eco)
		if err != nil {
			return Stats{}, err
		}
		if meta == nil {
			continue
		}
		s.Ecosystems = append(s.Ecosystems, *meta)
	}
	return s, nil
}
