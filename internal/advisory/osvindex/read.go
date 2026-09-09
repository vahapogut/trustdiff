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
// ecosystem whose metadata is unreadable, was written by another schema or no
// longer has the shard files it counts is left out, which is the same answer as
// never having downloaded it: an index that is half there must say so rather than
// answer "no advisories" for every package in it.
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
// listed explicitly, or it falls in one of the ranges. Both comparisons go
// through the ecosystem's own scheme in internal/model/version, so npm and
// crates.io versions are semantic versions and PyPI ones are PEP 440, and a
// listed version is matched by what it means and not by how it is spelled.
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
	if listed(eco, rec.Versions, ver) {
		return true
	}
	for i := range rec.Ranges {
		if inRange(eco, &rec.Ranges[i], ver) {
			return true
		}
	}
	return false
}

// listed reports whether ver is one of the versions the record names explicitly.
// The comparison goes through the ecosystem's scheme, not through byte equality:
// PEP 440 makes 1.0.0 the same version as a listed 1.0, 2.0 the same as 2.0.0 and
// 3.0-1 the same as 3.0.post1, and the OSV API reports all three as affected, so
// an offline run that compared the spellings would miss what an online run finds.
// A listed version that does not parse is compared as it is written, which is all
// that can honestly be said about it.
func listed(eco model.Ecosystem, versions []string, ver string) bool {
	for _, v := range versions {
		if v == ver {
			return true
		}
		if cmp, err := version.Compare(eco, ver, v); err == nil && cmp == 0 {
			return true
		}
	}
	return false
}

// inRange applies one range.
//
// A bound that does not parse as a version of this ecosystem cannot be ordered,
// and the two ends are then treated differently on purpose. An upper bound that
// cannot be ordered stops the range from matching: dropping it would leave a
// range that claims every version ever published for the package, including the
// ones released after the fix. A lower bound that cannot be ordered is dropped
// instead and the upper bound still applies, because the range stays finite
// either way and the alternative is what this used to do: an introduced version
// OSV spelled as 1.0.0.beta hid an advisory whose fixed version said plainly that
// everything below 2.0.0 was affected, which is a silent false negative and the
// most damaging answer this package can give.
//
// A range with nothing orderable left in it matches only an exact spelling of its
// introduced version, since that is all it can honestly claim.
func inRange(eco model.Ecosystem, r *Range, ver string) bool {
	if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
		return false
	}
	if _, err := version.Parse(eco, ver); err != nil {
		// The version being asked about cannot be ordered against anything, so
		// the only thing this range can say about it is whether it is spelled
		// like the version the range starts at.
		return ver == r.Introduced
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
	if r.Introduced != "" {
		cmp, err := version.Compare(eco, ver, r.Introduced)
		switch {
		case err == nil && cmp < 0:
			return false
		case err != nil && r.Fixed == "" && r.LastAffected == "":
			// The lower bound is all this range has and it cannot be ordered,
			// so there is nothing left to compare ver with.
			return false
		}
	}
	return true
}

// readMeta reads one ecosystem's meta.json and answers whether the ecosystem is
// indexed. A missing file, an unreadable one, one written by another schema and
// one whose shard files are no longer on disk all return a nil Meta without an
// error: the answer in each case is that the ecosystem is not indexed, and a
// refresh fixes it.
//
// The shard test is here rather than in one caller because every caller needs the
// same answer. A metadata file whose shards are gone (an interrupted "cache
// clear" removes the files in directory order, so 00.json through ff.json go
// before meta.json) would otherwise make Open succeed and every lookup answer
// "no advisories", which is the one answer a security tool must never invent,
// while "cache status" called the ecosystem indexed and a refresh revalidated
// against it and was told 304.
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
	if countShards(ecosystemDir(cacheDir, eco)) != meta.Shards {
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
