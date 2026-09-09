package osvindex

import (
	"archive/zip"
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Limits bound what the builder is willing to read out of an archive nobody in
// this process produced. The zero value selects the defaults below.
//
// The archive is untrusted input even though it comes from a Google Cloud
// Storage bucket over TLS: a compromised bucket, a proxy in the way or a
// mistyped BaseURL can all put something else in front of the reader, and a zip
// is the classic shape for both a decompression bomb and a path traversal. Each
// field below says which of those it covers.
type Limits struct {
	// MaxArchiveBytes refuses an archive larger than this before a byte of it is
	// read, from the Content-Length, and again while streaming in case the
	// header lied or was absent. It is what keeps a hostile or broken server
	// from filling the disk, and it is checked in download.go rather than here.
	MaxArchiveBytes int64
	// MaxEntries refuses an archive with more members than this. It covers the
	// archive made of millions of tiny files, whose cost is per entry rather
	// than per byte.
	MaxEntries int
	// MaxEntryBytes bounds one member of the archive. It is the guard against a
	// decompression bomb: every member is read through an io.LimitReader, so a
	// few compressed kilobytes can never become gigabytes in memory.
	MaxEntryBytes int64
	// MaxTotalBytes bounds the sum of every member read. It covers the bomb
	// spread over many members, each of them individually under MaxEntryBytes.
	MaxTotalBytes int64
}

// Limit defaults, sized against what OSV actually publishes (see the package
// comment for the numbers measured on 2026-09-10) with room for growth, so that
// a refusal means something is wrong rather than that OSV grew.
const (
	// npm's archive was 204.9 MiB. 512 MiB is more than twice that.
	defaultMaxArchiveBytes = 512 << 20
	// npm's archive held 228,889 members.
	defaultMaxEntries = 2_000_000
	// The largest OSV records are a few hundred kilobytes of affected lists.
	defaultMaxEntryBytes = 8 << 20
	// npm's archive decompressed to 361.2 MiB.
	defaultMaxTotalBytes = 2 << 30
)

// withDefaults fills in the zero fields.
func (l Limits) withDefaults() Limits {
	if l.MaxArchiveBytes <= 0 {
		l.MaxArchiveBytes = defaultMaxArchiveBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = defaultMaxEntries
	}
	if l.MaxEntryBytes <= 0 {
		l.MaxEntryBytes = defaultMaxEntryBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = defaultMaxTotalBytes
	}
	return l
}

// summaryMaxRunes bounds a summary taken from a record's details, the same
// bound internal/advisory/osv applies to the summaries it derives.
const summaryMaxRunes = 200

// Built is one ecosystem's index in memory, before it is written. Shards maps a
// shard name ("00" to "ff") to the bytes of its file; a shard with no packages
// is absent rather than empty.
type Built struct {
	Ecosystem model.Ecosystem
	Shards    map[string][]byte
	// Advisories is the number of distinct advisory ids kept, Withdrawn how many
	// of those were withdrawn, Packages the number of distinct lookup keys.
	Advisories int
	Withdrawn  int
	Packages   int
	// Unusable counts members that were skipped because their JSON did not
	// decode. A member that could not be read at all is an error instead: that
	// is a damaged download, not one bad record.
	Unusable int
	// Bytes is the size of the shard files.
	Bytes int64
}

// shardFile is the on-disk shape of one shard. Packages are sorted by name so
// the file is deterministic and can be searched without building a map.
type shardFile struct {
	Schema     int             `json:"schema"`
	Ecosystem  model.Ecosystem `json:"ecosystem"`
	Shard      string          `json:"shard"`
	Packages   []packageEntry  `json:"packages"`
	Advisories int             `json:"advisories"`
}

// packageEntry is every advisory the index holds for one lookup key. Name is the
// normalized key, not the spelling any particular record used: the caller has
// the ref's own spelling for display.
type packageEntry struct {
	Name       string   `json:"name"`
	Advisories []Record `json:"advisories"`
}

// osvRecord is the part of an OSV record the builder reads. database_specific is
// kept raw because its shape belongs to the source database, exactly as the
// online client treats it.
type osvRecord struct {
	ID               string                     `json:"id"`
	Aliases          []string                   `json:"aliases"`
	Summary          string                     `json:"summary"`
	Details          string                     `json:"details"`
	Published        string                     `json:"published"`
	Modified         string                     `json:"modified"`
	Withdrawn        string                     `json:"withdrawn"`
	Severity         []osvSeverity              `json:"severity"`
	DatabaseSpecific map[string]json.RawMessage `json:"database_specific"`
	Affected         []osvAffected              `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

// BuildFromZip reads the OSV archive at zipPath and returns the index of one
// ecosystem. Nothing is written; the caller decides where the shards go, which
// is what lets a test compare two builds byte for byte.
//
// The archive is read once, member by member, and every member is bounded by
// limits. A member whose JSON does not decode is counted in Unusable and
// skipped, since one bad record must not cost a whole refresh; a member that
// cannot be read at all fails the build naming the archive and the member,
// because that is a damaged or truncated download and half an advisory index is
// worse than none.
func BuildFromZip(zipPath string, eco model.Ecosystem, limits Limits, log *slog.Logger) (*Built, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	limits = limits.withDefaults()
	osvEco := OSVEcosystem(eco)
	if osvEco == "" {
		return nil, fmt.Errorf("osvindex: %s has no OSV ecosystem", eco)
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("osvindex: reading %s: %w", zipPath, err)
	}
	defer func() { _ = zr.Close() }()

	if len(zr.File) > limits.MaxEntries {
		return nil, fmt.Errorf("osvindex: %s: %w: %d members, the limit is %d",
			zipPath, ErrTooLarge, len(zr.File), limits.MaxEntries)
	}

	// byKey collects, per lookup key, one record per advisory id. The inner map
	// merges the affected blocks of a record that names the same package more
	// than once, which happens when a record splits ranges across blocks.
	byKey := make(map[string]map[string]*Record)
	ids := make(map[string]bool)
	withdrawn := make(map[string]bool)
	var read, unusable int
	var total int64

	for _, f := range zr.File {
		if !usableMember(f.Name) {
			continue
		}
		data, err := readMember(f, limits.MaxEntryBytes)
		if err != nil {
			return nil, fmt.Errorf("osvindex: %s: member %s: %w", zipPath, f.Name, err)
		}
		total += int64(len(data))
		if total > limits.MaxTotalBytes {
			return nil, fmt.Errorf("osvindex: %s: %w: members decompress to more than %d bytes",
				zipPath, ErrTooLarge, limits.MaxTotalBytes)
		}
		read++

		var rec osvRecord
		if err := json.Unmarshal(data, &rec); err != nil || rec.ID == "" {
			unusable++
			log.Debug("osv archive member skipped", "archive", zipPath, "member", f.Name, "error", err)
			continue
		}
		added := collect(&rec, osvEco, eco, byKey, log)
		if added {
			ids[rec.ID] = true
			if rec.Withdrawn != "" {
				withdrawn[rec.ID] = true
			}
		}
	}
	if unusable > 0 {
		log.Warn("osv archive members could not be decoded", "archive", zipPath, "members", unusable, "read", read)
	}

	built := &Built{
		Ecosystem:  eco,
		Shards:     map[string][]byte{},
		Advisories: len(ids),
		Withdrawn:  len(withdrawn),
		Packages:   len(byKey),
		Unusable:   unusable,
	}
	if err := marshalShards(built, byKey); err != nil {
		return nil, err
	}
	log.Debug("osv index built", "archive", zipPath, "ecosystem", eco, "advisories", built.Advisories,
		"packages", built.Packages, "shards", len(built.Shards), "bytes", built.Bytes)
	return built, nil
}

// usableMember decides whether a member of the archive is one of the advisory
// files, and is also the guard against a path outside the destination. Nothing
// here is ever extracted, so a "zip slip" member cannot overwrite a file: the
// member name is used for nothing but this test and the error messages, and no
// path is ever built from it. The test is kept anyway, so that an archive that
// is not what OSV publishes is skipped rather than parsed: a name is usable only
// when it is a plain <id>.json with no directory separator of either kind, no
// drive letter, and no . or .. segment.
func usableMember(name string) bool {
	if name == "" || strings.ContainsAny(name, `\:`) || strings.Contains(name, "/") {
		return false
	}
	if name == "." || name == ".." || name != path.Clean(name) {
		return false
	}
	return strings.HasSuffix(name, ".json")
}

// readMember reads one member through an io.LimitReader, which is the guard
// against a decompression bomb: whatever the member claims to be, at most max
// bytes of it reach memory. A member that is exactly max bytes is refused too,
// because it cannot be told from a truncated one.
func readMember(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: member is larger than %d bytes", ErrTooLarge, max)
	}
	// The CRC of a member is only verified once its stream has been read to the
	// end, which io.ReadAll did, so a corrupted body has already failed above.
	return data, nil
}

// collect folds one record into byKey and reports whether it contributed
// anything. Only affected blocks of this archive's own ecosystem are kept: a
// per-ecosystem archive carries whole records, and a record may list packages of
// other ecosystems (see the package comment).
func collect(rec *osvRecord, osvEco string, eco model.Ecosystem, byKey map[string]map[string]*Record, log *slog.Logger) bool {
	added := false
	for i := range rec.Affected {
		a := &rec.Affected[i]
		if !sameEcosystem(a.Package.Ecosystem, osvEco) || a.Package.Name == "" {
			continue
		}
		key := lookupKey(eco, a.Package.Name)
		if key == "" {
			continue
		}
		perID := byKey[key]
		if perID == nil {
			perID = map[string]*Record{}
			byKey[key] = perID
		}
		r := perID[rec.ID]
		if r == nil {
			r = newRecord(rec, log)
			perID[rec.ID] = r
		}
		r.Ranges = append(r.Ranges, flattenRanges(a.Ranges)...)
		r.Versions = append(r.Versions, a.Versions...)
		added = true
	}
	return added
}

// sameEcosystem compares an affected block's ecosystem with the archive's. OSV
// allows a suffix after a colon (Alpine:v3.10, Debian:11) that names a release
// of the same ecosystem; npm, PyPI and crates.io never carry one, but the
// comparison ignores it so a suffix would not silently drop a record.
func sameEcosystem(got, want string) bool {
	if base, _, ok := strings.Cut(got, ":"); ok {
		got = base
	}
	return strings.EqualFold(got, want)
}

// newRecord maps an OSV record onto the stored shape, without the affected
// ranges, which the caller merges in.
func newRecord(rec *osvRecord, log *slog.Logger) *Record {
	out := &Record{
		ID:            rec.ID,
		Aliases:       slices.Clone(rec.Aliases),
		Summary:       summaryOf(rec),
		SeverityLabel: databaseSeverity(rec),
		CVSSv3:        cvss3Vector(rec),
		Published:     parseTime(rec.ID, "published", rec.Published, log),
		Modified:      parseTime(rec.ID, "modified", rec.Modified, log),
		Withdrawn:     parseTime(rec.ID, "withdrawn", rec.Withdrawn, log),
	}
	return out
}

// flattenRanges turns OSV range events into the stored triples. Events of one
// range are read in order: an introduced event opens a range and the fixed or
// last_affected event that follows closes it, which is how the OSV schema
// defines them. A GIT range is dropped, since its events are commit hashes and
// comparing one with a package version is meaningless; a range with an unknown
// or missing type is kept, because real records carry one (MAL-2021-1 had a
// range with no type on 2026-09-10) and its events are versions.
func flattenRanges(ranges []osvRange) []Range {
	var out []Range
	for i := range ranges {
		r := &ranges[i]
		if strings.EqualFold(r.Type, "GIT") {
			continue
		}
		var current *Range
		for _, event := range r.Events {
			switch {
			case event["introduced"] != "":
				if current != nil {
					out = append(out, *current)
				}
				current = &Range{Introduced: event["introduced"]}
			case event["fixed"] != "":
				if current == nil {
					current = &Range{Introduced: "0"}
				}
				current.Fixed = event["fixed"]
				out = append(out, *current)
				current = nil
			case event["last_affected"] != "":
				if current == nil {
					current = &Range{Introduced: "0"}
				}
				current.LastAffected = event["last_affected"]
				out = append(out, *current)
				current = nil
			}
		}
		if current != nil {
			out = append(out, *current)
		}
	}
	return out
}

// summaryOf returns the record's summary, or the first line of its details when
// it has none, bounded to summaryMaxRunes. It matches what the online client
// stores, so a finding reads the same online and offline.
func summaryOf(rec *osvRecord) string {
	if s := strings.TrimSpace(rec.Summary); s != "" {
		return s
	}
	for line := range strings.SplitSeq(rec.Details, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if runes := []rune(line); len(runes) > summaryMaxRunes {
			return string(runes[:summaryMaxRunes])
		}
		return line
	}
	return ""
}

// databaseSeverity returns database_specific.severity when it is a string.
func databaseSeverity(rec *osvRecord) string {
	raw, ok := rec.DatabaseSpecific["severity"]
	if !ok {
		return ""
	}
	var label string
	if err := json.Unmarshal(raw, &label); err != nil {
		return ""
	}
	return strings.TrimSpace(label)
}

// cvss3Vector returns the first CVSS_V3 vector of the record. It is not scored
// here; see the package comment for why the input is stored instead.
func cvss3Vector(rec *osvRecord) string {
	for _, s := range rec.Severity {
		if s.Type == "CVSS_V3" && strings.TrimSpace(s.Score) != "" {
			return strings.TrimSpace(s.Score)
		}
	}
	return ""
}

// parseTime reads an RFC 3339 timestamp (OSV writes UTC with a Z suffix and
// sometimes fractional seconds). Empty or unparsable values yield the zero time,
// so one odd timestamp cannot lose a record.
func parseTime(id, field, value string, log *slog.Logger) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		log.Debug("unparsable timestamp in the OSV archive", "id", id, "field", field, "value", value, "error", err)
		return time.Time{}
	}
	// UTC so that two builds of the same archive marshal the same bytes whatever
	// the offset the record spelled.
	return t.UTC()
}

// marshalShards sorts everything and renders one file per non-empty shard. The
// sorting is what makes a build reproducible: keys, ids, ranges and versions all
// come out in the same order for the same input, so the bytes do too.
func marshalShards(built *Built, byKey map[string]map[string]*Record) error {
	buckets := make([][]packageEntry, shardCount)
	for key, perID := range byKey {
		entry := packageEntry{Name: key, Advisories: make([]Record, 0, len(perID))}
		for _, rec := range perID {
			rec.Ranges = sortRanges(rec.Ranges)
			rec.Versions = sortStrings(rec.Versions)
			rec.Aliases = sortStrings(rec.Aliases)
			entry.Advisories = append(entry.Advisories, *rec)
		}
		slices.SortFunc(entry.Advisories, func(a, b Record) int { return strings.Compare(a.ID, b.ID) })
		i := shardOf(key)
		buckets[i] = append(buckets[i], entry)
	}
	for i, entries := range buckets {
		if len(entries) == 0 {
			continue
		}
		slices.SortFunc(entries, func(a, b packageEntry) int { return strings.Compare(a.Name, b.Name) })
		advisories := 0
		for j := range entries {
			advisories += len(entries[j].Advisories)
		}
		name := shardName(i)
		data, err := json.Marshal(shardFile{
			Schema:     Schema,
			Ecosystem:  built.Ecosystem,
			Shard:      name,
			Packages:   entries,
			Advisories: advisories,
		})
		if err != nil {
			return fmt.Errorf("osvindex: encoding shard %s of %s: %w", name, built.Ecosystem, err)
		}
		// A trailing newline so the file is a well behaved text file; it is part
		// of the deterministic bytes.
		data = append(data, '\n')
		built.Shards[name] = data
		built.Bytes += int64(len(data))
	}
	return nil
}

// sortRanges orders ranges and drops exact duplicates, which appear when a
// record splits the same range across affected blocks.
func sortRanges(in []Range) []Range {
	if len(in) == 0 {
		return nil
	}
	slices.SortFunc(in, func(a, b Range) int {
		return cmp.Or(
			strings.Compare(a.Introduced, b.Introduced),
			strings.Compare(a.Fixed, b.Fixed),
			strings.Compare(a.LastAffected, b.LastAffected),
		)
	})
	return slices.Compact(in)
}

// sortStrings orders and deduplicates a list, dropping empties.
func sortStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// WriteShards writes an index into the ecosystem's directory, creating it when
// needed. Every file is written to a temporary name and renamed into place, so a
// reader never sees a partial shard, and a shard whose bytes are already on disk
// is left alone: that is what keeps a refresh of an unchanged archive from
// churning the cache. Shard files that the new index has no packages for are
// removed, so a shrinking ecosystem does not leave stale answers behind.
//
// It returns how many shard files it wrote and how many it removed.
func WriteShards(cacheDir string, built *Built) (written, removed int, err error) {
	dir := ecosystemDir(cacheDir, built.Ecosystem)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, 0, fmt.Errorf("osvindex: creating %s: %w", dir, err)
	}
	for i := range shardCount {
		name := shardName(i)
		path := filepath.Join(dir, name+".json")
		data, keep := built.Shards[name]
		if !keep {
			gone, err := removeIfPresent(path)
			if err != nil {
				return written, removed, err
			}
			if gone {
				removed++
			}
			continue
		}
		if sameBytes(path, data) {
			continue
		}
		if err := writeFileAtomic(dir, name+".json", data); err != nil {
			return written, removed, err
		}
		written++
	}
	return written, removed, nil
}

// sameBytes reports whether path already holds exactly data. Anything that
// cannot be read, a missing file included, is not the same and is overwritten:
// the answer is only ever used to skip a write that would change nothing, so a
// read failure costs a rewrite and nothing more.
func sameBytes(path string, data []byte) bool {
	// #nosec G304 -- the path is <cache>/advisories/osv/<ecosystem>/<shard>.json,
	// built from constants and a two hex digit shard name this package computed.
	existing, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Equal(existing, data)
}
