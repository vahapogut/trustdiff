// Package osvindex downloads the OSV per-ecosystem advisory archives and turns
// them into a compact plain-file index that answers "what affects this package
// name at this version" without the network. It is what makes --offline more
// than a way to read the HTTP cache: "trustdiff cache refresh" fills the index
// and an offline run reads only from it.
//
// # The source, verified 2026-09-10
//
// OSV publishes one zip per ecosystem in a public Google Cloud Storage bucket:
//
//	https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip
//
// and the list of ecosystem names at
// https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt, whose
// lines 29, 42 and 43 on that day were PyPI, crates.io and npm. Those are the
// three names this package uses, spelled exactly as OSV spells them (they are
// also the names the OSV API takes, see internal/advisory/osv), so the URL of
// the npm archive is
// https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip.
//
// Each archive is a flat zip of one JSON file per advisory, named <id>.json, in
// the OSV schema (schema_version 1.7.x on that day). Measured on 2026-09-10 with
// a HEAD request for the size and by parsing the central directory for the rest:
//
//	ecosystem   zip bytes    entries   uncompressed   note
//	npm         214,850,107  228,889   378,776,243    Zip64; 221,519 of the entries are MAL- records
//	PyPI         33,793,593   25,361    72,211,038
//	crates.io     3,429,918    2,817     6,858,989
//
// Every archive answered with an ETag and a Last-Modified header, so a refresh
// revalidates conditionally and a server answer of 304 costs one request and no
// rebuild.
//
// Two properties of the archives shape the reader. First, a per-ecosystem
// archive carries whole records, and a record may list affected packages of
// other ecosystems: the PyPI archive of that day held affected entries for Go,
// Maven, npm, NuGet and six more, so the builder keeps only the affected blocks
// whose ecosystem matches the archive. Second, ranges come in three types,
// SEMVER, ECOSYSTEM and GIT, and some records (MAL-2021-1 that day) carry a
// range with no type at all; GIT ranges hold commit hashes and are dropped,
// everything else is compared as a version of the ecosystem.
//
// # Why the index has the shape it has
//
// The question a check asks is always the same: given this ecosystem, this name
// and this version, which advisories apply. It is never "what does advisory X
// say", so an index keyed by advisory id (which is what the archive is) would
// have to be scanned end to end for every answer. The index therefore inverts
// the archive into package-name keys, and the answer is one map or binary search
// hit followed by a version comparison per stored range.
//
// The index is not one file per ecosystem, because npm's would be tens of
// megabytes of JSON and every run, however small, would parse all of it. It is
// split into shardCount shards by the first byte of the SHA-256 of the lookup
// key, so evaluating a single ref parses about 1/256th of the ecosystem, and a
// whole lockfile parses each shard at most once (the reader memoizes them). The
// advisory record is repeated in every shard that needs it rather than being
// referenced from a separate table, so that one shard file is a complete answer
// on its own: an advisory listing several packages is a rounding error against
// the space that indirection would cost in complexity.
//
// Everything that a finding must print is in the record (id, summary, aliases,
// the severity inputs, withdrawn), so the offline path never needs the original
// JSON. The two derivable fields are left out on purpose: Malicious is the MAL-
// prefix of the id and the advisory page is https://osv.dev/vulnerability/<id>,
// and at npm's record count each of them would cost several megabytes to store.
//
// The severity is stored as its two inputs, database_specific.severity and every
// CVSS_V3 vector of the record, not as a bucketed severity. The rule that turns
// those into an advisory.Severity lives in internal/advisory/osv and must not be
// forked here: keeping the inputs verbatim lets that one rule decide for the
// offline path exactly as it decides for the online one. That is also why the
// vectors are stored as a list, unfiltered: the rule skips a vector that does not
// parse and takes the next one, and it can only do that offline if the index kept
// the next one.
//
// # Layout
//
//	<cache>/advisories/osv/<ecosystem>/meta.json   what was downloaded and when
//	<cache>/advisories/osv/<ecosystem>/<xx>.json   one shard, xx being 00 to ff
//
// <ecosystem> is the trustdiff name (npm, pypi, cargo), so the directory is
// readable next to the rest of the cache. The osv level exists so that another
// advisory source can be indexed beside this one later without moving anything.
// Shards with no packages are not written, which keeps a small ecosystem to a
// handful of files.
//
// Shard bytes are a pure function of the archive contents: entries are sorted,
// deduplicated and marshaled with a fixed field order, so building the same
// archive twice writes the same bytes and a refresh that finds nothing new
// rewrites nothing. Everything that does change between two runs of the same
// archive (the download time, the ETag) lives in meta.json.
//
// This package does not go through internal/httpcache, which every other client
// does. It cannot: httpcache buffers a whole response in memory and refuses one
// over 128 MiB, and the npm archive was 204.9 MiB on 2026-09-10 and grows. The
// download here streams to a temporary file instead, and reproduces what
// httpcache would have given it: the identifying User-Agent, one request at a
// time, a deadline, conditional revalidation from the stored ETag and
// Last-Modified, and a hard size cap. See download.go.
package osvindex

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

const (
	// SourceBaseURL is the bucket that holds the per-ecosystem archives.
	// Options.BaseURL overrides it, which is how the tests point the downloader
	// at an httptest server.
	SourceBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

	// ArchiveName is the file every ecosystem prefix serves.
	ArchiveName = "all.zip"

	// Subdir is the directory under the trustdiff cache directory that holds
	// every advisory index. It is a subdirectory rather than loose files so that
	// httpcache entries and index files can never be mistaken for each other.
	Subdir = "advisories"

	// sourceDir is the level under Subdir that names the advisory source, so a
	// second source could be indexed beside OSV without moving these files.
	sourceDir = "osv"

	// metaName is the per-ecosystem metadata file.
	metaName = "meta.json"

	// Schema is the version of the on-disk format. A reader that meets another
	// number treats the ecosystem as not indexed rather than guessing, so an
	// upgrade that changes the format is a refresh away from working. It went
	// from 1 to 2 when cvss_v3 became the list of every CVSS_V3 vector of the
	// record rather than the first one, so that the severity rule in
	// internal/advisory/osv can skip a vector that does not parse offline exactly
	// as it does online.
	Schema = 2

	// shardCount is how many shards one ecosystem is split into. It is 256 so
	// that a shard is named by the first byte of the key hash in hex, which
	// makes the file name derivable from the name being looked up with no table
	// to consult. At npm's size that is roughly 200 KiB per shard.
	shardCount = 256

	// StaleAfter is when "cache status" starts calling an index stale. OSV
	// republishes the archives continuously (all three were rewritten within the
	// same six hours on 2026-09-10), and a week-old copy has missed a week of
	// malicious-package advisories, which are the ones that matter most and the
	// ones that appear fastest. An index that looks fresh but is not is worse
	// than none, so the threshold is deliberately short.
	StaleAfter = 7 * 24 * time.Hour
)

// ErrNoIndex is returned (wrapped) when an offline lookup has no index to read:
// the directory holds nothing, or nothing for the ecosystem asked about, or what
// it holds was written by another schema. Callers use errors.Is and report the
// check as skipped; the message says offline so the skipped reason a check
// prints does too.
var ErrNoIndex = errors.New("offline: no advisory index")

// ErrForeignFiles is returned (wrapped) by Clear when the index directory holds
// a file this package did not write, so a mistyped cache directory is never
// emptied.
var ErrForeignFiles = errors.New("refusing to clear an advisory index directory trustdiff did not fill")

// ErrTooLarge is returned (wrapped) when an archive, or what it decompresses to,
// exceeds the limits in Limits. Callers use errors.Is to tell a refusal from a
// transport failure.
var ErrTooLarge = errors.New("archive larger than the limit")

// Range is one affected version range of an advisory, flattened from an OSV
// range's events. Introduced is the first affected version ("0" means from the
// beginning of the package's history, which is how OSV writes it and how
// malicious-package advisories say "every version"). Fixed is the first version
// that is not affected and LastAffected the last one that is; a range carries at
// most one of them, and neither means the range has no upper bound.
type Range struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Record is one advisory as the index stores it, together with the part of the
// advisory that says which versions of one package it affects. Everything a
// finding prints is here; see the package comment for what is left out and why.
type Record struct {
	// ID is the OSV id, for example GHSA-xxxx or MAL-2026-1234.
	ID string `json:"id"`
	// Aliases are other identifiers for the same advisory (CVE ids), in the
	// order the record lists them. The order is kept rather than sorted because
	// it carries meaning (OSV lists the identifier the record came from first)
	// and because the online path shows the record's own order: an advisory must
	// not read differently offline.
	Aliases []string `json:"aliases,omitempty"`
	// Summary is the record's summary, or the first line of its details when it
	// has none, bounded to summaryMaxRunes.
	Summary string `json:"summary,omitempty"`
	// SeverityLabel is database_specific.severity verbatim (GHSA writes LOW,
	// MODERATE, HIGH or CRITICAL). It is stored unparsed: the caller's own rule
	// decides what it means.
	SeverityLabel string `json:"severity_label,omitempty"`
	// CVSSv3 holds every CVSS_V3 vector string of the record, in the order the
	// record listed them and unparsed, for the same reason. It is the whole list
	// rather than the first one because the rule that scores them skips a vector
	// that does not parse, so one malformed vector must not hide the usable one
	// behind it; keeping the list is what lets that rule decide offline exactly
	// as it decides online. A record with only a CVSS_V4 entry leaves it empty,
	// which is the same answer the online path gives today.
	CVSSv3 []string `json:"cvss_v3,omitempty"`
	// Published and Modified are the record's timestamps, zero when it had none
	// or they did not parse.
	Published time.Time `json:"published,omitzero"`
	Modified  time.Time `json:"modified,omitzero"`
	// Withdrawn is set when OSV has withdrawn the record. Lookup never returns a
	// withdrawn record, since a withdrawn advisory is not a finding; it stays in
	// the index so that the counts in "cache status" match what was downloaded
	// and so a later flag could show them.
	Withdrawn time.Time `json:"withdrawn,omitzero"`
	// Ranges and Versions are the affected version ranges and the explicitly
	// listed affected versions, merged across every affected block of the record
	// that named this package in this ecosystem. A version matches when it is in
	// Versions or falls in a Range.
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// Malicious reports whether the record is a malicious-package advisory. It is
// the MAL- prefix of the id, which is why the flag is not stored.
func (r *Record) Malicious() bool { return strings.HasPrefix(r.ID, maliciousPrefix) }

// maliciousPrefix marks advisories imported from ossf/malicious-packages. It is
// spelled out here rather than taken from internal/advisory/osv because osv is
// the package that will import this one to answer offline, and an import back
// would be a cycle.
const maliciousPrefix = "MAL-"

// Meta is what meta.json records about one ecosystem's index: where it came
// from, when, and how big the result is. "cache status" prints it and a refresh
// revalidates from ETag and LastModified.
type Meta struct {
	// Schema is the on-disk format version the shards were written with.
	Schema int `json:"schema"`
	// Ecosystem is the trustdiff ecosystem, OSVEcosystem the name OSV uses.
	Ecosystem    model.Ecosystem `json:"ecosystem"`
	OSVEcosystem string          `json:"osv_ecosystem"`
	// SourceURL is the archive that was downloaded.
	SourceURL string `json:"source_url"`
	// ETag and LastModified are the validators the server sent, replayed on the
	// next refresh so an unchanged archive costs one conditional request.
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	// DownloadedAt is when the archive was last confirmed by the server, which
	// is what the age in "cache status" measures. A refresh answered with 304
	// moves it forward: the copy on disk was confirmed current at that moment.
	DownloadedAt time.Time `json:"downloaded_at"`
	// ArchiveBytes and ArchiveSHA256 describe the archive that was read.
	ArchiveBytes  int64  `json:"archive_bytes"`
	ArchiveSHA256 string `json:"archive_sha256,omitempty"`
	// Advisories is how many distinct advisory ids the index holds for this
	// ecosystem, Withdrawn how many of those are withdrawn, Packages how many
	// distinct names are indexed and Shards how many shard files were written.
	Advisories int `json:"advisories"`
	Withdrawn  int `json:"withdrawn"`
	Packages   int `json:"packages"`
	Shards     int `json:"shards"`
	// Unusable is how many entries of the archive could not be decoded and were
	// skipped, normally zero. It is recorded so a refresh that quietly lost
	// records is visible afterwards.
	Unusable int `json:"unusable"`
	// IndexBytes is the size of the shard files this index owns.
	IndexBytes int64 `json:"index_bytes"`
}

// Age is how long ago the archive was last confirmed by the server.
func (m *Meta) Age(now time.Time) time.Duration { return now.Sub(m.DownloadedAt) }

// Stale reports whether the index is older than StaleAfter, which is what
// "cache status" says out loud.
func (m *Meta) Stale(now time.Time) bool { return m.Age(now) > StaleAfter }

// OSVEcosystem maps a trustdiff ecosystem to the name OSV publishes an archive
// under, or "" when OSV has none (Deno and JSR have no OSV ecosystem). It is the
// support test callers apply per ecosystem before they treat an absent answer as
// "no advisories". The names were read from the ecosystems.txt listing on
// 2026-09-10; see the package comment.
//
// It repeats what osv.Ecosystem does rather than calling it, because
// internal/advisory/osv is the package that will import this one to answer
// offline and the call back would be an import cycle.
func OSVEcosystem(eco model.Ecosystem) string {
	switch eco {
	case model.NPM:
		return "npm"
	case model.PyPI:
		return "PyPI"
	case model.Cargo:
		return "crates.io"
	default:
		return ""
	}
}

// Indexable lists the ecosystems OSV publishes an archive for, in a stable
// order. It is the default set "cache refresh" downloads when the policy names
// none.
func Indexable() []model.Ecosystem {
	return []model.Ecosystem{model.NPM, model.PyPI, model.Cargo}
}

// ArchiveURL is the archive of one ecosystem under base, or "" when OSV does not
// publish one for it.
func ArchiveURL(base string, eco model.Ecosystem) string {
	name := OSVEcosystem(eco)
	if name == "" {
		return ""
	}
	// The ecosystem name is one of three constants above, never user input, so
	// it is joined as a path segment without escaping; crates.io's dot and the
	// mixed case of PyPI are both legal in a path segment.
	return strings.TrimRight(base, "/") + "/" + name + "/" + ArchiveName
}

// Dir is the index directory under a cache directory.
func Dir(cacheDir string) string { return filepath.Join(cacheDir, Subdir, sourceDir) }

// ecosystemDir is where one ecosystem's meta and shards live.
func ecosystemDir(cacheDir string, eco model.Ecosystem) string {
	return filepath.Join(Dir(cacheDir), string(eco))
}

// shardName is the file name of shard i, two lower case hex digits.
func shardName(i int) string { return fmt.Sprintf("%02x", i) }

// shardOf returns the shard a lookup key belongs to. The first byte of the
// SHA-256 of the key spreads names evenly whatever their prefixes look like
// (npm's @scope/ names and PyPI's would otherwise pile into a few shards), and
// it is cheap: one hash of a short string per lookup.
func shardOf(key string) int {
	sum := sha256.Sum256([]byte(key))
	return int(sum[0])
}

// lookupKey normalizes a package name to the key the index is written and read
// under. The rules follow how each registry treats names, and match what the
// online path gets from the OSV API:
//
//   - npm is case sensitive. JSONStream and jsonstream are two packages, so the
//     name is the key unchanged.
//   - PyPI is case insensitive and normalizes runs of -, _ and . to a single -
//     (PEP 503), so Pillow, pillow and zope.interface all find their advisories.
//   - crates.io names are unique case insensitively, so the key is lower cased.
//     Hyphens and underscores are left alone: a lockfile spells the canonical
//     name, and folding them would be a guess this package cannot check.
func lookupKey(eco model.Ecosystem, name string) string {
	name = strings.TrimSpace(name)
	switch eco {
	case model.PyPI:
		return normalizePyPI(name)
	case model.Cargo:
		return strings.ToLower(name)
	case model.NPM, model.Deno, model.JSR:
		return name
	default:
		return name
	}
}

// normalizePyPI applies PEP 503: lower case, and every run of -, _ or . becomes
// a single -. A run at either end becomes a hyphen too, which is what the PEP's
// re.sub(r"[-_.]+", "-", name) does and what the reference implementation
// produces: _foo_ normalizes to -foo-, not to foo. PyPI would not accept such a
// name, so nothing in the archives depends on it, but the write side and the read
// side share this function and a rule that is not the published one is a
// divergence waiting for the day a name like that appears.
func normalizePyPI(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	sep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			sep = true
			continue
		}
		if sep {
			b.WriteByte('-')
			sep = false
		}
		b.WriteRune(r)
	}
	if sep {
		b.WriteByte('-')
	}
	return b.String()
}
