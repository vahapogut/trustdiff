package osvindex

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// indexFixture builds and writes the index of every fixture ecosystem into a new
// cache directory, without a network round trip, and returns a Reader over it.
func indexFixture(t *testing.T) (string, *Reader) {
	t.Helper()
	dir := t.TempDir()
	for _, eco := range Indexable() {
		built, err := BuildFromZip(zipFixture(t, eco), eco, Limits{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := WriteShards(dir, built); err != nil {
			t.Fatal(err)
		}
		meta := Meta{
			Schema: Schema, Ecosystem: eco, OSVEcosystem: OSVEcosystem(eco),
			SourceURL: ArchiveURL(SourceBaseURL, eco), DownloadedAt: time.Now().UTC(),
			Advisories: built.Advisories, Withdrawn: built.Withdrawn,
			Packages: built.Packages, Shards: len(built.Shards), IndexBytes: built.Bytes,
		}
		if err := writeMeta(dir, &meta); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, r
}

// TestLookupByNameAndVersion is the table the whole index exists for: which
// advisories a name at a version gets. Every case is one of the shapes the
// fixtures were written for.
func TestLookupByNameAndVersion(t *testing.T) {
	_, r := indexFixture(t)

	cases := []struct {
		name    string
		eco     model.Ecosystem
		pkg     string
		version string
		want    []string
	}{
		// A range is [introduced, fixed): the version before the fix is
		// affected and the fixed version itself is not.
		{name: "inside the range", eco: model.NPM, pkg: "lodash", version: "4.17.20", want: []string{"GHSA-35jh-r3h4-6jhm"}},
		{name: "the introduced version itself", eco: model.NPM, pkg: "lodash", version: "4.0.0", want: []string{"GHSA-35jh-r3h4-6jhm"}},
		{name: "just below the range", eco: model.NPM, pkg: "lodash", version: "3.10.1", want: nil},
		{name: "the fixed version is not affected", eco: model.NPM, pkg: "lodash", version: "4.17.21", want: nil},
		{name: "above the fix", eco: model.NPM, pkg: "lodash", version: "4.18.0", want: nil},

		// last_affected is inclusive, unlike fixed.
		{name: "the last affected version", eco: model.Cargo, pkg: "rustc-serialize", version: "0.3.24", want: []string{"GHSA-2226-4v3c-cff8"}},
		{name: "one past the last affected version", eco: model.Cargo, pkg: "rustc-serialize", version: "0.3.25", want: nil},
		{name: "PyPI last_affected boundary", eco: model.PyPI, pkg: "Django", version: "3.2.18", want: []string{"GHSA-6d5v-tt3m-jt7v"}},
		{name: "PyPI one past it", eco: model.PyPI, pkg: "django", version: "3.2.19", want: nil},
		{name: "PyPI below the introduced version", eco: model.PyPI, pkg: "django", version: "3.1.14", want: nil},

		// introduced "0" with no upper bound is how a malicious-package
		// advisory says every version.
		{name: "malicious, first version", eco: model.NPM, pkg: "flatmap-stream", version: "0.0.1", want: []string{"MAL-2025-20690"}},
		{name: "malicious, much later version", eco: model.NPM, pkg: "flatmap-stream", version: "9.9.9", want: []string{"MAL-2025-20690"}},

		// Explicitly listed versions, with no range at all.
		{name: "listed version", eco: model.PyPI, pkg: "zope.interface", version: "5.4.0", want: []string{"PYSEC-2026-1"}},
		{name: "a version that is not listed", eco: model.PyPI, pkg: "zope.interface", version: "5.5.1", want: nil},
		{name: "the same name spelled another way", eco: model.PyPI, pkg: "Zope_Interface", version: "5.5.0", want: []string{"PYSEC-2026-1"}},

		// Names are normalized per ecosystem.
		{name: "cargo name in another case", eco: model.Cargo, pkg: "serde", version: "1.0.50", want: []string{"RUSTSEC-2026-0001"}},
		{name: "cargo fixed version", eco: model.Cargo, pkg: "serde", version: "1.0.100", want: nil},
		{name: "npm is case sensitive", eco: model.NPM, pkg: "Lodash", version: "4.17.20", want: nil},

		// A withdrawn advisory is never an answer.
		{name: "withdrawn npm", eco: model.NPM, pkg: "left-pad", version: "1.0.0", want: nil},
		{name: "withdrawn pypi", eco: model.PyPI, pkg: "requests", version: "2.31.0", want: nil},
		{name: "withdrawn cargo", eco: model.Cargo, pkg: "openssl", version: "0.10.60", want: nil},

		// A name nothing affects.
		{name: "unaffected name", eco: model.NPM, pkg: "express", version: "4.19.2", want: nil},
		{name: "unaffected name, no version", eco: model.Cargo, pkg: "tokio", version: "", want: nil},

		// No version asks for every advisory of the package.
		{name: "no version", eco: model.NPM, pkg: "lodash", version: "", want: []string{"GHSA-35jh-r3h4-6jhm"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.Lookup(tt.eco, tt.pkg, tt.version)
			if err != nil {
				t.Fatalf("Lookup(%s, %s, %s): %v", tt.eco, tt.pkg, tt.version, err)
			}
			ids := make([]string, len(got))
			for i := range got {
				ids[i] = got[i].ID
			}
			if strings.Join(ids, ",") != strings.Join(tt.want, ",") {
				t.Errorf("Lookup(%s, %s, %s) = %v, want %v", tt.eco, tt.pkg, tt.version, ids, tt.want)
			}
		})
	}
}

// TestLookupRecordContents checks that everything a finding prints survived the
// round trip through the index, including an advisory with no severity at all.
func TestLookupRecordContents(t *testing.T) {
	_, r := indexFixture(t)

	got, err := r.Lookup(model.NPM, "lodash", "4.17.20")
	if err != nil || len(got) != 1 {
		t.Fatalf("Lookup = %v, %v", got, err)
	}
	rec := got[0]
	if rec.Summary != "Command Injection in lodash" {
		t.Errorf("Summary = %q", rec.Summary)
	}
	if len(rec.Aliases) != 1 || rec.Aliases[0] != "CVE-2021-23337" {
		t.Errorf("Aliases = %v", rec.Aliases)
	}
	if rec.SeverityLabel != "HIGH" {
		t.Errorf("SeverityLabel = %q, want HIGH", rec.SeverityLabel)
	}
	if len(rec.CVSSv3) != 1 || rec.CVSSv3[0] != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSSv3 = %q", rec.CVSSv3)
	}
	if rec.Published.IsZero() || rec.Modified.IsZero() {
		t.Errorf("timestamps = %v, %v", rec.Published, rec.Modified)
	}
	if rec.Malicious() {
		t.Error("Malicious() = true for a GHSA record")
	}

	// A malicious-package advisory: the flag is the id prefix, and OSV published
	// no severity for it at all, which is what "unknown" has to be built from.
	got, err = r.Lookup(model.NPM, "flatmap-stream", "1.0.0")
	if err != nil || len(got) != 1 {
		t.Fatalf("Lookup = %v, %v", got, err)
	}
	mal := got[0]
	if !mal.Malicious() {
		t.Error("Malicious() = false for a MAL- record")
	}
	if mal.SeverityLabel != "" || len(mal.CVSSv3) != 0 {
		t.Errorf("severity inputs = %q, %q; want both empty", mal.SeverityLabel, mal.CVSSv3)
	}

	// A record with no summary takes the first line of its details, exactly as
	// the online client does.
	got, err = r.Lookup(model.PyPI, "zope-interface", "5.4.0")
	if err != nil || len(got) != 1 {
		t.Fatalf("Lookup = %v, %v", got, err)
	}
	if !strings.HasPrefix(got[0].Summary, "zope.interface 5.4.0 and 5.5.0") {
		t.Errorf("Summary = %q", got[0].Summary)
	}
	if got[0].SeverityLabel != "" || len(got[0].CVSSv3) != 0 {
		t.Errorf("severity inputs = %q, %q; want both empty", got[0].SeverityLabel, got[0].CVSSv3)
	}

	// A CVSS vector with no database label: the vector is kept so the caller's
	// own rule can score it.
	got, err = r.Lookup(model.Cargo, "rustc-serialize", "0.3.24")
	if err != nil || len(got) != 1 {
		t.Fatalf("Lookup = %v, %v", got, err)
	}
	if got[0].SeverityLabel != "" || len(got[0].CVSSv3) != 1 || !strings.HasPrefix(got[0].CVSSv3[0], "CVSS:3.1/") {
		t.Errorf("severity inputs = %q, %q", got[0].SeverityLabel, got[0].CVSSv3)
	}
}

// TestGitRangesAreIgnored checks that a GIT range never matches: its events are
// commit hashes, and a commit hash compared with a version is meaningless.
func TestGitRangesAreIgnored(t *testing.T) {
	built, err := BuildFromZip(zipFixture(t, model.Cargo), model.Cargo, Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := findRecord(t, built, "rustc-serialize", "GHSA-2226-4v3c-cff8")
	if len(rec.Ranges) != 1 {
		t.Fatalf("ranges = %+v, want only the SEMVER one", rec.Ranges)
	}
	if rec.Ranges[0].LastAffected != "0.3.24" {
		t.Errorf("range = %+v", rec.Ranges[0])
	}
}

// findRecord digs one advisory out of a built index, so a test can assert on
// what was stored rather than on what a lookup returned.
func findRecord(t *testing.T, built *Built, key, id string) Record {
	t.Helper()
	name := shardName(shardOf(key))
	data, ok := built.Shards[name]
	if !ok {
		t.Fatalf("no shard %s for %s", name, key)
	}
	var file shardFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	for _, pkg := range file.Packages {
		if pkg.Name != key {
			continue
		}
		for j := range pkg.Advisories {
			if pkg.Advisories[j].ID == id {
				return pkg.Advisories[j]
			}
		}
	}
	t.Fatalf("no advisory %s for %s", id, key)
	return Record{}
}

func TestOpenWithoutAnIndex(t *testing.T) {
	_, err := Open(t.TempDir())
	if !errors.Is(err, ErrNoIndex) {
		t.Fatalf("err = %v, want ErrNoIndex", err)
	}
	if !strings.Contains(err.Error(), "offline") || !strings.Contains(err.Error(), "cache refresh") {
		t.Errorf("error %q should say offline and how to fix it", err)
	}
}

// TestLookupOfAnUnindexedEcosystem is the difference that matters offline: an
// ecosystem that was never downloaded must not answer "nothing affects it".
func TestLookupOfAnUnindexedEcosystem(t *testing.T) {
	dir := t.TempDir()
	built, err := BuildFromZip(zipFixture(t, model.NPM), model.NPM, Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteShards(dir, built); err != nil {
		t.Fatal(err)
	}
	if err := writeMeta(dir, &Meta{Schema: Schema, Ecosystem: model.NPM, Shards: len(built.Shards)}); err != nil {
		t.Fatal(err)
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Ecosystems(); len(got) != 1 || got[0] != model.NPM {
		t.Fatalf("Ecosystems() = %v", got)
	}
	if _, err := r.Lookup(model.PyPI, "django", "3.2.18"); !errors.Is(err, ErrNoIndex) {
		t.Fatalf("err = %v, want ErrNoIndex", err)
	}
}

// TestOpenWithoutTheShards is the false negative an offline security tool can
// least afford. "cache clear" removes an ecosystem's files in the order ReadDir
// gives, so 00.json through ff.json go before meta.json and an interrupted clear
// leaves the metadata behind with no shards. Every lookup then lands in an absent
// shard, which reads as an empty bucket, and the run reports the package as clean.
func TestOpenWithoutTheShards(t *testing.T) {
	dir, _ := indexFixture(t)
	removeShards(t, ecosystemDir(dir, model.NPM))

	r, err := Open(dir)
	if err != nil {
		t.Fatalf("Open with two ecosystems left: %v", err)
	}
	if slices.Contains(r.Ecosystems(), model.NPM) {
		t.Errorf("Ecosystems() = %v, want npm left out", r.Ecosystems())
	}
	if _, err := r.Lookup(model.NPM, "lodash", "4.17.20"); !errors.Is(err, ErrNoIndex) {
		t.Fatalf("Lookup of a shardless ecosystem: err = %v, want ErrNoIndex", err)
	}
	// "cache status" reads the same metadata and must not call it indexed either.
	stats, err := Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range stats.Ecosystems {
		if stats.Ecosystems[i].Ecosystem == model.NPM {
			t.Errorf("Stat still reports npm as indexed: %+v", stats.Ecosystems[i])
		}
	}

	// With every ecosystem in that state there is nothing to read at all.
	for _, eco := range Indexable() {
		removeShards(t, ecosystemDir(dir, eco))
	}
	if _, err := Open(dir); !errors.Is(err, ErrNoIndex) {
		t.Fatalf("Open with no shards anywhere: err = %v, want ErrNoIndex", err)
	}
}

// removeShards deletes an ecosystem's shard files and leaves its meta.json, which
// is what an interrupted "cache clear" leaves behind.
func removeShards(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == metaName {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

// TestListedVersionsUseTheEcosystemScheme covers the versions list, which OSV
// records use instead of a range. PEP 440 makes each of these three spellings the
// same version as one the record lists, and the OSV API reports all three as
// affected, so an offline run that compared the bytes would answer clean where an
// online run answers vulnerable.
func TestListedVersionsUseTheEcosystemScheme(t *testing.T) {
	record := `{"id":"PYSEC-2026-2","summary":"listed versions only",
		"affected":[{"package":{"name":"pkg","ecosystem":"PyPI"},
		"versions":["1.0","2.0.0","3.0.post1","not-a-version"]}]}`
	r := readerOfRecords(t, model.PyPI, record)

	affected := []string{"1.0", "1.0.0", "1.0.0.0", "2.0", "2.0.0", "3.0-1", "3.0.post1", "not-a-version"}
	for _, ver := range affected {
		got, err := r.Lookup(model.PyPI, "pkg", ver)
		if err != nil {
			t.Fatalf("Lookup(pypi, pkg, %s): %v", ver, err)
		}
		if len(got) != 1 {
			t.Errorf("Lookup(pypi, pkg, %s) = %v, want PYSEC-2026-2", ver, got)
		}
	}
	for _, ver := range []string{"1.1", "2.0.1", "3.0", "3.0.post2", "another-odd-one"} {
		got, err := r.Lookup(model.PyPI, "pkg", ver)
		if err != nil {
			t.Fatalf("Lookup(pypi, pkg, %s): %v", ver, err)
		}
		if got != nil {
			t.Errorf("Lookup(pypi, pkg, %s) = %v, want nothing", ver, got)
		}
	}
}

// TestEventWithTwoKeysStaysBounded covers a malformed range that fails toward a
// false positive: the OSV schema allows one key per event object, and reading only
// the first key of {"introduced":"1.0.0","fixed":"2.0.0"} leaves a range with no
// upper bound, which reports every version the package will ever publish.
func TestEventWithTwoKeysStaysBounded(t *testing.T) {
	record := `{"id":"GHSA-two-keys","summary":"one event, two keys",
		"affected":[{"package":{"name":"p","ecosystem":"npm"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0","fixed":"2.0.0"}]}]}]}`
	r := readerOfRecords(t, model.NPM, record)

	cases := map[string]bool{"0.9.0": false, "1.0.0": true, "1.5.0": true, "2.0.0": false, "99.0.0": false}
	for ver, want := range cases {
		got, err := r.Lookup(model.NPM, "p", ver)
		if err != nil {
			t.Fatalf("Lookup(npm, p, %s): %v", ver, err)
		}
		if (len(got) == 1) != want {
			t.Errorf("Lookup(npm, p, %s) = %v, want affected = %v", ver, got, want)
		}
	}
}

// TestUnparsableIntroducedKeepsTheFix is the other half of the same trade. An
// introduced version that is not a semantic version cannot be ordered, but the
// fixed version of the same range still says plainly that everything below it is
// affected, and dropping the whole range over the bound that could not be read
// hid the advisory from every version it covers.
func TestUnparsableIntroducedKeepsTheFix(t *testing.T) {
	record := `{"id":"GHSA-odd-bound","summary":"an introduced version that is not a semantic version",
		"affected":[{"package":{"name":"p","ecosystem":"npm"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0.beta"},{"fixed":"2.0.0"}]}]}]}`
	r := readerOfRecords(t, model.NPM, record)

	cases := map[string]bool{"0.9.0": true, "1.5.0": true, "1.0.0.beta": true, "2.0.0": false, "3.0.0": false}
	for ver, want := range cases {
		got, err := r.Lookup(model.NPM, "p", ver)
		if err != nil {
			t.Fatalf("Lookup(npm, p, %s): %v", ver, err)
		}
		if (len(got) == 1) != want {
			t.Errorf("Lookup(npm, p, %s) = %v, want affected = %v", ver, got, want)
		}
	}
}

// TestOpenIgnoresAnotherSchema checks the upgrade path: an index written by a
// format this build does not know reads as not downloaded, not as empty.
func TestOpenIgnoresAnotherSchema(t *testing.T) {
	dir := t.TempDir()
	built, err := BuildFromZip(zipFixture(t, model.NPM), model.NPM, Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteShards(dir, built); err != nil {
		t.Fatal(err)
	}
	if err := writeMeta(dir, &Meta{Schema: Schema + 1, Ecosystem: model.NPM, Shards: len(built.Shards)}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrNoIndex) {
		t.Fatalf("err = %v, want ErrNoIndex", err)
	}
}

func TestStatAndStale(t *testing.T) {
	dir, r := indexFixture(t)
	stats, err := Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Ecosystems) != 3 || stats.Bytes == 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.Dir != Dir(dir) {
		t.Errorf("Dir = %q, want %q", stats.Dir, Dir(dir))
	}
	now := time.Now()
	if len(r.Stale(now)) != 0 {
		t.Errorf("a fresh index reads as stale: %v", r.Stale(now))
	}
	if got := r.Stale(now.Add(StaleAfter + time.Hour)); len(got) != 3 {
		t.Errorf("Stale() = %v, want all three", got)
	}
	meta := r.Meta(model.NPM)
	if meta == nil || meta.Advisories != 3 {
		t.Fatalf("Meta(npm) = %+v", meta)
	}
	if meta.Stale(now) {
		t.Error("a fresh ecosystem reads as stale")
	}
	if !meta.Stale(now.Add(StaleAfter + time.Second)) {
		t.Error("an old ecosystem does not read as stale")
	}
}

func TestStatOfAnEmptyCacheDirectory(t *testing.T) {
	stats, err := Stat(filepath.Join(t.TempDir(), "never-created"))
	if err != nil {
		t.Fatalf("Stat of a missing directory: %v", err)
	}
	if len(stats.Ecosystems) != 0 || stats.Bytes != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestClear(t *testing.T) {
	dir, _ := indexFixture(t)
	if err := Clear(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, Subdir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the index directory survived: %v", err)
	}
	// Clearing twice is not an error, which is what "cache clear" needs.
	if err := Clear(dir); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
}

// TestClearKeepsForeignFilesAndClearsTheRest is what a person asking for the
// cache to be cleared gets when one stray file is under the index: the index
// goes, the stray file stays, and the answer names it. Refusing the whole
// operation over one file used to leave every ecosystem on disk with no way
// forward except deleting the directory by hand.
func TestClearKeepsForeignFilesAndClearsTheRest(t *testing.T) {
	dir, _ := indexFixture(t)
	npm := ecosystemDir(dir, model.NPM)
	keep := filepath.Join(npm, "thesis.docx")
	if err := os.WriteFile(keep, []byte("irreplaceable"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Clear(dir)
	if !errors.Is(err, ErrForeignFiles) {
		t.Fatalf("err = %v, want ErrForeignFiles", err)
	}
	if !strings.Contains(err.Error(), "thesis.docx") {
		t.Errorf("error %q does not name the file", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the foreign file was removed: %v", err)
	}
	// Everything this package wrote is gone, in the ecosystem that held the
	// stray file and in the ones that did not.
	if _, err := os.Stat(filepath.Join(npm, metaName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the index files beside the foreign file survived: %v", err)
	}
	for _, eco := range []model.Ecosystem{model.PyPI, model.Cargo} {
		if _, err := os.Stat(ecosystemDir(dir, eco)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived a refusal about another ecosystem: %v", eco, err)
		}
	}
	// A second clear has nothing of its own left to remove and says the same
	// thing about the same file.
	if err := Clear(dir); !errors.Is(err, ErrForeignFiles) {
		t.Fatalf("second Clear: err = %v, want ErrForeignFiles", err)
	}
	// And once the file is out of the way, the directories go too.
	if err := os.Remove(keep); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir); err != nil {
		t.Fatalf("Clear after the foreign file was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, Subdir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the index directory survived: %v", err)
	}
}

// TestClearKeepsAForeignDirectory checks the other shape: a directory under the
// index that is not an ecosystem is not ours to look inside, so it is kept whole.
func TestClearKeepsAForeignDirectory(t *testing.T) {
	dir, _ := indexFixture(t)
	foreign := filepath.Join(Dir(dir), "not-an-ecosystem")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(foreign, "notes.txt")
	if err := os.WriteFile(inside, []byte("irreplaceable"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Clear(dir)
	if !errors.Is(err, ErrForeignFiles) || !strings.Contains(err.Error(), "not-an-ecosystem") {
		t.Fatalf("err = %v, want ErrForeignFiles naming the directory", err)
	}
	if _, err := os.Stat(inside); err != nil {
		t.Fatalf("the foreign directory was emptied: %v", err)
	}
	if _, err := os.Stat(ecosystemDir(dir, model.NPM)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("npm survived a refusal about another directory: %v", err)
	}
}

func TestAffectsWithUnparsableBounds(t *testing.T) {
	rec := &Record{Ranges: []Range{{Introduced: "not-a-version"}}}
	if !Affects(model.NPM, rec, "not-a-version") {
		t.Error("an exact match with an unorderable bound should still count")
	}
	if Affects(model.NPM, rec, "1.0.0") {
		t.Error("a bound that cannot be ordered must not match another version")
	}
	empty := &Record{Ranges: []Range{{}}}
	if Affects(model.NPM, empty, "1.0.0") {
		t.Error("a range with no bounds at all must not match")
	}
}
