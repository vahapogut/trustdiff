package osvindex

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// zipFixture zips every JSON file of testdata/<eco> into a temporary all.zip and
// returns its path. The archive is built here rather than checked in so that the
// records stay reviewable as JSON and so the corrupt and truncated variants below
// can be derived from the same bytes.
func zipFixture(t *testing.T, eco model.Ecosystem) string {
	t.Helper()
	return zipFixtureIn(t, t.TempDir(), eco)
}

func zipFixtureIn(t *testing.T, dir string, eco model.Ecosystem) string {
	t.Helper()
	path := filepath.Join(dir, string(eco)+"-all.zip")
	if err := os.WriteFile(path, zipFixtureBytes(t, eco), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// zipFixtureBytes renders the archive of one ecosystem in memory.
func zipFixtureBytes(t *testing.T, eco model.Ecosystem) []byte {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("testdata", string(eco)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("testdata", string(eco), e.Name())) // #nosec G304 -- a fixture of this repository.
		if err != nil {
			t.Fatal(err)
		}
		w, err := zw.Create(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// writeZip stores raw bytes as a file the builder can be pointed at.
func writeZip(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOSVEcosystemAndArchiveURL(t *testing.T) {
	cases := []struct {
		eco  model.Ecosystem
		name string
		url  string
	}{
		{eco: model.NPM, name: "npm", url: SourceBaseURL + "/npm/all.zip"},
		{eco: model.PyPI, name: "PyPI", url: SourceBaseURL + "/PyPI/all.zip"},
		{eco: model.Cargo, name: "crates.io", url: SourceBaseURL + "/crates.io/all.zip"},
		{eco: model.Deno, name: "", url: ""},
		{eco: model.JSR, name: "", url: ""},
	}
	for _, tt := range cases {
		if got := OSVEcosystem(tt.eco); got != tt.name {
			t.Errorf("OSVEcosystem(%s) = %q, want %q", tt.eco, got, tt.name)
		}
		if got := ArchiveURL(SourceBaseURL+"/", tt.eco); got != tt.url {
			t.Errorf("ArchiveURL(%s) = %q, want %q", tt.eco, got, tt.url)
		}
	}
}

func TestLookupKey(t *testing.T) {
	cases := []struct {
		eco  model.Ecosystem
		in   string
		want string
	}{
		{eco: model.NPM, in: "JSONStream", want: "JSONStream"},
		{eco: model.NPM, in: "@scope/name", want: "@scope/name"},
		{eco: model.PyPI, in: "Zope.Interface", want: "zope-interface"},
		{eco: model.PyPI, in: "zope__interface", want: "zope-interface"},
		{eco: model.PyPI, in: "Pillow", want: "pillow"},
		{eco: model.Cargo, in: "Serde", want: "serde"},
		{eco: model.Cargo, in: "rustc-serialize", want: "rustc-serialize"},
	}
	for _, tt := range cases {
		if got := lookupKey(tt.eco, tt.in); got != tt.want {
			t.Errorf("lookupKey(%s, %q) = %q, want %q", tt.eco, tt.in, got, tt.want)
		}
	}
}

func TestUsableMember(t *testing.T) {
	usable := []string{"GHSA-2226-4v3c-cff8.json", "MAL-2025-20690.json"}
	for _, name := range usable {
		if !usableMember(name) {
			t.Errorf("usableMember(%q) = false, want true", name)
		}
	}
	// The names below are what a hostile archive would use to write outside the
	// destination. Nothing here is ever extracted, so they cannot escape
	// anything, but they are still refused rather than parsed.
	unusable := []string{
		"", "notes.txt", "nested/GHSA-1.json", `..\..\evil.json`, "../evil.json",
		"C:/evil.json", "./GHSA-1.json", "..", ".",
	}
	for _, name := range unusable {
		if usableMember(name) {
			t.Errorf("usableMember(%q) = true, want false", name)
		}
	}
}

func TestBuildFromZipCounts(t *testing.T) {
	cases := []struct {
		eco        model.Ecosystem
		advisories int
		withdrawn  int
		packages   int
	}{
		{eco: model.NPM, advisories: 3, withdrawn: 1, packages: 3},
		{eco: model.PyPI, advisories: 3, withdrawn: 1, packages: 3},
		{eco: model.Cargo, advisories: 3, withdrawn: 1, packages: 3},
	}
	for _, tt := range cases {
		built, err := BuildFromZip(zipFixture(t, tt.eco), tt.eco, Limits{}, nil)
		if err != nil {
			t.Fatalf("%s: %v", tt.eco, err)
		}
		if built.Advisories != tt.advisories || built.Withdrawn != tt.withdrawn || built.Packages != tt.packages {
			t.Errorf("%s: advisories %d, withdrawn %d, packages %d; want %d, %d, %d",
				tt.eco, built.Advisories, built.Withdrawn, built.Packages, tt.advisories, tt.withdrawn, tt.packages)
		}
		if built.Unusable != 0 {
			t.Errorf("%s: %d unusable members, want 0", tt.eco, built.Unusable)
		}
		if len(built.Shards) == 0 || built.Bytes == 0 {
			t.Errorf("%s: %d shards, %d bytes", tt.eco, len(built.Shards), built.Bytes)
		}
	}
}

// TestBuildDropsForeignEcosystem checks the property that a per-ecosystem archive
// still carries whole records: the npm archive's lodash advisory also lists a
// PyPI package, and the npm index must not answer for it.
func TestBuildDropsForeignEcosystem(t *testing.T) {
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
	// The record's PyPI block was dropped, so npm knows nothing about requests.
	got, err := r.Lookup(model.NPM, "requests", "2.0.0")
	if err != nil || got != nil {
		t.Fatalf("Lookup(npm, requests) = %v, %v; want nil, nil", got, err)
	}
}

// TestBuildIsDeterministic is the promise that a refresh does not churn the
// cache: the same archive builds byte for byte the same shards, so WriteShards
// rewrites nothing.
func TestBuildIsDeterministic(t *testing.T) {
	for _, eco := range Indexable() {
		// Two archives with the same members, written separately, so nothing but
		// the record contents can be carrying the equality.
		first, err := BuildFromZip(zipFixture(t, eco), eco, Limits{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		second, err := BuildFromZip(zipFixture(t, eco), eco, Limits{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(first.Shards) != len(second.Shards) {
			t.Fatalf("%s: %d shards then %d", eco, len(first.Shards), len(second.Shards))
		}
		for name, want := range first.Shards {
			got, ok := second.Shards[name]
			if !ok {
				t.Fatalf("%s: shard %s missing from the second build", eco, name)
			}
			if !bytes.Equal(want, got) {
				t.Errorf("%s: shard %s differs between two builds\nfirst:  %s\nsecond: %s", eco, name, want, got)
			}
		}

		// And writing the second build over the first rewrites nothing.
		dir := t.TempDir()
		written, removed, err := WriteShards(dir, first)
		if err != nil {
			t.Fatal(err)
		}
		if written != len(first.Shards) || removed != 0 {
			t.Fatalf("%s: first write wrote %d and removed %d, want %d and 0", eco, written, removed, len(first.Shards))
		}
		written, removed, err = WriteShards(dir, second)
		if err != nil {
			t.Fatal(err)
		}
		if written != 0 || removed != 0 {
			t.Errorf("%s: rewriting the same index wrote %d and removed %d, want 0 and 0", eco, written, removed)
		}
	}
}

// TestWriteShardsRemovesStaleShards checks that an ecosystem that loses a package
// loses its shard file too, so the reader cannot answer from an index that is no
// longer there.
func TestWriteShardsRemovesStaleShards(t *testing.T) {
	dir := t.TempDir()
	full, err := BuildFromZip(zipFixture(t, model.NPM), model.NPM, Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteShards(dir, full); err != nil {
		t.Fatal(err)
	}
	empty := &Built{Ecosystem: model.NPM, Shards: map[string][]byte{}}
	written, removed, err := WriteShards(dir, empty)
	if err != nil {
		t.Fatal(err)
	}
	if written != 0 || removed != len(full.Shards) {
		t.Fatalf("wrote %d and removed %d, want 0 and %d", written, removed, len(full.Shards))
	}
	left, err := countShards(ecosystemDir(dir, model.NPM))
	if err != nil || left != 0 {
		t.Fatalf("%d shard files left, %v", left, err)
	}
}

func TestBuildRejectsUnsupportedEcosystem(t *testing.T) {
	if _, err := BuildFromZip(zipFixture(t, model.NPM), model.Deno, Limits{}, nil); err == nil {
		t.Fatal("want an error for an ecosystem OSV does not publish")
	}
}

// TestBuildRejectsCorruptArchive covers the two ways a downloaded archive is
// damaged. Neither must panic, and both must name the file.
func TestBuildRejectsCorruptArchive(t *testing.T) {
	good := zipFixtureBytes(t, model.NPM)

	t.Run("not a zip", func(t *testing.T) {
		path := writeZip(t, "garbage.zip", []byte("PK\x03\x04 this is not an archive at all, only the first bytes look like one"))
		_, err := BuildFromZip(path, model.NPM, Limits{}, nil)
		if err == nil {
			t.Fatal("want an error")
		}
		if !bytes.Contains([]byte(err.Error()), []byte(path)) {
			t.Errorf("error %q does not name %s", err, path)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		// Cutting the tail removes the end of central directory record, which is
		// what archive/zip looks for first.
		path := writeZip(t, "truncated.zip", good[:len(good)*6/10])
		_, err := BuildFromZip(path, model.NPM, Limits{}, nil)
		if err == nil {
			t.Fatal("want an error")
		}
		if !bytes.Contains([]byte(err.Error()), []byte(path)) {
			t.Errorf("error %q does not name %s", err, path)
		}
	})

	t.Run("damaged member", func(t *testing.T) {
		// The directory at the end stays intact, so the archive opens and only
		// the member's deflate stream is broken. Half an index is worse than
		// none, so this fails the build rather than skipping the member.
		damaged := bytes.Clone(good)
		for i := 200; i < 400 && i < len(damaged); i++ {
			damaged[i] ^= 0xff
		}
		path := writeZip(t, "damaged.zip", damaged)
		_, err := BuildFromZip(path, model.NPM, Limits{}, nil)
		if err == nil {
			t.Fatal("want an error")
		}
		if !bytes.Contains([]byte(err.Error()), []byte(path)) {
			t.Errorf("error %q does not name %s", err, path)
		}
	})
}

// TestBuildSkipsUndecodableMember checks the other half of that rule: a member
// that reads fine but is not an OSV record costs itself, not the refresh.
func TestBuildSkipsUndecodableMember(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "all.zip")
	f, err := os.Create(path) // #nosec G304 -- a path this test built.
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	members := map[string]string{
		"GHSA-good.json":   `{"id":"GHSA-good","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
		"GHSA-broken.json": `{"id":"GHSA-broken", this is not JSON`,
		"GHSA-noid.json":   `{"summary":"a record without an id"}`,
	}
	for name, body := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	built, err := BuildFromZip(path, model.NPM, Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if built.Advisories != 1 || built.Unusable != 2 {
		t.Fatalf("advisories %d, unusable %d; want 1 and 2", built.Advisories, built.Unusable)
	}
}

// TestBuildLimits covers each of the three guards on the archive contents.
func TestBuildLimits(t *testing.T) {
	path := zipFixture(t, model.NPM)

	t.Run("members", func(t *testing.T) {
		_, err := BuildFromZip(path, model.NPM, Limits{MaxEntries: 2}, nil)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})

	t.Run("one member", func(t *testing.T) {
		_, err := BuildFromZip(path, model.NPM, Limits{MaxEntryBytes: 64}, nil)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})

	t.Run("every member together", func(t *testing.T) {
		// Larger than any single member, smaller than the three together, so
		// only the running total can catch it.
		_, err := BuildFromZip(path, model.NPM, Limits{MaxTotalBytes: 1200}, nil)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})
}
