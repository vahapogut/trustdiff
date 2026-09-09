package baseline

import (
	"bytes"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Regenerate the golden file with: go test ./internal/baseline/ -update
var update = flag.Bool("update", false, "rewrite the golden files under testdata/")

// fixture is the baseline every golden test writes: one package per ecosystem,
// each with a different combination of the fields that may be absent, put in an
// order that is not the order the file stores. The values are invented; no real
// package is described.
func fixture() *File {
	f := New(now)
	f.Put(&Entry{
		Ecosystem: model.PyPI, Name: "example-tool", Version: "2.32.3", ObservedAt: ago(2 * day),
		Maintainers:     []string{"org:example", "carol"},
		Publisher:       "github:example/example-tool/publish.yml",
		PublisherSource: FromProvenance,
		Provenance: &Provenance{
			Kind: model.ProvenanceAttestation, Verified: true,
			Identity: "github:example/example-tool/publish.yml",
		},
	})
	f.Put(&Entry{
		Ecosystem: model.NPM, Name: "example-lib", Version: "4.19.2", ObservedAt: ago(2 * day),
		Maintainers:     []string{"alice"},
		Publisher:       "alice",
		PublisherSource: FromRegistry,
		Provenance:      &Provenance{Kind: model.ProvenanceNone},
	})
	// A scoped name sorts before an unscoped one, and this entry carries no
	// provenance at all, which is what a release nobody could ask about looks like.
	f.Put(&Entry{
		Ecosystem: model.NPM, Name: "@example/scoped", Version: "2.0.0", ObservedAt: ago(9 * day),
		Maintainers: []string{"bob-ci", "alice"},
	})
	f.Put(&Entry{
		Ecosystem: model.Cargo, Name: "example-crate", Version: "1.0.200", ObservedAt: ago(2 * day),
		Maintainers:     []string{"dave", "github:example:crates"},
		Publisher:       "github:example/example-crate",
		PublisherSource: FromRegistry,
		Provenance: &Provenance{
			Kind: model.ProvenanceTrustedPublisher, Verified: false,
			Identity: "github:example/example-crate",
		},
	})
	return f
}

const goldenPath = "baseline.json.golden"

// The written document is the golden file, byte for byte: entries sorted by
// ecosystem and name, times in UTC, two-space indentation and a trailing newline.
// A stable rendering is the whole point of the format, because a file that
// reorders itself on every run is a file a repository churns on.
func TestWriteMatchesTheGolden(t *testing.T) {
	got, err := Bytes(fixture())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", goldenPath)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))) {
		t.Errorf("written baseline does not match testdata/%s:\n%s", goldenPath, got)
	}
}

// What the writer produced must read back as the same file, and writing it again
// must produce the same bytes: the file is compared in pull requests, so a round
// trip that changed a line would show up as a change nobody made.
func TestWriteReadWriteIsStable(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	if err := Write(path, fixture()); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(path, loaded); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("a read and a rewrite changed the file:\n%s\n%s", first, second)
	}
}

// The write is atomic: the directory is created, nothing is left behind, and a
// second write replaces the file rather than appending to it.
func TestWriteReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	if err := Write(path, file(entry("npm:example-lib@1.0.0", day, "alice"))); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, file(entry("npm:example-lib@2.0.0", 0, "alice", "bob-ci"))); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Packages) != 1 || got.Packages[0].Version != "2.0.0" {
		t.Fatalf("packages = %+v, want only the second write", got.Packages)
	}
	left, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].Name() != FileName {
		names := make([]string, 0, len(left))
		for _, e := range left {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only %s: a temporary file was left behind", names, FileName)
	}
}

// A project with no baseline is not a failure, and the caller tells the two apart
// with fs.ErrNotExist.
func TestLoadMissingFile(t *testing.T) {
	_, err := Load(Path(t.TempDir()))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestFindWalksUpwards(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "packages", "web")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, found, err := Find(deep); err != nil || found {
		t.Fatalf("found = %v, err = %v, want nothing found", found, err)
	}
	if err := Write(Path(root), New(now)); err != nil {
		t.Fatal(err)
	}
	path, found, err := Find(deep)
	if err != nil || !found {
		t.Fatalf("found = %v, err = %v, want the repository's baseline", found, err)
	}
	if path != Path(root) {
		t.Errorf("path = %q, want %q", path, Path(root))
	}
}

// A directory named baseline.json is not a baseline, and the walk must carry on
// past it rather than reporting it as the file.
func TestFindIgnoresADirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(Path(root), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, found, err := Find(root); err != nil || found {
		t.Fatalf("found = %v, err = %v, want nothing found", found, err)
	}
}

func TestParseRejects(t *testing.T) {
	valid := `{"schema":"trustdiff.baseline/1","updated_at":"2026-09-09T12:00:00Z","packages":[` +
		`{"ecosystem":"npm","name":"example-lib","version":"1.0.0","observed_at":"2026-09-08T12:00:00Z"}]}`
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatalf("the valid document was rejected: %v", err)
	}
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "another schema version",
			doc:  strings.Replace(valid, "trustdiff.baseline/1", "trustdiff.baseline/2", 1),
			want: "not a trustdiff baseline of schema version 1",
		},
		{
			name: "a field this binary does not know",
			doc:  strings.Replace(valid, `"version":"1.0.0"`, `"version":"1.0.0","surprise":true`, 1),
			want: "unknown field",
		},
		{
			name: "an ecosystem nothing reads",
			doc:  strings.Replace(valid, `"ecosystem":"npm"`, `"ecosystem":"maven"`, 1),
			want: `unknown ecosystem "maven"`,
		},
		{
			name: "an entry with no version",
			doc:  strings.Replace(valid, `"version":"1.0.0"`, `"version":""`, 1),
			want: "empty version",
		},
		{
			name: "an entry that was never observed",
			doc:  strings.Replace(valid, `"observed_at":"2026-09-08T12:00:00Z"`, `"observed_at":"0001-01-01T00:00:00Z"`, 1),
			want: "missing observed_at",
		},
		{
			name: "a publisher from nowhere",
			doc:  strings.Replace(valid, `"version":"1.0.0"`, `"version":"1.0.0","publisher":"alice"`, 1),
			want: "publisher_source",
		},
		{
			name: "one package recorded twice",
			doc: strings.Replace(valid, `"observed_at":"2026-09-08T12:00:00Z"}]`,
				`"observed_at":"2026-09-08T12:00:00Z"},{"ecosystem":"npm","name":"example-lib","version":"2.0.0","observed_at":"2026-09-08T12:00:00Z"}]`, 1),
			want: "is already recorded at packages[0]",
		},
		{
			name: "not JSON at all",
			doc:  "# a policy file, not a baseline\n",
			want: "decode the baseline",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.doc))
			if err == nil {
				t.Fatalf("the document was accepted: %s", tt.doc)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to name %q", err, tt.want)
			}
		})
	}
}

// A file written by hand, in any order and in any time zone, is served in the
// documented one.
func TestParseSortsAndNormalizes(t *testing.T) {
	doc := `{"schema":"trustdiff.baseline/1","updated_at":"2026-09-09T14:00:00.500+02:00","packages":[` +
		`{"ecosystem":"pypi","name":"Zope.Interface","version":"6.0","observed_at":"2026-09-08T14:00:00+02:00","maintainers":["carol","alice"]},` +
		`{"ecosystem":"npm","name":"example-lib","version":"1.0.0","observed_at":"2026-09-08T12:00:00Z"}]}`
	f, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if f.Packages[0].Ecosystem != model.NPM || f.Packages[1].Name != "zope-interface" {
		t.Fatalf("packages = %+v, want them sorted and PEP 503 normalized", f.Packages)
	}
	if got := f.Packages[1].Maintainers; got[0] != "alice" || got[1] != "carol" {
		t.Errorf("maintainers = %v, want them sorted", got)
	}
	if want := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC); !f.UpdatedAt.Equal(want) {
		t.Errorf("updated_at = %s, want %s", f.UpdatedAt, want)
	}
}
