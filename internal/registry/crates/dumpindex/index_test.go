package dumpindex

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/registry/crates"
)

var fixtureTime = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func fixtureTables() map[string]string {
	return map[string]string{
		"metadata.json":         `{"timestamp":"2026-09-29T00:00:00Z","crates_io_commit":"0498d51e0f06f379c8e570db1628763ad4be7927"}`,
		"data/crates.csv":       "id,name,created_at,updated_at\n1,test_crate,2020-01-01 00:00:00,2026-09-28 00:00:00+00\n",
		"data/users.csv":        "id,gh_login,username\n2,old-login,publisher\n",
		"data/versions.csv":     "crate_id,num,created_at,published_by,yanked,tar_sha256\n1,1.0.0,2026-09-27 00:00:00,2,f,\\x" + strings.Repeat("a", 64) + "\n1,1.1.0-beta.1,2026-09-28T00:00:00Z,,t," + strings.Repeat("b", 64) + "\n",
		"data/teams.csv":        "id,login\n3,github:org:team\n",
		"data/crate_owners.csv": "crate_id,owner_kind,owner_id,created_at\n1,0,2,2020-01-01 00:00:00\n1,1,3,2020-01-01 00:00:00\n",
	}
}

func archiveFixture(t *testing.T, tables map[string]string, extra ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range tables {
		if err := tw.WriteHeader(&tar.Header{Name: "2026-09-29/" + name, Mode: 0o600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range extra {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func refreshFixture(t *testing.T, dir string, body []byte, modify func(*Options)) (*Meta, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "trustdiff-test" {
			t.Error("missing User-Agent")
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	o := Options{URL: srv.URL, UserAgent: "trustdiff-test", Now: func() time.Time { return fixtureTime }}
	if modify != nil {
		modify(&o)
	}
	return Refresh(context.Background(), dir, &o)
}

func TestRefreshReadsSnapshotWithoutPerCrateRequests(t *testing.T) {
	dir := t.TempDir()
	body := archiveFixture(t, fixtureTables())
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = w.Write(body) }))
	defer srv.Close()
	m, err := Refresh(context.Background(), dir, &Options{URL: srv.URL, Now: func() time.Time { return fixtureTime }})
	if err != nil {
		t.Fatal(err)
	}
	if m.Crates != 1 || m.Versions != 2 {
		t.Fatalf("counts: %+v", m)
	}
	i, err := Open(dir, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	list, err := i.Versions(context.Background(), "Test-Crate")
	if err != nil {
		t.Fatal(err)
	}
	if list.Name != "test_crate" || list.Latest != "1.0.0" || len(list.Versions) != 2 {
		t.Fatalf("list: %+v", list)
	}
	info, err := i.VersionInfo(context.Background(), model.MustParseRef("cargo:test_crate@1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Publisher == nil || info.Publisher.Name != "publisher" {
		t.Fatalf("publisher: %+v", info.Publisher)
	}
	for _, facet := range []string{model.FacetScripts, model.FacetDependencies, model.FacetProvenance} {
		if info.Unknown[facet] == "" {
			t.Errorf("%s was incorrectly treated as known", facet)
		}
	}
	owners, err := i.Owners(context.Background(), "test_crate")
	if err != nil || len(owners) != 2 {
		t.Fatalf("owners=%v err=%v", owners, err)
	}
	if _, err := i.Downloads(context.Background(), "test_crate"); !errors.Is(err, registry.ErrUnsupported) {
		t.Fatalf("downloads=%v", err)
	}
	if _, err := i.Versions(context.Background(), "missing"); !errors.Is(err, ErrSnapshotMiss) || errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("missing=%v", err)
	}
	if _, err := i.VersionInfo(context.Background(), model.MustParseRef("cargo:test_crate@9.9.9")); !errors.Is(err, ErrSnapshotMiss) || errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("missing version=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("made %d requests, want one bulk download", calls.Load())
	}
	stats, err := Stat(dir)
	if err != nil || stats.Meta == nil || stats.Bytes == 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
}

func TestRefreshRejectsUntrustedArchivesAndKeepsOldIndex(t *testing.T) {
	valid := archiveFixture(t, fixtureTables())
	tests := []struct {
		name     string
		tables   func(map[string]string)
		extra    *tar.Header
		options  func(*Options)
		truncate bool
	}{
		{name: "missing versions", tables: func(m map[string]string) { delete(m, "data/versions.csv") }},
		{name: "duplicate table", extra: &tar.Header{Name: "2026-09-29/data/crates.csv", Mode: 0o600}},
		{name: "parent traversal", extra: &tar.Header{Name: "2026-09-29/../../escape", Mode: 0o600}},
		{name: "absolute path", extra: &tar.Header{Name: "/escape", Mode: 0o600}},
		{name: "windows path", extra: &tar.Header{Name: `C:\escape`, Mode: 0o600}},
		{name: "symlink", extra: &tar.Header{Name: "2026-09-29/link", Typeflag: tar.TypeSymlink, Linkname: "../../escape"}},
		{name: "hardlink", extra: &tar.Header{Name: "2026-09-29/link", Typeflag: tar.TypeLink, Linkname: "../../escape"}},
		{name: "compressed limit", options: func(o *Options) { o.MaxDownloadBytes = 30 }},
		{name: "expanded limit", options: func(o *Options) { o.MaxExpandedBytes = 512 }},
		{name: "index limit", options: func(o *Options) { o.MaxIndexBytes = 40 }},
		{name: "row count", options: func(o *Options) { o.MaxRecords = 1 }},
		{name: "large quoted row", tables: func(m map[string]string) {
			m["data/crates.csv"] = "id,name,created_at,updated_at,readme\n1,test_crate,2020-01-01T00:00:00Z,2020-01-01T00:00:00Z,\"" + strings.Repeat("a\n", 10000) + "\"\n"
		}, options: func(o *Options) { o.MaxRowBytes = 4096 }},
		{name: "duplicate header", tables: func(m map[string]string) { m["data/users.csv"] = "id,id,gh_login\n2,2,publisher\n" }},
		{name: "missing header", tables: func(m map[string]string) { m["data/users.csv"] = "id,name\n2,publisher\n" }},
		{name: "invalid timestamp", tables: func(m map[string]string) { m["metadata.json"] = `{"timestamp":"bad","crates_io_commit":"x"}` }},
		{name: "future snapshot", tables: func(m map[string]string) {
			m["metadata.json"] = `{"timestamp":"2027-01-01T00:00:00Z","crates_io_commit":"x"}`
		}},
		{name: "unknown user", tables: func(m map[string]string) { m["data/users.csv"] = "id,gh_login\n9,publisher\n" }},
		{name: "truncated gzip", truncate: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			old, err := refreshFixture(t, dir, valid, nil)
			if err != nil {
				t.Fatal(err)
			}
			tables := fixtureTables()
			if tt.tables != nil {
				tt.tables(tables)
			}
			var extra []*tar.Header
			if tt.extra != nil {
				extra = append(extra, tt.extra)
			}
			body := archiveFixture(t, tables, extra...)
			if tt.truncate {
				body = body[:len(body)-5]
			}
			if _, err := refreshFixture(t, dir, body, tt.options); err == nil {
				t.Fatal("invalid archive succeeded")
			}
			current, err := ReadMeta(dir)
			if err != nil {
				t.Fatal(err)
			}
			if current.Generation != old.Generation {
				t.Fatal("failed refresh changed generation")
			}
			if _, err := Open(dir, fixtureTime); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIndexStalenessCorruptionAndCancellation(t *testing.T) {
	dir := t.TempDir()
	m, err := refreshFixture(t, dir, archiveFixture(t, fixtureTables()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, m.SnapshotAt.Add(StaleAfter)); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale index: %v", err)
	}
	i, err := Open(dir, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := i.Versions(ctx, "test_crate"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Refresh(ctx, dir, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled refresh: %v", err)
	}
	file := filepath.Join(Dir(dir), m.Generation, shardFor("test_crate"))
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-2] ^= 1
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Versions(context.Background(), "test_crate"); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupt index: %v", err)
	}
}

func TestClearRefusesForeignFilesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	m, err := refreshFixture(t, dir, archiveFixture(t, fixtureTables()), nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(Dir(dir), m.Generation, "keep.txt")
	if err := os.WriteFile(foreign, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir); err == nil {
		t.Fatal("foreign file was accepted")
	}
	if _, err := os.Stat(filepath.Join(Dir(dir), "current.json")); err != nil {
		t.Fatal("refused clear removed metadata")
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if err := Clear(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(Dir(dir))
	if err != nil || len(entries) != 0 {
		t.Fatalf("clear left files: %v, %v", entries, err)
	}
	if err := os.Remove(Dir(dir)); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, Dir(dir)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := Clear(dir); err == nil {
		t.Fatal("symlink directory was accepted")
	}
}

func TestDumpFactsMatchRecordedAPIResponses(t *testing.T) {
	tables := map[string]string{"metadata.json": fixtureTables()["metadata.json"]}
	for _, name := range []string{"crates.csv", "users.csv", "versions.csv"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		tables["data/"+name] = string(b)
	}
	dir := t.TempDir()
	if _, err := refreshFixture(t, dir, archiveFixture(t, tables), nil); err != nil {
		t.Fatal(err)
	}
	i, err := Open(dir, fixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/crates/")
		if name != "serde" && name != "cfg-if" && name != "paste" {
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(filepath.Join("..", "testdata", name+".json"))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	hc, err := httpcache.New(httpcache.Options{NoCache: true, UserAgent: "trustdiff-test"})
	if err != nil {
		t.Fatal(err)
	}
	api := crates.New(hc, crates.WithAPIBase(srv.URL))
	for _, name := range []string{"serde", "cfg-if", "paste"} {
		t.Run(name, func(t *testing.T) {
			want, err := api.Versions(context.Background(), name)
			if err != nil {
				t.Fatal(err)
			}
			got, err := i.Versions(context.Background(), name)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != want.Name || !got.Created.Equal(want.Created) || !got.Modified.Equal(want.Modified) || got.Latest != want.Latest || len(got.Versions) != len(want.Versions) {
				t.Fatalf("package facts differ: got %+v want name=%s created=%s modified=%s latest=%s versions=%d", got, want.Name, want.Created, want.Modified, want.Latest, len(want.Versions))
			}
			for n, v := range got.Versions {
				w := want.Versions[n]
				if v.Ref != w.Ref || !v.PublishedAt.Equal(w.PublishedAt) || v.Yanked != w.Yanked || v.Integrity != w.Integrity || v.Prerelease != w.Prerelease || !reflect.DeepEqual(v.Publisher, w.Publisher) {
					t.Errorf("version %s differs from pinned API", v.Ref)
				}
			}
		})
	}
}

func TestMetadataPathCannotEscapeIndex(t *testing.T) {
	dir := t.TempDir()
	m, err := refreshFixture(t, dir, archiveFixture(t, fixtureTables()), nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Generation = "../../outside"
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir(dir), "current.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, fixtureTime); err == nil {
		t.Fatal("escaping generation accepted")
	}
}
