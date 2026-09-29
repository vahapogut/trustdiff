package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry/crates"
	"github.com/vahapogut/trustdiff/internal/registry/crates/dumpindex"
	"github.com/vahapogut/trustdiff/internal/report"
)

func cratesCLIFixture(t *testing.T, snapshot time.Time) []byte {
	t.Helper()
	data := map[string]string{
		"metadata.json":     `{"timestamp":"` + snapshot.Format(time.RFC3339Nano) + `","crates_io_commit":"fixture"}`,
		"data/crates.csv":   "id,name,created_at,updated_at\n1,test_crate,2020-01-01T00:00:00Z," + snapshot.Format(time.RFC3339Nano) + "\n",
		"data/users.csv":    "id,gh_login,username\n2,publisher,publisher\n",
		"data/versions.csv": "crate_id,num,created_at,published_by,yanked,tar_sha256\n1,1.0.0," + snapshot.Format(time.RFC3339Nano) + ",2,f," + strings.Repeat("a", 64) + "\n",
	}
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for name, body := range data {
		if err := tw.WriteHeader(&tar.Header{Name: "snapshot/" + name, Mode: 0o600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func installCLIDump(t *testing.T, snapshot time.Time) (string, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)
	body := cratesCLIFixture(t, snapshot)
	calls := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	previous := cratesRefreshOptions
	cratesRefreshOptions = func() dumpindex.Options {
		return dumpindex.Options{URL: srv.URL, Now: func() time.Time { return snapshot }}
	}
	t.Cleanup(func() { cratesRefreshOptions = previous })
	code, stdout, stderr := run(t, "--format", "json", "cache", "refresh", "--crates-dump")
	if code != ExitOK || stderr != "" {
		t.Fatalf("refresh: %d %s %s", code, stdout, stderr)
	}
	var meta dumpindex.Meta
	if err := json.Unmarshal([]byte(stdout), &meta); err != nil || meta.Crates != 1 || meta.Versions != 1 {
		t.Fatalf("metadata: %s %v", stdout, err)
	}
	return dir, calls
}

func TestCratesCacheRefreshStatusClear(t *testing.T) {
	dir, calls := installCLIDump(t, time.Now().UTC().Add(-time.Hour))
	if httpcache.CratesSubdir != dumpindex.Subdir {
		t.Fatal("cache ownership subdirectories differ")
	}
	code, stdout, stderr := run(t, "--format", "json", "cache", "status")
	var r cacheStatusReport
	if code != ExitOK || stderr != "" || json.Unmarshal([]byte(stdout), &r) != nil {
		t.Fatalf("status: %d %s %s", code, stdout, stderr)
	}
	if r.CratesDump.Meta == nil || r.CratesDump.AgeSeconds < 3590 || r.CratesDump.Stale {
		t.Fatalf("status does not expose age: %+v", r.CratesDump)
	}
	code, stdout, stderr = run(t, "--format", "json", "cache", "clear")
	var cleared cacheClearReport
	if code != ExitOK || stderr != "" || json.Unmarshal([]byte(stdout), &cleared) != nil || cleared.RemovedCratesBytes <= 0 {
		t.Fatalf("clear: %d %s %s", code, stdout, stderr)
	}
	stats, err := dumpindex.Stat(dir)
	if err != nil || stats.Bytes != 0 || stats.Meta != nil {
		t.Fatalf("clear left index: %+v %v", stats, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected downloads: %d", calls.Load())
	}
}

func TestCratesDumpScanUsesIndexButCheckKeepsAPI(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	dir, calls := installCLIDump(t, now.Add(-time.Hour))
	t.Setenv(nowEnv, now.Format(time.RFC3339))
	project := t.TempDir()
	t.Chdir(project)
	lock := "version = 4\n\n[[package]]\nname = \"test-crate\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"" + strings.Repeat("a", 64) + "\"\n"
	if err := os.WriteFile(filepath.Join(project, "Cargo.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "--offline", "--format", "json", "scan", project)
	var r report.Report
	if code != ExitOK && code != ExitFindings {
		t.Fatalf("scan: %d %s %s", code, stdout, stderr)
	}
	if err := json.Unmarshal([]byte(stdout), &r); err != nil || len(r.Subjects) != 1 {
		t.Fatalf("scan report: %s %v", stdout, err)
	}
	s := r.Subjects[0]
	if s.Ref.Name != "test_crate" {
		t.Fatalf("dump canonicalization not used: %+v", s.Ref)
	}
	found := false
	for _, f := range s.Findings {
		if f.ID == "TD001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("dump publication time missing: %+v", s)
	}
	for _, sk := range s.Skipped {
		if sk.Check == "TD005" || sk.Check == "TD006" {
			if !strings.Contains(sk.Reason, "dump") && !strings.Contains(sk.Reason, "previous") {
				t.Errorf("missing explicit unavailable facet: %+v", sk)
			}
		}
	}
	_, stdout, _ = run(t, "--offline", "--format", "json", "check", "cargo:test-crate@1.0.0")
	if !strings.Contains(stdout, "offline") {
		t.Fatalf("single check incorrectly used dump: %s", stdout)
	}
	if calls.Load() != 1 {
		t.Fatalf("scan made %d bulk/API requests", calls.Load())
	}
	// A direct bulk source selection with the pinned run clock remains fresh
	// regardless of the wall clock on which this regression test runs.
	hc, err := httpcache.New(httpcache.Options{Dir: dir, Offline: true, UserAgent: "trustdiff-test"})
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	a := &App{Stderr: &diagnostics, Opts: Options{Log: slog.New(slog.DiscardHandler)}}
	api := crates.New(hc)
	if _, ok := a.bulkCratesSource(dir, api, now).(*dumpindex.Index); !ok {
		t.Fatalf("run clock not forwarded: %s", diagnostics.String())
	}
	if a.bulkCratesSource(dir, api, now.Add(72*time.Hour)) != api || !strings.Contains(diagnostics.String(), "stale") {
		t.Fatal("stale index did not fall back with diagnostic")
	}
	diagnostics.Reset()
	if err := os.WriteFile(filepath.Join(dumpindex.Dir(dir), "current.json"), []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if a.bulkCratesSource(dir, api, now) != api || !strings.Contains(diagnostics.String(), "metadata") {
		t.Fatal("corrupt metadata did not fall back with diagnostic")
	}
	diagnostics.Reset()
	if a.bulkCratesSource(t.TempDir(), api, now) != api || diagnostics.Len() != 0 {
		t.Fatal("missing index should keep ordinary API/cache behavior without a warning")
	}
}

func TestCratesDumpRefreshFlagValidation(t *testing.T) {
	for _, args := range [][]string{{"--offline", "cache", "refresh", "--crates-dump"}, {"cache", "refresh", "--crates-dump", "--ecosystem", "cargo"}} {
		code, _, _ := run(t, args...)
		if code != ExitUsage {
			t.Fatalf("%v exited %d", args, code)
		}
	}
}

func TestCorruptCratesShardDoesNotFallBackToAPI(t *testing.T) {
	now := time.Now().UTC()
	dir, calls := installCLIDump(t, now)
	meta, err := dumpindex.ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name := range meta.Shards {
		if err := os.WriteFile(filepath.Join(dumpindex.Dir(dir), meta.Generation, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := &App{Stderr: &bytes.Buffer{}, Opts: Options{Log: slog.New(slog.DiscardHandler)}}
	hc, err := httpcache.New(httpcache.Options{Dir: dir, Offline: true, UserAgent: "trustdiff-test"})
	if err != nil {
		t.Fatal(err)
	}
	source := a.bulkCratesSource(dir, crates.New(hc), now)
	if _, err := source.Versions(context.Background(), "test_crate"); err == nil || strings.Contains(err.Error(), "offline") {
		t.Fatalf("corrupt shard silently fell back: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("corrupt shard fetched another source")
	}
}

func TestCratesSnapshotMissFollowsUnavailablePolicy(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	_, calls := installCLIDump(t, now)
	t.Setenv(nowEnv, now.Format(time.RFC3339))
	project := t.TempDir()
	t.Chdir(project)
	var config strings.Builder
	config.WriteString("version: 1\non_data_unavailable: fail\nchecks:\n")
	for _, name := range policy.CheckNames() {
		level := "off"
		if name == "young-version" {
			level = "warn"
		}
		config.WriteString("  " + name + ": " + level + "\n")
	}
	if err := os.WriteFile(filepath.Join(project, ".trustdiff.yaml"), []byte(config.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, version string }{{"missing_crate", "1.0.0"}, {"test_crate", "9.9.9"}} {
		lock := "version = 4\n[[package]]\nname = \"" + tt.name + "\"\nversion = \"" + tt.version + "\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
		if err := os.WriteFile(filepath.Join(project, "Cargo.lock"), []byte(lock), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := run(t, "--offline", "--format", "json", "scan", project)
		if code != ExitUnavailable || !strings.Contains(stdout, "dump snapshot") {
			t.Fatalf("snapshot miss %s@%s: exit=%d stdout=%s stderr=%s", tt.name, tt.version, code, stdout, stderr)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("snapshot miss fetched additional registry data")
	}
}
