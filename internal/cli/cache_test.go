package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory/osvindex"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/version"
)

// fillCache writes n entries into dir through the real client and a local server.
func fillCache(t *testing.T, dir string, n int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := httpcache.New(httpcache.Options{
		Dir:       dir,
		UserAgent: version.UserAgent(),
		HostRPS:   map[string]float64{u.Host: 10000},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := c.Get(context.Background(), srv.URL+"/pkg-"+string(rune('a'+i)), httpcache.Request{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCacheStatusAndClear(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)

	code, stdout, stderr := run(t, "cache", "status")
	if code != ExitOK || stderr != "" {
		t.Fatalf("status on empty cache: exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"Directory: " + dir, "Entries:   0", "Oldest:    none", "Newest:    none"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want it to contain %q", stdout, want)
		}
	}

	fillCache(t, dir, 2)

	code, stdout, stderr = run(t, "cache", "status")
	if code != ExitOK || stderr != "" {
		t.Fatalf("status: exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"Entries:   2", "Oldest:    less than a minute ago", "Newest:    less than a minute ago"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout = %q, want it to contain %q", stdout, want)
		}
	}

	code, stdout, stderr = run(t, "--format", "json", "cache", "status")
	if code != ExitOK || stderr != "" {
		t.Fatalf("status json: exit %d, stderr %q", code, stderr)
	}
	var report struct {
		Dir     string    `json:"dir"`
		Entries int       `json:"entries"`
		Bytes   int64     `json:"bytes"`
		Oldest  time.Time `json:"oldest_fetched_at"`
		Newest  time.Time `json:"newest_fetched_at"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("status --format json is not JSON: %v\n%s", err, stdout)
	}
	if report.Dir != dir || report.Entries != 2 || report.Bytes <= 0 || report.Oldest.IsZero() || report.Newest.IsZero() {
		t.Fatalf("json report = %+v", report)
	}

	code, stdout, stderr = run(t, "cache", "clear")
	if code != ExitOK || stderr != "" {
		t.Fatalf("clear: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "Removed 2 entries") || !strings.Contains(stdout, dir) {
		t.Fatalf("clear stdout = %q", stdout)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("after clear: %d files, %v", len(entries), err)
	}

	code, stdout, _ = run(t, "cache", "clear")
	if code != ExitOK || !strings.Contains(stdout, "Nothing to remove") {
		t.Fatalf("second clear: exit %d, stdout %q", code, stdout)
	}
}

func TestCacheClearJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)
	fillCache(t, dir, 1)
	code, stdout, stderr := run(t, "--format", "json", "cache", "clear")
	if code != ExitOK || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var report struct {
		Dir     string `json:"dir"`
		Entries int    `json:"removed_entries"`
		Bytes   int64  `json:"removed_bytes"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if report.Dir != dir || report.Entries != 1 || report.Bytes <= 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestCacheClearRefusesForeignDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)
	keep := filepath.Join(dir, "thesis.docx")
	if err := os.WriteFile(keep, []byte("irreplaceable"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "cache", "clear")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "refusing") || !strings.Contains(stderr, "thesis.docx") {
		t.Errorf("stderr = %q", stderr)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("foreign file was removed: %v", err)
	}
}

func TestCacheDirPrecedence(t *testing.T) {
	envDir := t.TempDir()
	flagDir := filepath.Join(t.TempDir(), "flag")
	t.Setenv(httpcache.EnvDir, envDir)

	_, stdout, _ := run(t, "cache", "status")
	if !strings.Contains(stdout, "Directory: "+envDir) {
		t.Errorf("env not honored: %q", stdout)
	}
	code, stdout, stderr := run(t, "cache", "status", "--cache-dir", flagDir)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "Directory: "+flagDir) || !strings.Contains(stdout, "Entries:   0") {
		t.Errorf("flag not honored or missing dir not reported as empty: %q", stdout)
	}
	if _, err := os.Stat(flagDir); err == nil {
		t.Error("cache status created the directory; it should only read")
	}
}

func TestCacheStubsStillExit2(t *testing.T) {
	for _, sub := range []string{"refresh-lists"} {
		code, _, stderr := run(t, "cache", sub)
		if code != ExitUsage || !strings.Contains(stderr, "not implemented") {
			t.Errorf("cache %s: exit %d, stderr %q", sub, code, stderr)
		}
	}
}

func TestFormatHelpers(t *testing.T) {
	ages := []struct {
		d    time.Duration
		want string
	}{
		{d: -time.Second, want: "less than a minute ago"},
		{d: 30 * time.Second, want: "less than a minute ago"},
		{d: 5 * time.Minute, want: "5m ago"},
		{d: 3*time.Hour + 7*time.Minute, want: "3h 7m ago"},
		{d: 49 * time.Hour, want: "2d 1h ago"},
	}
	for _, tt := range ages {
		if got := formatAge(tt.d); got != tt.want {
			t.Errorf("formatAge(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
	sizes := []struct {
		n    int64
		want string
	}{
		{n: 0, want: "0 B"},
		{n: 1023, want: "1023 B"},
		{n: 1024, want: "1.0 KiB"},
		{n: 1536, want: "1.5 KiB"},
		{n: 5 << 20, want: "5.0 MiB"},
		{n: 3 << 30, want: "3.0 GiB"},
	}
	for _, tt := range sizes {
		if got := formatBytes(tt.n); got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// advisoryArchives builds one OSV style archive per ecosystem, each holding a
// single hand written record, and serves them at the paths the real bucket uses.
// The index format itself is covered in internal/advisory/osvindex; what these
// tests need is a server the command can be pointed at without the network.
func advisoryArchives(t *testing.T) *httptest.Server {
	t.Helper()
	records := map[model.Ecosystem]string{
		model.NPM: `{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection in lodash",
			"published":"2021-05-06T16:05:51Z","modified":"2026-01-11T05:08:55Z",
			"database_specific":{"severity":"HIGH"},
			"affected":[{"package":{"name":"lodash","ecosystem":"npm"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"4.0.0"},{"fixed":"4.17.21"}]}]}]}`,
		model.PyPI: `{"id":"GHSA-6d5v-tt3m-jt7v","summary":"Django denial of service",
			"published":"2026-02-14T21:30:40Z","modified":"2026-02-20T18:26:14Z",
			"affected":[{"package":{"name":"Django","ecosystem":"PyPI"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.2"},{"last_affected":"3.2.18"}]}]}]}`,
		model.Cargo: `{"id":"GHSA-2226-4v3c-cff8","summary":"Stack overflow in rustc_serialize",
			"published":"2022-06-17T00:18:24Z","modified":"2023-11-08T04:13:48Z",
			"affected":[{"package":{"name":"rustc-serialize","ecosystem":"crates.io"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"0.3.24"}]}]}]}`,
	}
	archives := map[string][]byte{}
	for eco, record := range records {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(recordID(t, record) + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(record)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		archives["/"+osvindex.OSVEcosystem(eco)+"/"+osvindex.ArchiveName] = buf.Bytes()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := archives[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// recordID reads the id out of one record, so the archive member is named after
// it the way the real archives name theirs.
func recordID(t *testing.T, record string) string {
	t.Helper()
	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(record), &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed.ID
}

// useArchiveServer points "cache refresh" at a local server for one test.
func useArchiveServer(t *testing.T, url string) {
	t.Helper()
	previous := refreshOptions
	refreshOptions = func() osvindex.Options { return osvindex.Options{BaseURL: url} }
	t.Cleanup(func() { refreshOptions = previous })
}

func TestCacheRefreshStatusAndClear(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)
	useArchiveServer(t, advisoryArchives(t).URL)

	code, stdout, stderr := run(t, "cache", "status")
	if code != ExitOK || stderr != "" {
		t.Fatalf("status before a refresh: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "Advisory index: none") || !strings.Contains(stdout, "cache refresh") {
		t.Fatalf("status before a refresh should say there is no index: %q", stdout)
	}

	code, stdout, stderr = run(t, "cache", "refresh")
	if code != ExitOK || stderr != "" {
		t.Fatalf("refresh: exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	for _, want := range []string{"npm", "pypi", "cargo", "1 advisories for 1 packages", osvindex.Dir(dir)} {
		if !strings.Contains(stdout, want) {
			t.Errorf("refresh stdout = %q, want it to contain %q", stdout, want)
		}
	}

	code, stdout, stderr = run(t, "cache", "status")
	if code != ExitOK || stderr != "" {
		t.Fatalf("status: exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"Advisory index:", "npm    1 advisories", "pypi   1 advisories", "cargo  1 advisories", "downloaded less than a minute ago"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("status stdout = %q, want it to contain %q", stdout, want)
		}
	}
	if strings.Contains(stdout, "stale") {
		t.Errorf("a fresh index reads as stale: %q", stdout)
	}

	// A second refresh downloads the same archive and rewrites nothing, because
	// the index is built deterministically.
	code, stdout, _ = run(t, "cache", "refresh")
	if code != ExitOK || !strings.Contains(stdout, "index unchanged") {
		t.Fatalf("second refresh: exit %d, stdout %q", code, stdout)
	}

	code, stdout, stderr = run(t, "cache", "clear")
	if code != ExitOK || stderr != "" {
		t.Fatalf("clear: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "advisory index included") {
		t.Errorf("clear stdout = %q, want it to mention the advisory index", stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, osvindex.Subdir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the index survived cache clear: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("after clear: %d files, %v", len(entries), err)
	}
}

func TestCacheStatusReportsAStaleIndex(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)
	useArchiveServer(t, advisoryArchives(t).URL)

	if code, _, stderr := run(t, "cache", "refresh", "--ecosystem", "npm"); code != ExitOK {
		t.Fatalf("refresh: exit %d, stderr %q", code, stderr)
	}
	// Backdate the download past the threshold. An index that looks fresh but is
	// not is worse than none, so the status line has to say so.
	metaPath := filepath.Join(dir, osvindex.Subdir, "osv", "npm", "meta.json")
	data, err := os.ReadFile(metaPath) // #nosec G304 -- a path this test built.
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatal(err)
	}
	meta["downloaded_at"] = time.Now().Add(-osvindex.StaleAfter - time.Hour).UTC().Format(time.RFC3339Nano)
	if data, err = json.Marshal(meta); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := run(t, "cache", "status")
	if code != ExitOK {
		t.Fatalf("status: exit %d", code)
	}
	if !strings.Contains(stdout, "stale") || !strings.Contains(stdout, "cache refresh") {
		t.Errorf("status stdout = %q, want it to call the index stale", stdout)
	}
	if !strings.Contains(stdout, "pypi   not downloaded") {
		t.Errorf("status stdout = %q, want it to name the ecosystems that are missing", stdout)
	}

	code, stdout, _ = run(t, "--format", "json", "cache", "status")
	if code != ExitOK {
		t.Fatalf("status json: exit %d", code)
	}
	var report struct {
		AdvisoryIndex struct {
			Dir        string `json:"dir"`
			Bytes      int64  `json:"bytes"`
			StaleAfter string `json:"stale_after"`
			Ecosystems []struct {
				Ecosystem  string  `json:"ecosystem"`
				Advisories int     `json:"advisories"`
				AgeSeconds float64 `json:"age_seconds"`
				Stale      bool    `json:"stale"`
			} `json:"ecosystems"`
		} `json:"advisory_index"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("status --format json is not JSON: %v\n%s", err, stdout)
	}
	index := report.AdvisoryIndex
	if index.Dir != osvindex.Dir(dir) || index.Bytes == 0 || index.StaleAfter == "" {
		t.Fatalf("advisory_index = %+v", index)
	}
	if len(index.Ecosystems) != 1 {
		t.Fatalf("%d ecosystems, want 1", len(index.Ecosystems))
	}
	if index.Ecosystems[0].Ecosystem != "npm" || index.Ecosystems[0].Advisories != 1 {
		t.Errorf("ecosystem = %+v", index.Ecosystems[0])
	}
	if !index.Ecosystems[0].Stale || index.Ecosystems[0].AgeSeconds < osvindex.StaleAfter.Seconds() {
		t.Errorf("ecosystem = %+v, want it stale", index.Ecosystems[0])
	}
}

func TestCacheRefreshJSONAndFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)
	// A server that knows nothing, so every ecosystem fails.
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	useArchiveServer(t, srv.URL)

	code, stdout, stderr := run(t, "--format", "json", "cache", "refresh", "--ecosystem", "npm", "--ecosystem", "cargo")
	if code != ExitUnavailable {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, ExitUnavailable, stderr)
	}
	var report struct {
		Dir        string `json:"dir"`
		Ecosystems []struct {
			Ecosystem string `json:"ecosystem"`
			Error     string `json:"error"`
		} `json:"ecosystems"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if report.Dir != dir || len(report.Ecosystems) != 2 {
		t.Fatalf("report = %+v", report)
	}
	for _, e := range report.Ecosystems {
		if e.Error == "" || !strings.Contains(e.Error, "404") {
			t.Errorf("%s: error = %q, want one naming the status", e.Ecosystem, e.Error)
		}
	}
}

func TestCacheRefreshEcosystemSelection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)
	useArchiveServer(t, advisoryArchives(t).URL)

	// --ecosystem wins over everything.
	if code, stdout, stderr := run(t, "cache", "refresh", "--ecosystem", "cargo"); code != ExitOK {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	index, err := osvindex.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Ecosystems) != 1 || index.Ecosystems[0].Ecosystem != model.Cargo {
		t.Fatalf("index = %+v", index.Ecosystems)
	}

	// An ecosystem OSV publishes no archive for is a usage error, named.
	code, _, stderr := run(t, "cache", "refresh", "--ecosystem", "deno")
	if code != ExitUsage || !strings.Contains(stderr, "deno") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	code, _, stderr = run(t, "cache", "refresh", "--ecosystem", "nope")
	if code != ExitUsage || !strings.Contains(stderr, "unknown ecosystem") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}

	// The policy decides when the flag is absent.
	policyPath := filepath.Join(t.TempDir(), ".trustdiff.yaml")
	if err := os.WriteFile(policyPath, []byte("version: 1\necosystems:\n  pypi:\n    cooldown: 7d\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run(t, "--policy", policyPath, "cache", "refresh"); code != ExitOK {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	if index, err = osvindex.Stat(dir); err != nil {
		t.Fatal(err)
	}
	if len(index.Ecosystems) != 2 {
		t.Fatalf("index = %+v, want cargo from the flag run and pypi from the policy", index.Ecosystems)
	}
}

func TestCacheRefreshRefusesOffline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)
	code, _, stderr := run(t, "--offline", "cache", "refresh", "--ecosystem", "npm")
	if code != ExitUsage || !strings.Contains(stderr, "offline") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

// TestCacheClearRefusesAForeignIndexDirectory checks that the advisory index is
// held to the same rule as the rest of the cache: a directory trustdiff did not
// fill is never emptied.
func TestCacheClearRefusesAForeignIndexDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(httpcache.EnvDir, dir)
	useArchiveServer(t, advisoryArchives(t).URL)
	if code, _, stderr := run(t, "cache", "refresh", "--ecosystem", "npm"); code != ExitOK {
		t.Fatalf("refresh: exit %d, stderr %q", code, stderr)
	}
	keep := filepath.Join(dir, osvindex.Subdir, "osv", "npm", "thesis.docx")
	if err := os.WriteFile(keep, []byte("irreplaceable"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "cache", "clear")
	if code != ExitUsage || !strings.Contains(stderr, "refusing") || !strings.Contains(stderr, "thesis.docx") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the foreign file was removed: %v", err)
	}
}
