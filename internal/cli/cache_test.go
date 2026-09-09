package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
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
	for _, sub := range []string{"refresh-lists", "refresh"} {
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
