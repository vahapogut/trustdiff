package httpcache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultDir(t *testing.T) {
	t.Setenv(EnvDir, "")
	got, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	userDir, err := os.UserCacheDir()
	if err != nil {
		t.Skip("no user cache dir on this machine")
	}
	if want := filepath.Join(userDir, "trustdiff"); got != want {
		t.Fatalf("DefaultDir() = %q, want %q", got, want)
	}

	custom := t.TempDir()
	t.Setenv(EnvDir, custom)
	got, err = DefaultDir()
	if err != nil || got != custom {
		t.Fatalf("DefaultDir() with %s = %q, %v; want %q", EnvDir, got, err, custom)
	}

	// New honors the same variable when Dir is empty.
	c, err := New(Options{UserAgent: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Dir() != custom {
		t.Fatalf("New().Dir() = %q, want %q", c.Dir(), custom)
	}
}

func TestEntryFileNameScheme(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	tests := []struct {
		name string
		want bool
	}{
		{name: hash + ".json", want: true},
		{name: hash + ".body", want: true},
		{name: hash + ".json.123456.tmp", want: true},
		{name: hash + ".body.7.tmp", want: true},
		{name: hash + ".txt", want: false},
		{name: hash[:63] + ".json", want: false},
		{name: strings.ToUpper(hash) + ".json", want: false},
		{name: "notes.txt", want: false},
		{name: hash + ".json.tmp", want: false},
		{name: ".DS_Store", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := entryFileName.MatchString(tt.name); got != tt.want {
				t.Fatalf("entryFileName.MatchString(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestStatAndClear(t *testing.T) {
	ts := newTestServer(t, okHandler("0123456789"))
	env := newTestEnv(t, ts, nil)
	ctx := context.Background()

	empty, err := Stat(env.dir)
	if err != nil {
		t.Fatal(err)
	}
	if empty != (Stats{}) {
		t.Fatalf("Stat(empty) = %+v, want zero", empty)
	}

	first := env.clock.now()
	if _, err := env.client.Get(ctx, ts.URL+"/a", Request{}); err != nil {
		t.Fatal(err)
	}
	env.clock.advance(time.Hour)
	if _, err := env.client.Get(ctx, ts.URL+"/b", Request{}); err != nil {
		t.Fatal(err)
	}
	second := env.clock.now()

	stats, err := Stat(env.dir)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Entries != 2 {
		t.Errorf("Entries = %d, want 2", stats.Entries)
	}
	if stats.Bytes <= 20 {
		t.Errorf("Bytes = %d, want body and metadata bytes", stats.Bytes)
	}
	if !stats.OldestFetchedAt.Equal(first) || !stats.NewestFetchedAt.Equal(second) {
		t.Errorf("oldest %v newest %v, want %v and %v", stats.OldestFetchedAt, stats.NewestFetchedAt, first, second)
	}

	if err := Clear(env.dir); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if names := entryFiles(t, env.dir); len(names) != 0 {
		t.Fatalf("files after Clear = %v", names)
	}
	after, err := Stat(env.dir)
	if err != nil || after != (Stats{}) {
		t.Fatalf("Stat after Clear = %+v, %v", after, err)
	}
	if _, err := os.Stat(env.dir); err != nil {
		t.Fatalf("Clear removed the directory itself: %v", err)
	}
}

func TestStatCountsLeftoverTempFilesAsBytesOnly(t *testing.T) {
	dir := t.TempDir()
	hash := strings.Repeat("cd", 32)
	if err := os.WriteFile(filepath.Join(dir, hash+".body.42.tmp"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hash+".json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	stats, err := Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Entries != 0 {
		t.Errorf("Entries = %d, want 0 for corrupt metadata", stats.Entries)
	}
	if stats.Bytes != int64(len("partial")+len("{corrupt")) {
		t.Errorf("Bytes = %d", stats.Bytes)
	}
	if err := Clear(dir); err != nil {
		t.Fatalf("Clear must remove our own leftovers: %v", err)
	}
	if names := entryFiles(t, dir); len(names) != 0 {
		t.Fatalf("files after Clear = %v", names)
	}
}

func TestStatAndClearOnMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never-created")
	stats, err := Stat(dir)
	if err != nil || stats != (Stats{}) {
		t.Fatalf("Stat(missing) = %+v, %v", stats, err)
	}
	if err := Clear(dir); err != nil {
		t.Fatalf("Clear(missing) = %v, want nil", err)
	}
}

func TestClearRefusesForeignDirectories(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{name: "foreign file", setup: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "subdirectory", setup: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(filepath.Join(dir, "photos"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestServer(t, okHandler("x"))
			env := newTestEnv(t, ts, nil)
			if _, err := env.client.Get(context.Background(), ts.URL, Request{}); err != nil {
				t.Fatal(err)
			}
			tt.setup(t, env.dir)
			err := Clear(env.dir)
			if !errors.Is(err, ErrForeignFiles) {
				t.Fatalf("Clear = %v, want ErrForeignFiles", err)
			}
			if names := entryFiles(t, env.dir); len(names) != 3 {
				t.Fatalf("Clear removed something from a refused directory: %v", names)
			}
			if _, err := Stat(env.dir); err != nil {
				t.Fatalf("Stat must still work on a mixed directory: %v", err)
			}
		})
	}
}

func TestWriteFileAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("ef", 32) + bodySuffix
	if err := writeFileAtomic(dir, name, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(dir, name, []byte("two")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || string(got) != "two" {
		t.Fatalf("content = %q, %v", got, err)
	}
	if names := entryFiles(t, dir); len(names) != 1 {
		t.Fatalf("files = %v, want only the final file", names)
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		meta entryMeta
	}{
		{name: "hour", meta: entryMeta{URL: "u", Accept: "*/*", ETag: `"e"`, LastModified: "lm", FetchedAt: time.Date(2026, 9, 9, 1, 2, 3, 0, time.UTC), TTL: time.Hour, Status: 200, ContentType: "text/plain", Length: 12345}},
		{name: "forever", meta: entryMeta{URL: "u", Accept: "a", FetchedAt: time.Date(2026, 9, 9, 1, 2, 3, 0, time.UTC), TTL: Forever, Status: 404}},
		{name: "post", meta: entryMeta{Method: "POST", URL: "u", Accept: "application/json", BodySHA256: strings.Repeat("ab", 32), FetchedAt: time.Date(2026, 9, 9, 1, 2, 3, 0, time.UTC), TTL: 6 * time.Hour, Status: 200, ContentType: "application/json", Length: 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.meta.marshal()
			if err != nil {
				t.Fatal(err)
			}
			if tt.meta.TTL == Forever && !strings.Contains(string(data), `"ttl": "forever"`) {
				t.Errorf("Forever not written as the word forever: %s", data)
			}
			// An empty body is a real length, so it is written even when zero.
			if !strings.Contains(string(data), `"length": `) {
				t.Errorf("length not written: %s", data)
			}
			got, err := parseMeta(data)
			if err != nil {
				t.Fatalf("parse: %v\n%s", err, data)
			}
			if got != tt.meta {
				t.Fatalf("round trip = %+v, want %+v", got, tt.meta)
			}
		})
	}
}

func TestParseMetaRejectsNegativeLength(t *testing.T) {
	data := `{"url":"u","accept":"*/*","fetched_at":"2026-09-09T12:00:00Z","ttl":"1h0m0s","status":200,"length":-1}`
	if _, err := parseMeta([]byte(data)); err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("parseMeta error = %v, want it to mention the length", err)
	}
}

func TestMetaFresh(t *testing.T) {
	at := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		ttl  time.Duration
		now  time.Time
		want bool
	}{
		{name: "within ttl", ttl: time.Hour, now: at.Add(59 * time.Minute), want: true},
		{name: "at ttl", ttl: time.Hour, now: at.Add(time.Hour), want: false},
		{name: "past ttl", ttl: time.Hour, now: at.Add(2 * time.Hour), want: false},
		{name: "forever", ttl: Forever, now: at.Add(1000 * 24 * time.Hour), want: true},
		{name: "zero ttl is stale", ttl: 0, now: at, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The entry was stored as Forever; only the requested ttl may count.
			m := entryMeta{FetchedAt: at, TTL: Forever}
			if got := m.fresh(tt.now, tt.ttl); got != tt.want {
				t.Fatalf("fresh(now, %v) = %v, want %v", tt.ttl, got, tt.want)
			}
		})
	}
}

func TestMetaMatches(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)
	get := entryMeta{Method: "GET", URL: "u", Accept: "*/*"}
	legacy := entryMeta{URL: "u", Accept: "*/*"} // written before Post existed
	post := entryMeta{Method: "POST", URL: "u", Accept: "*/*", BodySHA256: hash}
	tests := []struct {
		name     string
		meta     entryMeta
		method   string
		url      string
		accept   string
		bodyHash string
		want     bool
	}{
		{name: "get", meta: get, method: "GET", url: "u", accept: "*/*", want: true},
		{name: "get other url", meta: get, method: "GET", url: "v", accept: "*/*", want: false},
		{name: "get other accept", meta: get, method: "GET", url: "u", accept: "application/json", want: false},
		{name: "legacy entry is a get", meta: legacy, method: "GET", url: "u", accept: "*/*", want: true},
		{name: "legacy entry is not a post", meta: legacy, method: "POST", url: "u", accept: "*/*", bodyHash: hash, want: false},
		{name: "post", meta: post, method: "POST", url: "u", accept: "*/*", bodyHash: hash, want: true},
		{name: "post other body", meta: post, method: "POST", url: "u", accept: "*/*", bodyHash: other, want: false},
		{name: "post entry for a get", meta: post, method: "GET", url: "u", accept: "*/*", want: false},
		{name: "get entry for a post", meta: get, method: "POST", url: "u", accept: "*/*", bodyHash: hash, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.meta.matches(tt.method, tt.url, tt.accept, tt.bodyHash); got != tt.want {
				t.Fatalf("matches(%q, %q, %q, %q) = %v, want %v", tt.method, tt.url, tt.accept, tt.bodyHash, got, tt.want)
			}
		})
	}
}
