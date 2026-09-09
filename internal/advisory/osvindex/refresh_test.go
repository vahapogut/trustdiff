package osvindex

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// archiveServer serves the fixture archive of every ecosystem at the same paths
// the real bucket uses, with an ETag, and honors If-None-Match. It records what
// it was asked for, so a test can prove that a conditional refresh transferred
// nothing.
type archiveServer struct {
	*httptest.Server

	mu       sync.Mutex
	requests []string
	bodies   int
	agents   []string
}

const fixtureETag = `"fixture-1"`

func newArchiveServer(t *testing.T) *archiveServer {
	t.Helper()
	archives := map[string][]byte{}
	for _, eco := range Indexable() {
		archives["/"+OSVEcosystem(eco)+"/"+ArchiveName] = zipFixtureBytes(t, eco)
	}
	s := &archiveServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.URL.Path)
		s.agents = append(s.agents, r.Header.Get("User-Agent"))
		s.mu.Unlock()
		body, ok := archives[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("ETag", fixtureETag)
		w.Header().Set("Last-Modified", "Wed, 09 Sep 2026 19:55:57 GMT")
		if r.Header.Get("If-None-Match") == fixtureETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		s.mu.Lock()
		s.bodies++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *archiveServer) counts() (requests, bodies int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests), s.bodies
}

// testOptions are the options every refresh test starts from.
func testOptions(base string) Options {
	return Options{BaseURL: base, UserAgent: "trustdiff-test/0 (+https://example.invalid)"}
}

func TestRefreshBuildsAndAnswers(t *testing.T) {
	srv := newArchiveServer(t)
	dir := t.TempDir()

	results, err := Refresh(context.Background(), dir, Indexable(), testOptions(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("%d results, want 3", len(results))
	}
	for i := range results {
		res := &results[i]
		if res.Err != nil {
			t.Fatalf("%s: %v", res.Ecosystem, res.Err)
		}
		if res.Unchanged {
			t.Errorf("%s: the first refresh reports unchanged", res.Ecosystem)
		}
		if res.WroteShards == 0 {
			t.Errorf("%s: the first refresh wrote no shard", res.Ecosystem)
		}
		if res.Meta.Advisories != 3 || res.Meta.Packages != 3 || res.Meta.Withdrawn != 1 {
			t.Errorf("%s: meta = %+v", res.Ecosystem, res.Meta)
		}
		if res.Meta.ETag != fixtureETag || res.Meta.ArchiveSHA256 == "" || res.Meta.ArchiveBytes == 0 {
			t.Errorf("%s: validators = %+v", res.Ecosystem, res.Meta)
		}
		if res.Meta.SourceURL != srv.URL+"/"+OSVEcosystem(res.Ecosystem)+"/"+ArchiveName {
			t.Errorf("%s: SourceURL = %q", res.Ecosystem, res.Meta.SourceURL)
		}
	}

	// The identifying User-Agent goes out with every request, as it does through
	// internal/httpcache.
	srv.mu.Lock()
	agents := append([]string(nil), srv.agents...)
	srv.mu.Unlock()
	for _, agent := range agents {
		if !strings.HasPrefix(agent, "trustdiff-test/0") {
			t.Fatalf("User-Agent = %q", agent)
		}
	}

	// The archive itself is not kept: only the index is.
	for _, eco := range Indexable() {
		left, err := filepath.Glob(filepath.Join(ecosystemDir(dir, eco), archiveTempName+"*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(left) != 0 {
			t.Errorf("%s: the downloaded archive was left behind: %v", eco, left)
		}
	}

	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Lookup(model.NPM, "lodash", "4.17.20")
	if err != nil || len(got) != 1 || got[0].ID != "GHSA-35jh-r3h4-6jhm" {
		t.Fatalf("Lookup after a refresh = %v, %v", got, err)
	}
}

// TestRefreshIsConditional is the no-churn promise: a second refresh replays the
// stored ETag, the server answers 304, nothing is transferred and the index on
// disk is kept.
func TestRefreshIsConditional(t *testing.T) {
	srv := newArchiveServer(t)
	dir := t.TempDir()

	if _, err := Refresh(context.Background(), dir, []model.Ecosystem{model.NPM}, testOptions(srv.URL)); err != nil {
		t.Fatal(err)
	}
	_, bodies := srv.counts()
	if bodies != 1 {
		t.Fatalf("%d bodies after the first refresh, want 1", bodies)
	}
	shardsBefore := shardFingerprint(t, dir, model.NPM)

	opts := testOptions(srv.URL)
	opts.Now = func() time.Time { return time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC) }
	results, err := Refresh(context.Background(), dir, []model.Ecosystem{model.NPM}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Err != nil || !results[0].Unchanged {
		t.Fatalf("second refresh = %+v", results[0])
	}
	requests, bodies := srv.counts()
	if requests != 2 || bodies != 1 {
		t.Fatalf("%d requests and %d bodies, want 2 and 1", requests, bodies)
	}
	if results[0].WroteShards != 0 || results[0].RemovedShards != 0 {
		t.Errorf("an unchanged archive rewrote the index: %+v", results[0])
	}
	if got := shardFingerprint(t, dir, model.NPM); got != shardsBefore {
		t.Error("the shard files changed after a 304")
	}
	// The confirmation time moves forward, because that is what the age in
	// "cache status" measures: when the copy was last known to be current.
	if !results[0].Meta.DownloadedAt.Equal(opts.Now()) {
		t.Errorf("DownloadedAt = %v, want %v", results[0].Meta.DownloadedAt, opts.Now())
	}
	if results[0].Meta.Advisories != 3 {
		t.Errorf("the metadata lost its counts: %+v", results[0].Meta)
	}
}

// TestRefreshRewritesNothingWhenTheArchiveRepeats covers the second half of the
// no-churn promise, for a server that ignores conditional requests: the archive
// is downloaded again, and because the build is deterministic no shard file is
// written.
func TestRefreshRewritesNothingWhenTheArchiveRepeats(t *testing.T) {
	body := zipFixtureBytes(t, model.NPM)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	dir := t.TempDir()

	first, err := Refresh(context.Background(), dir, []model.Ecosystem{model.NPM}, testOptions(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Err != nil || first[0].WroteShards == 0 {
		t.Fatalf("first refresh = %+v", first[0])
	}
	second, err := Refresh(context.Background(), dir, []model.Ecosystem{model.NPM}, testOptions(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if second[0].Err != nil {
		t.Fatal(second[0].Err)
	}
	if second[0].Unchanged {
		t.Error("the server sent the archive again, so the refresh is not unchanged")
	}
	if second[0].WroteShards != 0 || second[0].RemovedShards != 0 {
		t.Errorf("the same archive rewrote %d shards and removed %d, want none of either",
			second[0].WroteShards, second[0].RemovedShards)
	}
}

// TestRefreshRebuildsWhenTheShardsAreGone checks that a metadata file whose
// shards someone deleted does not leave the ecosystem permanently empty by
// revalidating into a 304.
func TestRefreshRebuildsWhenTheShardsAreGone(t *testing.T) {
	srv := newArchiveServer(t)
	dir := t.TempDir()
	if _, err := Refresh(context.Background(), dir, []model.Ecosystem{model.NPM}, testOptions(srv.URL)); err != nil {
		t.Fatal(err)
	}
	shards, err := filepath.Glob(filepath.Join(ecosystemDir(dir, model.NPM), "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range shards {
		if filepath.Base(path) == metaName {
			continue
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	results, err := Refresh(context.Background(), dir, []model.Ecosystem{model.NPM}, testOptions(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Err != nil || results[0].Unchanged || results[0].WroteShards == 0 {
		t.Fatalf("result = %+v", results[0])
	}
	if _, bodies := srv.counts(); bodies != 2 {
		t.Errorf("%d bodies, want 2: the archive should have been downloaded again", bodies)
	}
}

// TestRefreshRefusesALargeArchive covers both halves of the size cap: the
// Content-Length that is refused before the body is read, and the body that
// turns out to be larger than the header said.
func TestRefreshRefusesALargeArchive(t *testing.T) {
	t.Run("content-length", func(t *testing.T) {
		var served int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "5000000")
			w.WriteHeader(http.StatusOK)
			served++
			_, _ = w.Write(make([]byte, 5000000))
		}))
		defer srv.Close()
		dir := t.TempDir()
		opts := testOptions(srv.URL)
		opts.Limits = Limits{MaxArchiveBytes: 1000}
		results, err := Refresh(context.Background(), dir, []model.Ecosystem{model.NPM}, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(results[0].Err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", results[0].Err)
		}
		if !strings.Contains(results[0].Err.Error(), srv.URL) {
			t.Errorf("error %q does not name the URL", results[0].Err)
		}
		left, _ := filepath.Glob(filepath.Join(ecosystemDir(dir, model.NPM), archiveTempName+"*"))
		if len(left) != 0 {
			t.Errorf("a refused archive was written to disk: %v", left)
		}
	})

	t.Run("no content-length", func(t *testing.T) {
		// A chunked response has no Content-Length, so only the limited reader
		// around the body can stop it.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Transfer-Encoding", "chunked")
			for range 20 {
				if _, err := w.Write(make([]byte, 4096)); err != nil {
					return
				}
			}
		}))
		defer srv.Close()
		dir := t.TempDir()
		opts := testOptions(srv.URL)
		opts.Limits = Limits{MaxArchiveBytes: 1000}
		results, err := Refresh(context.Background(), dir, []model.Ecosystem{model.NPM}, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(results[0].Err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", results[0].Err)
		}
		left, _ := filepath.Glob(filepath.Join(ecosystemDir(dir, model.NPM), archiveTempName+"*"))
		if len(left) != 0 {
			t.Errorf("a refused archive was left on disk: %v", left)
		}
	})
}

// TestRefreshKeepsTheEcosystemsThatWorked checks that one archive that will not
// download does not lose the two that did.
func TestRefreshKeepsTheEcosystemsThatWorked(t *testing.T) {
	archives := map[string][]byte{}
	for _, eco := range Indexable() {
		archives["/"+OSVEcosystem(eco)+"/"+ArchiveName] = zipFixtureBytes(t, eco)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/PyPI/") {
			http.Error(w, "the bucket is having a moment", http.StatusServiceUnavailable)
			return
		}
		body, ok := archives[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	dir := t.TempDir()

	results, err := Refresh(context.Background(), dir, Indexable(), testOptions(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	for i := range results {
		res := &results[i]
		if res.Ecosystem == model.PyPI {
			if res.Err == nil {
				t.Fatal("PyPI should have failed")
			}
			if !strings.Contains(res.Err.Error(), "503") || !strings.Contains(res.Err.Error(), srv.URL) {
				t.Errorf("PyPI error %q should name the status and the URL", res.Err)
			}
			continue
		}
		if res.Err != nil {
			t.Errorf("%s: %v", res.Ecosystem, res.Err)
		}
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Ecosystems(); len(got) != 2 {
		t.Fatalf("Ecosystems() = %v, want npm and cargo", got)
	}
}

func TestRefreshArgumentChecks(t *testing.T) {
	dir := t.TempDir()
	if _, err := Refresh(context.Background(), dir, Indexable(), Options{}); err == nil {
		t.Error("want an error without a User-Agent")
	}
	if _, err := Refresh(context.Background(), dir, nil, testOptions("http://example.invalid")); err == nil {
		t.Error("want an error without an ecosystem")
	}
	_, err := Refresh(context.Background(), dir, []model.Ecosystem{model.Deno}, testOptions("http://example.invalid"))
	if err == nil || !strings.Contains(err.Error(), "deno") {
		t.Errorf("err = %v, want one naming deno", err)
	}
}

func TestRefreshStopsWhenTheContextEnds(t *testing.T) {
	srv := newArchiveServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := Refresh(ctx, t.TempDir(), Indexable(), testOptions(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("results = %+v, want one failure", results)
	}
}

// shardFingerprint renders the names, sizes and modification times of one
// ecosystem's shard files, so a test can tell whether any of them was rewritten.
func shardFingerprint(t *testing.T, dir string, eco model.Ecosystem) string {
	t.Helper()
	entries, err := os.ReadDir(ecosystemDir(dir, eco))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !shardFileName.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %d %d\n", e.Name(), info.Size(), info.ModTime().UnixNano())
	}
	return b.String()
}
