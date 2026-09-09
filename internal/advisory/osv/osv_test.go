package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/osvindex"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Ids the recorded querybatch lists per query, in the order OSV returned them.
var (
	flatmapStreamIDs = []string{"GHSA-9x64-5r7x-2q53", "GHSA-mh6f-8j2x-4483", "MAL-2025-20690"}
	expressIDs       = []string{"GHSA-qw6h-vgh9-j6wx", "GHSA-rv95-896h-c2vc"}
	requestsIDs      = []string{"GHSA-9hjg-9r4m-mvj7", "GHSA-9wx4-h78v-vm56", "GHSA-gc5v-m9x4-r6x2", "PYSEC-2026-1872", "PYSEC-2026-1873", "PYSEC-2026-2275"}
)

// fixtureServer serves the recorded fixtures: the recorded querybatch answer
// for the recorded request body, vuln-<id>.json for every recorded id and the
// recorded 404 body for any other id. A test installs batch to answer bodies
// the recording does not cover, and fail to make one endpoint return a status.
type fixtureServer struct {
	*httptest.Server
	request  []byte
	response []byte
	details  map[string][]byte
	notFound []byte

	mu       sync.Mutex
	rawPosts [][]byte
	posts    []batchRequest
	gets     []string
	batch    func(req batchRequest) batchResponse
	failPath string
	failCode int
}

func newFixtureServer(t *testing.T) *fixtureServer {
	t.Helper()
	fs := &fixtureServer{
		request:  fixture(t, "querybatch-request.json"),
		response: fixture(t, "querybatch.json"),
		details:  map[string][]byte{},
		notFound: fixture(t, "vuln-not-found.json"),
	}
	files, err := filepath.Glob(filepath.Join("testdata", "vuln-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := filepath.Base(file)
		if name == "vuln-not-found.json" {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "vuln-"), ".json")
		fs.details[id] = fixture(t, name)
	}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A details request is counted whether or not it is made to fail, so
		// a test can see how many an outage costs.
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.EscapedPath(), "/vulns/") {
			fs.mu.Lock()
			fs.gets = append(fs.gets, strings.TrimPrefix(r.URL.EscapedPath(), "/vulns/"))
			fs.mu.Unlock()
		}
		fs.mu.Lock()
		failPath, failCode := fs.failPath, fs.failCode
		fs.mu.Unlock()
		if failCode != 0 && strings.HasPrefix(r.URL.EscapedPath(), failPath) {
			w.WriteHeader(failCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/querybatch":
			fs.serveBatch(t, w, r)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.EscapedPath(), "/vulns/"):
			id := strings.TrimPrefix(r.URL.EscapedPath(), "/vulns/")
			if body, ok := fs.details[id]; ok {
				_, _ = w.Write(body)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(fs.notFound)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fs.Close)
	return fs
}

func (fs *fixtureServer) serveBatch(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("querybatch Content-Type = %q, want application/json", ct)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("reading querybatch body: %v", err)
	}
	var req batchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Errorf("querybatch body %s does not decode: %v", body, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fs.mu.Lock()
	fs.rawPosts = append(fs.rawPosts, body)
	fs.posts = append(fs.posts, req)
	batch := fs.batch
	fs.mu.Unlock()

	if bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(fs.request)) {
		_, _ = w.Write(fs.response)
		return
	}
	answer := batchResponse{Results: make([]batchResult, len(req.Queries))}
	if batch != nil {
		answer = batch(req)
	}
	if err := json.NewEncoder(w).Encode(answer); err != nil {
		t.Errorf("encoding querybatch answer: %v", err)
	}
}

// answer installs the handler for querybatch bodies the recording does not cover.
func (fs *fixtureServer) answer(batch func(req batchRequest) batchResponse) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.batch = batch
}

// fail makes every request whose path starts with prefix return code.
func (fs *fixtureServer) fail(prefix string, code int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.failPath, fs.failCode = prefix, code
}

func (fs *fixtureServer) postCount() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return len(fs.posts)
}

func (fs *fixtureServer) post(i int) batchRequest {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.posts[i]
}

func (fs *fixtureServer) rawPost(i int) []byte {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]byte(nil), fs.rawPosts[i]...)
}

func (fs *fixtureServer) getIDs() []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]string(nil), fs.gets...)
}

// getCount counts the details requests for one id.
func (fs *fixtureServer) getCount(id string) int {
	n := 0
	for _, g := range fs.getIDs() {
		if g == id {
			n++
		}
	}
	return n
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return data
}

// newClient builds a client against the fixture server. dir is the httpcache
// directory, shared between clients when a test wants to observe the cache.
// Retries are off so a failing endpoint does not slow the test down.
func newClient(t *testing.T, fs *fixtureServer, dir string, offline bool) *Client {
	t.Helper()
	return newClientAt(t, fs, dir, offline, nil)
}

// newClientAt is newClient with a clock for the cache TTLs; nil means the wall
// clock.
func newClientAt(t *testing.T, fs *fixtureServer, dir string, offline bool, now func() time.Time) *Client {
	t.Helper()
	u, err := url.Parse(fs.URL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpcache.New(httpcache.Options{
		Dir:       dir,
		Offline:   offline,
		UserAgent: "trustdiff-test",
		Retries:   -1,
		HostRPS:   map[string]float64{u.Host: 1000},
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(h, WithBaseURL(fs.URL+"/"), WithLogger(slog.New(slog.DiscardHandler)))
}

func refs(t *testing.T, specs ...string) []model.PackageRef {
	t.Helper()
	out := make([]model.PackageRef, 0, len(specs))
	for _, s := range specs {
		r, err := model.ParseRef(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func ts(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ids lists the advisory ids of a result in order.
func ids(list []advisory.Advisory) []string {
	out := make([]string, 0, len(list))
	for i := range list {
		out = append(out, list[i].ID)
	}
	return out
}

// assertAdvisory compares two advisories field by field, times by instant.
func assertAdvisory(t *testing.T, got, want *advisory.Advisory) {
	t.Helper()
	if !got.Published.Equal(want.Published) || !got.Modified.Equal(want.Modified) {
		t.Errorf("%s: times = %v / %v, want %v / %v", want.ID, got.Published, got.Modified, want.Published, want.Modified)
	}
	g, w := *got, *want
	g.Published, g.Modified, w.Published, w.Modified = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("%s:\n got %+v\nwant %+v", want.ID, g, w)
	}
}

// find returns the advisory with id from a result.
func find(t *testing.T, list []advisory.Advisory, id string) *advisory.Advisory {
	t.Helper()
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	t.Fatalf("advisory %s not in %v", id, ids(list))
	return nil
}

// vulnsOf builds a batch result listing ids, with a modified stamp each.
func vulnsOf(ids ...string) batchResult {
	res := batchResult{}
	for _, id := range ids {
		res.Vulns = append(res.Vulns, batchVuln{ID: id, Modified: "2026-09-09T00:00:00Z"})
	}
	return res
}

func TestAdvisoriesRecorded(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	in := refs(t, "npm:flatmap-stream@0.1.1", "npm:express@4.17.1", "pypi:requests@2.31.0")

	got, err := c.Advisories(context.Background(), in)
	if err != nil {
		t.Fatalf("Advisories: %v", err)
	}
	if fs.postCount() != 1 {
		t.Fatalf("querybatch posts = %d, want 1", fs.postCount())
	}
	if body := fs.rawPost(0); !bytes.Equal(body, bytes.TrimSpace(fixture(t, "querybatch-request.json"))) {
		t.Errorf("querybatch body = %s, want the recorded request", body)
	}
	if len(got) != 3 {
		t.Fatalf("Advisories returned %d refs, want 3: %v", len(got), got)
	}
	for i, want := range [][]string{flatmapStreamIDs, expressIDs, requestsIDs} {
		if gotIDs := ids(got[in[i]]); !reflect.DeepEqual(gotIDs, want) {
			t.Errorf("%s: ids = %v, want %v", in[i], gotIDs, want)
		}
	}

	// One details request per distinct id, in sorted order, none twice.
	wantGets := make([]string, 0, len(flatmapStreamIDs)+len(expressIDs)+len(requestsIDs))
	wantGets = append(wantGets, flatmapStreamIDs...)
	wantGets = append(wantGets, expressIDs...)
	wantGets = append(wantGets, requestsIDs...)
	gotGets := fs.getIDs()
	if len(gotGets) != len(wantGets) {
		t.Errorf("details requests = %v, want one per id: %v", gotGets, wantGets)
	}
	for _, id := range wantGets {
		if n := fs.getCount(id); n != 1 {
			t.Errorf("details for %s requested %d times, want 1", id, n)
		}
	}

	flatmap := got[in[0]]
	assertAdvisory(t, find(t, flatmap, "MAL-2025-20690"), &advisory.Advisory{
		ID:        "MAL-2025-20690",
		Summary:   "Malicious code in flatmap-stream (npm)",
		Severity:  advisory.SeverityUnknown,
		Malicious: true,
		Published: ts(t, "2025-08-14T18:52:04Z"),
		Modified:  ts(t, "2025-08-14T18:52:04Z"),
		URL:       "https://osv.dev/vulnerability/MAL-2025-20690",
	})
	// A GHSA record about the same malicious package is not MAL- and keeps its label and score.
	assertAdvisory(t, find(t, flatmap, "GHSA-9x64-5r7x-2q53"), &advisory.Advisory{
		ID:             "GHSA-9x64-5r7x-2q53",
		Summary:        "Malicious Package in flatmap-stream",
		Severity:       advisory.SeverityCritical,
		Score:          9.8,
		SeveritySource: advisory.SeveritySourceLabel,
		Published:      ts(t, "2020-09-01T21:21:32Z"),
		Modified:       ts(t, "2021-10-01T13:30:04Z"),
		URL:            "https://osv.dev/vulnerability/GHSA-9x64-5r7x-2q53",
	})

	express := got[in[1]]
	assertAdvisory(t, find(t, express, "GHSA-rv95-896h-c2vc"), &advisory.Advisory{
		ID:             "GHSA-rv95-896h-c2vc",
		Aliases:        []string{"CVE-2024-29041"},
		Summary:        "Express.js Open Redirect in malformed URLs",
		Severity:       advisory.SeverityMedium, // database_specific.severity MODERATE
		Score:          6.1,                     // CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
		SeveritySource: advisory.SeveritySourceLabel,
		Published:      ts(t, "2024-03-25T19:40:26Z"),
		Modified:       ts(t, "2026-02-04T02:13:10.821360Z"),
		URL:            "https://osv.dev/vulnerability/GHSA-rv95-896h-c2vc",
	})
	// The label decides the bucket and the v3 vector the score even when a v4
	// vector is present too, and the source says the label won.
	if a := find(t, express, "GHSA-qw6h-vgh9-j6wx"); a.Severity != advisory.SeverityLow || a.Score != 5.0 || a.SeveritySource != advisory.SeveritySourceLabel {
		t.Errorf("GHSA-qw6h-vgh9-j6wx: severity %s score %v source %q, want low 5.0 from the label", a.Severity, a.Score, a.SeveritySource)
	}

	requests := got[in[2]]
	// PYSEC records carry no label: the score comes from the vector and the
	// summary, when missing, from the first line of the details, bounded.
	if a := find(t, requests, "PYSEC-2026-2275"); a.Severity != advisory.SeverityMedium || a.Score != 5.5 || a.SeveritySource != advisory.SeveritySourceCVSS3 ||
		!strings.HasPrefix(a.Summary, "Requests is a HTTP library.") || utf8.RuneCountInString(a.Summary) != summaryMaxRunes {
		t.Errorf("PYSEC-2026-2275: severity %s score %v source %q summary %q (%d runes)", a.Severity, a.Score, a.SeveritySource, a.Summary, utf8.RuneCountInString(a.Summary))
	}
	if a := find(t, requests, "PYSEC-2026-1872"); a.Severity != advisory.SeverityMedium || a.Score != 5.3 ||
		!reflect.DeepEqual(a.Aliases, []string{"CVE-2024-47081", "GHSA-9hjg-9r4m-mvj7"}) {
		t.Errorf("PYSEC-2026-1872: severity %s score %v aliases %v", a.Severity, a.Score, a.Aliases)
	}
	if a := find(t, requests, "GHSA-9hjg-9r4m-mvj7"); a.Severity != advisory.SeverityMedium || a.Score != 5.3 {
		t.Errorf("GHSA-9hjg-9r4m-mvj7: severity %s score %v, want medium 5.3", a.Severity, a.Score)
	}
	for _, list := range got {
		for i := range list {
			a := &list[i]
			if a.Malicious != strings.HasPrefix(a.ID, MaliciousPrefix) {
				t.Errorf("%s: Malicious = %v", a.ID, a.Malicious)
			}
			if a.URL != advisoryPageURL+a.ID {
				t.Errorf("%s: URL = %q", a.ID, a.URL)
			}
		}
	}
}

// TestToAdvisory walks every severity path over recorded and hand-written records.
func TestToAdvisory(t *testing.T) {
	t.Parallel()
	c := New(nil, WithLogger(slog.New(slog.DiscardHandler)))
	tests := []struct {
		name    string
		id      string
		fixture string
		record  string
		want    advisory.Advisory
	}{
		{
			name: "MAL record has no severity and is malicious by id", id: "MAL-2025-20690", fixture: "vuln-MAL-2025-20690.json",
			want: advisory.Advisory{
				ID: "MAL-2025-20690", Summary: "Malicious code in flatmap-stream (npm)", Severity: advisory.SeverityUnknown, Malicious: true,
				Published: ts(t, "2025-08-14T18:52:04Z"), Modified: ts(t, "2025-08-14T18:52:04Z"), URL: advisoryPageURL + "MAL-2025-20690",
			},
		},
		{
			name: "GHSA label with a v3.1 vector", id: "GHSA-rv95-896h-c2vc", fixture: "vuln-GHSA-rv95-896h-c2vc.json",
			want: advisory.Advisory{
				ID: "GHSA-rv95-896h-c2vc", Aliases: []string{"CVE-2024-29041"}, Summary: "Express.js Open Redirect in malformed URLs",
				Severity: advisory.SeverityMedium, Score: 6.1, SeveritySource: advisory.SeveritySourceLabel,
				Published: ts(t, "2024-03-25T19:40:26Z"), Modified: ts(t, "2026-02-04T02:13:10.821360Z"), URL: advisoryPageURL + "GHSA-rv95-896h-c2vc",
			},
		},
		{
			name: "GHSA label with only a CVSS_V4 entry keeps the label and no score", id: "GHSA-fjxv-7rqg-78g4", fixture: "vuln-GHSA-fjxv-7rqg-78g4.json",
			want: advisory.Advisory{
				ID: "GHSA-fjxv-7rqg-78g4", Aliases: []string{"CVE-2025-7783"}, Summary: "form-data uses unsafe random function in form-data for choosing boundary",
				Severity: advisory.SeverityCritical, Score: 0, SeveritySource: advisory.SeveritySourceLabel,
				Published: ts(t, "2025-07-21T19:04:54Z"), Modified: ts(t, "2026-07-16T03:59:27.270440328Z"), URL: advisoryPageURL + "GHSA-fjxv-7rqg-78g4",
			},
		},
		{
			name: "RUSTSEC record without severity is unknown", id: "RUSTSEC-2021-0145", fixture: "vuln-RUSTSEC-2021-0145.json",
			want: advisory.Advisory{
				ID: "RUSTSEC-2021-0145", Aliases: []string{"GHSA-g98v-hv3f-hcfr"}, Summary: "Potential unaligned read",
				Severity:  advisory.SeverityUnknown,
				Published: ts(t, "2021-07-04T12:00:00Z"), Modified: ts(t, "2023-11-08T04:19:25.814075Z"), URL: advisoryPageURL + "RUSTSEC-2021-0145",
			},
		},
		{
			name: "PYSEC record without label is scored from its vector", id: "PYSEC-2026-1873", fixture: "vuln-PYSEC-2026-1873.json",
			want: advisory.Advisory{
				ID: "PYSEC-2026-1873", Aliases: []string{"CVE-2024-35195", "GHSA-9wx4-h78v-vm56"},
				Summary:  "Requests `Session` object does not verify requests after making first request with verify=False",
				Severity: advisory.SeverityMedium, Score: 5.6, SeveritySource: advisory.SeveritySourceCVSS3, // CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N
				Published: ts(t, "2026-07-07T11:45:42.890131Z"), Modified: ts(t, "2026-07-07T17:46:36.762141019Z"), URL: advisoryPageURL + "PYSEC-2026-1873",
			},
		},
		{
			name: "only a CVSS_V4 entry and no label is unknown", id: "TEST-1",
			record: `{"id":"TEST-1","summary":"v4 only","severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"}]}`,
			want:   advisory.Advisory{ID: "TEST-1", Summary: "v4 only", Severity: advisory.SeverityUnknown, URL: advisoryPageURL + "TEST-1"},
		},
		{
			name: "a v3.0 vector is scored like a v3.1 one", id: "TEST-2",
			record: `{"id":"TEST-2","severity":[{"type":"CVSS_V3","score":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`,
			want:   advisory.Advisory{ID: "TEST-2", Severity: advisory.SeverityCritical, Score: 9.8, SeveritySource: advisory.SeveritySourceCVSS3, URL: advisoryPageURL + "TEST-2"},
		},
		{
			name: "a v3 vector after a v2 one", id: "TEST-3",
			record: `{"id":"TEST-3","severity":[{"type":"CVSS_V2","score":"AV:N/AC:L/Au:N/C:P/I:P/A:P"},{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}`,
			want:   advisory.Advisory{ID: "TEST-3", Severity: advisory.SeverityHigh, Score: 7.5, SeveritySource: advisory.SeveritySourceCVSS3, URL: advisoryPageURL + "TEST-3"},
		},
		{
			name: "only a v2 vector is unknown", id: "TEST-4",
			record: `{"id":"TEST-4","severity":[{"type":"CVSS_V2","score":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}]}`,
			want:   advisory.Advisory{ID: "TEST-4", Severity: advisory.SeverityUnknown, URL: advisoryPageURL + "TEST-4"},
		},
		{
			name: "an unrecognized label falls back to the vector", id: "TEST-5",
			record: `{"id":"TEST-5","database_specific":{"severity":"IMPORTANT"},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"}]}`,
			want:   advisory.Advisory{ID: "TEST-5", Severity: advisory.SeverityLow, Score: 3.1, SeveritySource: advisory.SeveritySourceCVSS3, URL: advisoryPageURL + "TEST-5"},
		},
		{
			name: "a label that is not a string is ignored", id: "TEST-6",
			record: `{"id":"TEST-6","database_specific":{"severity":{"level":"HIGH"}},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`,
			want:   advisory.Advisory{ID: "TEST-6", Severity: advisory.SeverityCritical, Score: 9.8, SeveritySource: advisory.SeveritySourceCVSS3, URL: advisoryPageURL + "TEST-6"},
		},
		{
			name: "a malformed vector is skipped for a usable one", id: "TEST-7",
			record: `{"id":"TEST-7","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/bogus"},{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}`,
			want:   advisory.Advisory{ID: "TEST-7", Severity: advisory.SeverityHigh, Score: 7.5, SeveritySource: advisory.SeveritySourceCVSS3, URL: advisoryPageURL + "TEST-7"},
		},
		{
			name: "only a malformed vector is unknown", id: "TEST-8",
			record: `{"id":"TEST-8","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]}`,
			want:   advisory.Advisory{ID: "TEST-8", Severity: advisory.SeverityUnknown, URL: advisoryPageURL + "TEST-8"},
		},
		{
			name: "a label with a malformed vector keeps the label", id: "TEST-9",
			record: `{"id":"TEST-9","database_specific":{"severity":"HIGH"},"severity":[{"type":"CVSS_V3","score":"nope"}]}`,
			want:   advisory.Advisory{ID: "TEST-9", Severity: advisory.SeverityHigh, SeveritySource: advisory.SeveritySourceLabel, URL: advisoryPageURL + "TEST-9"},
		},
		{
			name: "GHSA spellings of the label", id: "TEST-10",
			record: `{"id":"TEST-10","database_specific":{"severity":" moderate "}}`,
			want:   advisory.Advisory{ID: "TEST-10", Severity: advisory.SeverityMedium, SeveritySource: advisory.SeveritySourceLabel, URL: advisoryPageURL + "TEST-10"},
		},
		{
			name: "a MAL id is malicious even with a label", id: "MAL-2099-1",
			record: `{"id":"MAL-2099-1","database_specific":{"severity":"CRITICAL"}}`,
			want:   advisory.Advisory{ID: "MAL-2099-1", Severity: advisory.SeverityCritical, SeveritySource: advisory.SeveritySourceLabel, Malicious: true, URL: advisoryPageURL + "MAL-2099-1"},
		},
		{
			// FIRST rates a base score of 0.0 as None: a published rating, not a
			// missing one, so it must not count as medium.
			name: "a vector without impact scores None", id: "TEST-14",
			record: `{"id":"TEST-14","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}]}`,
			want:   advisory.Advisory{ID: "TEST-14", Severity: advisory.SeverityNone, Score: 0, SeveritySource: advisory.SeveritySourceCVSS3, URL: advisoryPageURL + "TEST-14"},
		},
		{
			name: "a label wins over a vector without impact", id: "TEST-15",
			record: `{"id":"TEST-15","database_specific":{"severity":"LOW"},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}]}`,
			want:   advisory.Advisory{ID: "TEST-15", Severity: advisory.SeverityLow, Score: 0, SeveritySource: advisory.SeveritySourceLabel, URL: advisoryPageURL + "TEST-15"},
		},
		{
			name: "summary falls back to the first non-empty line of details", id: "TEST-11",
			record: `{"id":"TEST-11","details":"\n  \nFirst line here.\nSecond line."}`,
			want:   advisory.Advisory{ID: "TEST-11", Summary: "First line here.", Severity: advisory.SeverityUnknown, URL: advisoryPageURL + "TEST-11"},
		},
		{
			name: "a long details line is cut to the summary bound", id: "TEST-12",
			record: `{"id":"TEST-12","details":"` + strings.Repeat("ü", summaryMaxRunes+50) + `"}`,
			want:   advisory.Advisory{ID: "TEST-12", Summary: strings.Repeat("ü", summaryMaxRunes), Severity: advisory.SeverityUnknown, URL: advisoryPageURL + "TEST-12"},
		},
		{
			name: "unparsable timestamps are left zero", id: "TEST-13",
			record: `{"id":"TEST-13","published":"yesterday","modified":"2026-13-45T00:00:00Z"}`,
			want:   advisory.Advisory{ID: "TEST-13", Severity: advisory.SeverityUnknown, URL: advisoryPageURL + "TEST-13"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := []byte(tt.record)
			if tt.fixture != "" {
				data = fixture(t, tt.fixture)
			}
			var rec vulnRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatalf("decoding record: %v", err)
			}
			got := c.toAdvisory(tt.id, &rec)
			assertAdvisory(t, &got, &tt.want)
		})
	}
}

func TestAdvisoriesChunking(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	// Every query is answered with the same advisory, so the 1001 refs share
	// one details request however many chunks they were split into.
	fs.answer(func(req batchRequest) batchResponse {
		res := batchResponse{Results: make([]batchResult, len(req.Queries))}
		for i := range res.Results {
			res.Results[i] = vulnsOf("GHSA-rv95-896h-c2vc")
		}
		return res
	})
	c := newClient(t, fs, t.TempDir(), false)
	in := make([]model.PackageRef, 0, MaxQueriesPerBatch+1)
	for i := range MaxQueriesPerBatch + 1 {
		in = append(in, model.PackageRef{Ecosystem: model.NPM, Name: fmt.Sprintf("pkg-%04d", i), Version: "1.0.0"})
	}

	got, err := c.Advisories(context.Background(), in)
	if err != nil {
		t.Fatalf("Advisories: %v", err)
	}
	if fs.postCount() != 2 {
		t.Fatalf("querybatch posts = %d, want 2", fs.postCount())
	}
	if n := len(fs.post(0).Queries); n != MaxQueriesPerBatch {
		t.Errorf("first post carries %d queries, want %d", n, MaxQueriesPerBatch)
	}
	if n := len(fs.post(1).Queries); n != 1 {
		t.Errorf("second post carries %d queries, want 1", n)
	}
	if q := fs.post(1).Queries[0]; q.Package.Name != "pkg-1000" || q.Package.Ecosystem != "npm" || q.Version != "1.0.0" {
		t.Errorf("second post query = %+v, want pkg-1000", q)
	}
	if len(got) != len(in) {
		t.Fatalf("Advisories returned %d refs, want %d", len(got), len(in))
	}
	for _, ref := range in {
		if gotIDs := ids(got[ref]); !reflect.DeepEqual(gotIDs, []string{"GHSA-rv95-896h-c2vc"}) {
			t.Fatalf("%s: ids = %v", ref, gotIDs)
		}
	}
	if gets := fs.getIDs(); !reflect.DeepEqual(gets, []string{"GHSA-rv95-896h-c2vc"}) {
		t.Errorf("details requests = %v, want exactly one", gets)
	}
}

func TestAdvisoriesDedupsRefs(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	in := refs(t, "npm:flatmap-stream@0.1.1", "npm:flatmap-stream@0.1.1", "npm:express@4.17.1", "pypi:requests@2.31.0", "npm:express@4.17.1")

	got, err := c.Advisories(context.Background(), in)
	if err != nil {
		t.Fatalf("Advisories: %v", err)
	}
	if fs.postCount() != 1 || len(fs.post(0).Queries) != 3 {
		t.Fatalf("posts = %d with %d queries, want one post of 3 distinct queries", fs.postCount(), len(fs.post(0).Queries))
	}
	if len(got) != 3 {
		t.Errorf("Advisories returned %d refs, want 3", len(got))
	}
	if gotIDs := ids(got[in[0]]); !reflect.DeepEqual(gotIDs, flatmapStreamIDs) {
		t.Errorf("flatmap-stream ids = %v", gotIDs)
	}
}

func TestAdvisoriesAlignsResultsToRefs(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	fs.answer(func(req batchRequest) batchResponse {
		res := batchResponse{Results: make([]batchResult, len(req.Queries))}
		for i, q := range req.Queries {
			switch q.Package.Name {
			case "b":
				res.Results[i] = vulnsOf("GHSA-rv95-896h-c2vc")
			case "c":
				res.Results[i] = vulnsOf("PYSEC-2026-2275", "GHSA-rv95-896h-c2vc")
			}
		}
		return res
	})
	c := newClient(t, fs, t.TempDir(), false)
	in := refs(t, "npm:a@1.0.0", "pypi:b@2.0.0", "cargo:c@3.0.0")

	got, err := c.Advisories(context.Background(), in)
	if err != nil {
		t.Fatalf("Advisories: %v", err)
	}
	wantQueries := []batchQuery{
		{Package: batchPackage{Name: "a", Ecosystem: "npm"}, Version: "1.0.0"},
		{Package: batchPackage{Name: "b", Ecosystem: "PyPI"}, Version: "2.0.0"},
		{Package: batchPackage{Name: "c", Ecosystem: "crates.io"}, Version: "3.0.0"},
	}
	if !reflect.DeepEqual(fs.post(0).Queries, wantQueries) {
		t.Errorf("queries = %+v, want %+v", fs.post(0).Queries, wantQueries)
	}
	if _, ok := got[in[0]]; ok {
		t.Errorf("a has no advisories but is in the map: %v", got[in[0]])
	}
	if gotIDs := ids(got[in[1]]); !reflect.DeepEqual(gotIDs, []string{"GHSA-rv95-896h-c2vc"}) {
		t.Errorf("b ids = %v", gotIDs)
	}
	if gotIDs := ids(got[in[2]]); !reflect.DeepEqual(gotIDs, []string{"PYSEC-2026-2275", "GHSA-rv95-896h-c2vc"}) {
		t.Errorf("c ids = %v", gotIDs)
	}
	if gets := fs.getIDs(); !reflect.DeepEqual(gets, []string{"GHSA-rv95-896h-c2vc", "PYSEC-2026-2275"}) {
		t.Errorf("details requests = %v, want each id once in sorted order", gets)
	}
	// The advisories of two refs are independent copies.
	got[in[1]][0].Aliases[0] = "changed"
	if got[in[2]][1].Aliases[0] != "CVE-2024-29041" {
		t.Error("advisories of different refs share an aliases slice")
	}
}

func TestAdvisoriesResultCountMismatch(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	fs.answer(func(_ batchRequest) batchResponse {
		return batchResponse{Results: []batchResult{vulnsOf("GHSA-rv95-896h-c2vc")}}
	})
	c := newClient(t, fs, t.TempDir(), false)

	_, err := c.Advisories(context.Background(), refs(t, "npm:a@1.0.0", "npm:b@1.0.0"))
	if err == nil || !strings.Contains(err.Error(), "1 results") {
		t.Fatalf("Advisories error = %v, want a result count mismatch", err)
	}
	if len(fs.getIDs()) != 0 {
		t.Errorf("details were requested after a bad batch: %v", fs.getIDs())
	}
}

func TestAdvisoriesFollowsPageTokens(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	fs.answer(func(req batchRequest) batchResponse {
		if len(req.Queries) == 1 && req.Queries[0].PageToken == "page-2" {
			return batchResponse{Results: []batchResult{vulnsOf("PYSEC-2026-2275")}}
		}
		first := vulnsOf("GHSA-rv95-896h-c2vc")
		first.NextPageToken = "page-2"
		return batchResponse{Results: []batchResult{first, vulnsOf("GHSA-qw6h-vgh9-j6wx")}}
	})
	c := newClient(t, fs, t.TempDir(), false)
	in := refs(t, "npm:a@1.0.0", "npm:b@1.0.0")

	got, err := c.Advisories(context.Background(), in)
	if err != nil {
		t.Fatalf("Advisories: %v", err)
	}
	if fs.postCount() != 2 {
		t.Fatalf("posts = %d, want 2", fs.postCount())
	}
	want := []batchQuery{{Package: batchPackage{Name: "a", Ecosystem: "npm"}, Version: "1.0.0", PageToken: "page-2"}}
	if !reflect.DeepEqual(fs.post(1).Queries, want) {
		t.Errorf("second post queries = %+v, want %+v", fs.post(1).Queries, want)
	}
	if gotIDs := ids(got[in[0]]); !reflect.DeepEqual(gotIDs, []string{"GHSA-rv95-896h-c2vc", "PYSEC-2026-2275"}) {
		t.Errorf("a ids = %v", gotIDs)
	}
	if gotIDs := ids(got[in[1]]); !reflect.DeepEqual(gotIDs, []string{"GHSA-qw6h-vgh9-j6wx"}) {
		t.Errorf("b ids = %v", gotIDs)
	}
}

func TestAdvisoriesBoundsPages(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	// A fresh token per answer, so every follow-up has a new body and reaches
	// the server instead of the cache.
	var pages atomic.Int32
	fs.answer(func(req batchRequest) batchResponse {
		res := batchResponse{Results: make([]batchResult, len(req.Queries))}
		for i := range res.Results {
			res.Results[i].NextPageToken = fmt.Sprintf("page-%d", pages.Add(1))
		}
		return res
	})
	c := newClient(t, fs, t.TempDir(), false)

	_, err := c.Advisories(context.Background(), refs(t, "npm:a@1.0.0"))
	if err == nil || !strings.Contains(err.Error(), "pages") {
		t.Fatalf("Advisories error = %v, want the page bound", err)
	}
	if fs.postCount() != maxPages {
		t.Errorf("posts = %d, want %d", fs.postCount(), maxPages)
	}
}

func TestAdvisoriesUnsupportedEcosystems(t *testing.T) {
	t.Parallel()
	t.Run("every ref unsupported", func(t *testing.T) {
		t.Parallel()
		fs := newFixtureServer(t)
		c := newClient(t, fs, t.TempDir(), false)
		got, err := c.Advisories(context.Background(), refs(t, "deno:std@1.0.0", "jsr:@std/path@1.0.0", "deno:other@2.0.0"))
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("Advisories error = %v, want ErrUnsupported", err)
		}
		if !strings.Contains(err.Error(), "deno, jsr") {
			t.Errorf("error %q does not name the ecosystems", err)
		}
		if got != nil || fs.postCount() != 0 {
			t.Errorf("got %v after %d posts, want nothing", got, fs.postCount())
		}
	})
	t.Run("unsupported refs are left out", func(t *testing.T) {
		t.Parallel()
		fs := newFixtureServer(t)
		fs.answer(func(req batchRequest) batchResponse {
			res := batchResponse{Results: make([]batchResult, len(req.Queries))}
			res.Results[0] = vulnsOf("GHSA-rv95-896h-c2vc")
			return res
		})
		c := newClient(t, fs, t.TempDir(), false)
		in := refs(t, "deno:std@1.0.0", "npm:express@4.17.1", "jsr:@std/path@1.0.0")
		got, err := c.Advisories(context.Background(), in)
		if err != nil {
			t.Fatalf("Advisories: %v", err)
		}
		if fs.postCount() != 1 || len(fs.post(0).Queries) != 1 || fs.post(0).Queries[0].Package.Name != "express" {
			t.Errorf("posts = %d %+v, want one query for express", fs.postCount(), fs.post(0).Queries)
		}
		if len(got) != 1 || len(got[in[1]]) != 1 {
			t.Errorf("got %v, want only express", got)
		}
	})
}

func TestAdvisoriesOffline(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	dir := t.TempDir()
	in := refs(t, "npm:flatmap-stream@0.1.1", "npm:express@4.17.1", "pypi:requests@2.31.0")

	cold := newClient(t, fs, dir, true)
	got, err := cold.Advisories(context.Background(), in)
	if !errors.Is(err, httpcache.ErrOffline) {
		t.Fatalf("offline with a cold cache: error = %v, want ErrOffline", err)
	}
	if got != nil || fs.postCount() != 0 || len(fs.getIDs()) != 0 {
		t.Fatalf("offline client reached the network: %d posts, %d gets", fs.postCount(), len(fs.getIDs()))
	}

	online := newClient(t, fs, dir, false)
	want, err := online.Advisories(context.Background(), in)
	if err != nil {
		t.Fatalf("online: %v", err)
	}
	posts, gets := fs.postCount(), len(fs.getIDs())

	warm := newClient(t, fs, dir, true)
	got, err = warm.Advisories(context.Background(), in)
	if err != nil {
		t.Fatalf("offline with a warm cache: %v", err)
	}
	if !reflect.DeepEqual(ids(got[in[0]]), ids(want[in[0]])) || len(got) != len(want) {
		t.Errorf("offline answer differs from the online one: %v vs %v", got, want)
	}
	if fs.postCount() != posts || len(fs.getIDs()) != gets {
		t.Errorf("offline client reached the network: %d posts, %d gets (were %d, %d)", fs.postCount(), len(fs.getIDs()), posts, gets)
	}

	// Within the TTL a second online client is served from the cache as well.
	again := newClient(t, fs, dir, false)
	if _, err := again.Advisories(context.Background(), in); err != nil {
		t.Fatalf("second online run: %v", err)
	}
	if fs.postCount() != posts || len(fs.getIDs()) != gets {
		t.Errorf("second online run fetched again within the TTL: %d posts, %d gets", fs.postCount(), len(fs.getIDs()))
	}
}

// TestAdvisoriesDetailFallbacks covers a batch entry whose record cannot be
// used: a MAL- id is answered from the entry whatever went wrong, any other
// id the vulns endpoint does not know is dropped rather than reported with an
// unknown severity, and an entry without an id is skipped without a request.
func TestAdvisoriesDetailFallbacks(t *testing.T) {
	t.Parallel()
	const modified = "2026-09-09T10:00:00Z"
	fromEntry := func(id string) *advisory.Advisory {
		return &advisory.Advisory{ID: id, Severity: advisory.SeverityUnknown, Malicious: true, Modified: ts(t, modified), URL: advisoryPageURL + id}
	}
	tests := []struct {
		name     string
		vulns    []batchVuln
		failCode int
		want     []string
		wantGets []string
		wantAdv  *advisory.Advisory
	}{
		{
			name:     "MAL id not found",
			vulns:    []batchVuln{{ID: "MAL-2099-1", Modified: modified}},
			want:     []string{"MAL-2099-1"},
			wantGets: []string{"MAL-2099-1"},
			wantAdv:  fromEntry("MAL-2099-1"),
		},
		{
			name:     "MAL id details fail",
			vulns:    []batchVuln{{ID: "MAL-2099-1", Modified: modified}},
			failCode: http.StatusServiceUnavailable,
			want:     []string{"MAL-2099-1"},
			wantGets: []string{"MAL-2099-1"},
			wantAdv:  fromEntry("MAL-2099-1"),
		},
		{
			name:     "other id not found is dropped",
			vulns:    []batchVuln{{ID: "GHSA-gone-0000-0000", Modified: modified}, {ID: "GHSA-rv95-896h-c2vc", Modified: modified}},
			want:     []string{"GHSA-rv95-896h-c2vc"},
			wantGets: []string{"GHSA-gone-0000-0000", "GHSA-rv95-896h-c2vc"},
		},
		{
			name:     "only a not found id leaves the ref without advisories",
			vulns:    []batchVuln{{ID: "GHSA-gone-0000-0000", Modified: modified}},
			wantGets: []string{"GHSA-gone-0000-0000"},
		},
		{
			name:     "empty id is skipped",
			vulns:    []batchVuln{{ID: "", Modified: modified}, {ID: "GHSA-rv95-896h-c2vc", Modified: modified}},
			want:     []string{"GHSA-rv95-896h-c2vc"},
			wantGets: []string{"GHSA-rv95-896h-c2vc"},
		},
		{
			name:  "only an empty id",
			vulns: []batchVuln{{ID: "", Modified: modified}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fs := newFixtureServer(t)
			fs.answer(func(_ batchRequest) batchResponse {
				return batchResponse{Results: []batchResult{{Vulns: tt.vulns}}}
			})
			if tt.failCode != 0 {
				fs.fail("/vulns/", tt.failCode)
			}
			c := newClient(t, fs, t.TempDir(), false)
			in := refs(t, "npm:gone@1.0.0")

			got, err := c.Advisories(context.Background(), in)
			if err != nil {
				t.Fatalf("Advisories: %v", err)
			}
			list, present := got[in[0]]
			if present != (len(tt.want) > 0) || !slices.Equal(ids(list), tt.want) {
				t.Errorf("advisories = %v (present %v), want %v", ids(list), present, tt.want)
			}
			if tt.wantAdv != nil && len(list) > 0 {
				assertAdvisory(t, &list[0], tt.wantAdv)
			}
			if gets := fs.getIDs(); !slices.Equal(gets, tt.wantGets) {
				t.Errorf("details requests = %v, want %v", gets, tt.wantGets)
			}
		})
	}
}

// TestAdvisoriesPartialFailure shows a failing details request losing only
// the refs that list the id: the others are answered, and the error names the
// lost ref while still unwrapping to the cause.
func TestAdvisoriesPartialFailure(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	// GHSA-rv95-896h-c2vc is listed for express alone.
	fs.fail("/vulns/GHSA-rv95-896h-c2vc", http.StatusServiceUnavailable)
	c := newClient(t, fs, t.TempDir(), false)
	in := refs(t, "npm:flatmap-stream@0.1.1", "npm:express@4.17.1", "pypi:requests@2.31.0")

	got, err := c.Advisories(context.Background(), in)
	var pe *advisory.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("Advisories error = %v, want a *advisory.PartialError", err)
	}
	if len(pe.Refs) != 1 || pe.Refs[in[1]] == nil {
		t.Errorf("PartialError.Refs = %v, want express alone", pe.Refs)
	}
	var se *httpcache.StatusError
	if !errors.As(err, &se) || se.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("error %v does not unwrap to the 503", err)
	}
	if !strings.Contains(err.Error(), "npm:express@4.17.1") || !strings.HasPrefix(err.Error(), "osv: ") {
		t.Errorf("error %q does not name the lost ref with the package prefix", err)
	}
	if _, ok := got[in[1]]; ok {
		t.Errorf("express was answered although its advisory failed: %v", got[in[1]])
	}
	if gotIDs := ids(got[in[0]]); !reflect.DeepEqual(gotIDs, flatmapStreamIDs) {
		t.Errorf("flatmap-stream ids = %v, want %v", gotIDs, flatmapStreamIDs)
	}
	if gotIDs := ids(got[in[2]]); !reflect.DeepEqual(gotIDs, requestsIDs) {
		t.Errorf("requests ids = %v, want %v", gotIDs, requestsIDs)
	}
}

// TestAdvisoriesChunkFailureIsLocal shows a failing querybatch chunk losing
// only its own refs.
func TestAdvisoriesChunkFailureIsLocal(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	fs.answer(func(req batchRequest) batchResponse {
		if len(req.Queries) == 1 {
			// The second chunk: a malformed answer with no results.
			return batchResponse{}
		}
		res := batchResponse{Results: make([]batchResult, len(req.Queries))}
		for i := range res.Results {
			res.Results[i] = vulnsOf("GHSA-rv95-896h-c2vc")
		}
		return res
	})
	c := newClient(t, fs, t.TempDir(), false)
	in := make([]model.PackageRef, 0, MaxQueriesPerBatch+1)
	for i := range MaxQueriesPerBatch + 1 {
		in = append(in, model.PackageRef{Ecosystem: model.NPM, Name: fmt.Sprintf("pkg-%04d", i), Version: "1.0.0"})
	}

	got, err := c.Advisories(context.Background(), in)
	var pe *advisory.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("Advisories error = %v, want a *advisory.PartialError", err)
	}
	last := in[MaxQueriesPerBatch]
	if len(pe.Refs) != 1 || pe.Refs[last] == nil || !strings.Contains(pe.Refs[last].Error(), "0 results") {
		t.Errorf("PartialError.Refs = %v, want the last ref with the result count error", pe.Refs)
	}
	if len(got) != MaxQueriesPerBatch {
		t.Errorf("Advisories answered %d refs, want %d", len(got), MaxQueriesPerBatch)
	}
	if gotIDs := ids(got[in[0]]); !reflect.DeepEqual(gotIDs, []string{"GHSA-rv95-896h-c2vc"}) {
		t.Errorf("first ref ids = %v", gotIDs)
	}
}

// TestCacheTTLs pins the six-hour lifetime of querybatch and vulns answers
// (brief section 11) with a settable clock. The duration is spelled out rather
// than taken from the constant, so a wrong constant fails here.
func TestCacheTTLs(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	start := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	now := start
	c := newClientAt(t, fs, t.TempDir(), false, func() time.Time { return now })
	in := refs(t, "npm:flatmap-stream@0.1.1", "npm:express@4.17.1", "pypi:requests@2.31.0")
	distinctIDs := len(flatmapStreamIDs) + len(expressIDs) + len(requestsIDs)
	steps := []struct {
		name                string
		at                  time.Duration
		wantPosts, wantGets int
	}{
		{"first call", 0, 1, distinctIDs},
		{"just under six hours", 6*time.Hour - time.Second, 1, distinctIDs},
		{"just over six hours", 6*time.Hour + time.Second, 2, 2 * distinctIDs},
	}
	for _, step := range steps {
		now = start.Add(step.at)
		if _, err := c.Advisories(context.Background(), in); err != nil {
			t.Fatalf("%s: Advisories: %v", step.name, err)
		}
		if posts, gets := fs.postCount(), len(fs.getIDs()); posts != step.wantPosts || gets != step.wantGets {
			t.Errorf("%s: posts %d gets %d, want %d and %d", step.name, posts, gets, step.wantPosts, step.wantGets)
		}
	}
}

func TestAdvisoriesEmpty(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	got, err := c.Advisories(context.Background(), nil)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("Advisories(nil) = %v, %v, want an empty map", got, err)
	}
	if fs.postCount() != 0 {
		t.Errorf("posts = %d, want 0", fs.postCount())
	}
}

func TestAdvisoriesUnversionedRef(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	fs.answer(func(_ batchRequest) batchResponse {
		return batchResponse{Results: []batchResult{vulnsOf("MAL-2025-20690")}}
	})
	c := newClient(t, fs, t.TempDir(), false)
	in := refs(t, "npm:flatmap-stream")

	got, err := c.Advisories(context.Background(), in)
	if err != nil {
		t.Fatalf("Advisories: %v", err)
	}
	want := `{"queries":[{"package":{"name":"flatmap-stream","ecosystem":"npm"}}]}`
	if body := string(fs.rawPost(0)); body != want {
		t.Errorf("body = %s, want %s", body, want)
	}
	if gotIDs := ids(got[in[0]]); !reflect.DeepEqual(gotIDs, []string{"MAL-2025-20690"}) {
		t.Errorf("ids = %v", gotIDs)
	}
}

func TestAdvisoriesServerErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		code       int
		wantMethod string
		// wantGets is how many details requests an outage costs: none when
		// the batch failed, maxDetailFailures when the details endpoint is
		// down, after which the remaining ids are given up without a request.
		wantGets int
	}{
		{"querybatch fails", "/querybatch", http.StatusInternalServerError, http.MethodPost, 0},
		{"details fail", "/vulns/", http.StatusServiceUnavailable, http.MethodGet, maxDetailFailures},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fs := newFixtureServer(t)
			fs.fail(tt.path, tt.code)
			c := newClient(t, fs, t.TempDir(), false)
			got, err := c.Advisories(context.Background(), refs(t, "npm:flatmap-stream@0.1.1", "npm:express@4.17.1", "pypi:requests@2.31.0"))
			var se *httpcache.StatusError
			if !errors.As(err, &se) {
				t.Fatalf("Advisories error = %v, want a StatusError", err)
			}
			if se.Method != tt.wantMethod || se.StatusCode != tt.code {
				t.Errorf("StatusError = %+v, want %s %d", se, tt.wantMethod, tt.code)
			}
			if !strings.HasPrefix(err.Error(), "osv: ") {
				t.Errorf("error %q is not prefixed with the package name", err)
			}
			// Every ref lost: the cause comes back alone, not as a partial answer.
			var pe *advisory.PartialError
			if got != nil || errors.As(err, &pe) {
				t.Errorf("Advisories = %v, %v; want no map and no PartialError when nothing was answered", got, err)
			}
			if gets := fs.getIDs(); len(gets) != tt.wantGets {
				t.Errorf("details requests = %v, want %d", gets, tt.wantGets)
			}
		})
	}
}

func TestAdvisoriesCanceled(t *testing.T) {
	t.Parallel()
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Advisories(ctx, refs(t, "npm:express@4.17.1"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Advisories error = %v, want context.Canceled", err)
	}
}

func TestEcosystem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		eco  model.Ecosystem
		want string
	}{
		{model.NPM, "npm"},
		{model.PyPI, "PyPI"},
		{model.Cargo, "crates.io"},
		{model.Deno, ""},
		{model.JSR, ""},
		{model.Ecosystem("maven"), ""},
	}
	for _, tt := range tests {
		if got := Ecosystem(tt.eco); got != tt.want {
			t.Errorf("Ecosystem(%q) = %q, want %q", tt.eco, got, tt.want)
		}
	}
}

func TestNewOptions(t *testing.T) {
	t.Parallel()
	if c := New(nil); c.base != DefaultBaseURL || c.log == nil {
		t.Errorf("New(nil) = %+v, want the default base URL and a logger", c)
	}
	if c := New(nil, WithBaseURL("http://127.0.0.1:1/v1///"), WithLogger(nil)); c.base != "http://127.0.0.1:1/v1" || c.log == nil {
		t.Errorf("New with options = %+v, want the trimmed base URL and the default logger", c)
	}
}

// The tests below put one record through both paths that can answer for it: the
// API, and the offline index built from the per-ecosystem archive. Everything is
// served from httptest servers built in this process, so no archive is ever
// downloaded. What they assert is agreement: an advisory that reads one way
// online and another way offline is worse than an advisory that reads badly both
// ways, because nobody can tell which run they are looking at.

// recordID reads the id out of a record the test wrote.
func recordID(t *testing.T, record string) string {
	t.Helper()
	var parsed struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(record), &parsed); err != nil {
		t.Fatalf("test record is not JSON: %v\n%s", err, record)
	}
	return parsed.ID
}

// onlineAdvisories answers a ref from an API server that lists every record for
// every query and serves each record from the vulns endpoint. The batch entries
// carry a modified of their own, older than any record's, so a test can see
// whether an advisory took its timestamp from the record or from the batch.
func onlineAdvisories(t *testing.T, ref model.PackageRef, records ...string) ([]advisory.Advisory, error) {
	t.Helper()
	const batchModified = "2000-01-01T00:00:00Z"
	byID := make(map[string]string, len(records))
	ids := make([]string, 0, len(records))
	for _, record := range records {
		id := recordID(t, record)
		byID[id] = record
		ids = append(ids, id)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/querybatch":
			var req batchRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("querybatch body does not decode: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			answer := batchResponse{Results: make([]batchResult, len(req.Queries))}
			for i := range answer.Results {
				for _, id := range ids {
					answer.Results[i].Vulns = append(answer.Results[i].Vulns, batchVuln{ID: id, Modified: batchModified})
				}
			}
			if err := json.NewEncoder(w).Encode(answer); err != nil {
				t.Errorf("encoding querybatch answer: %v", err)
			}
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.EscapedPath(), "/vulns/"):
			record, ok := byID[strings.TrimPrefix(r.URL.EscapedPath(), "/vulns/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(record))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpcache.New(httpcache.Options{
		Dir:       t.TempDir(),
		UserAgent: "trustdiff-test",
		Retries:   -1,
		HostRPS:   map[string]float64{u.Host: 1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := New(h, WithBaseURL(srv.URL), WithLogger(slog.New(slog.DiscardHandler)))
	got, err := c.Advisories(context.Background(), []model.PackageRef{ref})
	return got[ref], err
}

// offlineAdvisories answers the same ref from an index built by a real refresh
// against an archive of the same records, served from an httptest server at the
// path the OSV bucket uses.
func offlineAdvisories(t *testing.T, ref model.PackageRef, records ...string) ([]advisory.Advisory, error) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, record := range records {
		w, err := zw.Create(recordID(t, record) + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(record)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := "/" + osvindex.OSVEcosystem(ref.Ecosystem) + "/" + osvindex.ArchiveName
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != archive {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)

	cacheDir := t.TempDir()
	results, err := osvindex.Refresh(context.Background(), cacheDir, []model.Ecosystem{ref.Ecosystem},
		osvindex.Options{BaseURL: srv.URL, UserAgent: "trustdiff-test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("refresh = %+v", results)
	}
	h, err := httpcache.New(httpcache.Options{Dir: t.TempDir(), Offline: true, UserAgent: "trustdiff-test"})
	if err != nil {
		t.Fatal(err)
	}
	c := New(h, WithIndex(osvindex.Open(cacheDir)), WithLogger(slog.New(slog.DiscardHandler)))
	got, err := c.Advisories(context.Background(), []model.PackageRef{ref})
	return got[ref], err
}

// TestOnlineAndOfflineDescribeTheSameAdvisory is the parity table. Every case is a
// record whose two answers used to differ.
func TestOnlineAndOfflineDescribeTheSameAdvisory(t *testing.T) {
	t.Parallel()
	const usableVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	cases := []struct {
		name   string
		record string
		check  func(t *testing.T, got []advisory.Advisory)
	}{
		{
			// A malformed vector in front of a usable one. The rule skips the one
			// that does not parse, so both paths have to see both vectors: an
			// index that kept only the first handed it "not-a-vector" and
			// answered unknown with no score where the API answered critical.
			name: "a malformed CVSS vector does not hide the usable one",
			record: `{"id":"GHSA-two-vectors","summary":"Command injection",
				"published":"2026-01-02T03:04:05+02:00","modified":"2026-02-03T04:05:06Z",
				"aliases":["CVE-2026-2222","CVE-2026-1111"],
				"severity":[{"type":"CVSS_V3","score":"not-a-vector"},{"type":"CVSS_V3","score":"` + usableVector + `"}],
				"affected":[{"package":{"name":"p","ecosystem":"npm"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
			check: func(t *testing.T, got []advisory.Advisory) {
				t.Helper()
				if len(got) != 1 {
					t.Fatalf("advisories = %v, want one", got)
				}
				a := got[0]
				if a.Severity != advisory.SeverityCritical || a.Score != 9.8 || a.SeveritySource != advisory.SeveritySourceCVSS3 {
					t.Errorf("severity = %v %.1f from %q, want critical 9.8 from the vector", a.Severity, a.Score, a.SeveritySource)
				}
				// The record's own order, not sorted: OSV names the identifier
				// the record came from first.
				if want := []string{"CVE-2026-2222", "CVE-2026-1111"}; !slices.Equal(a.Aliases, want) {
					t.Errorf("Aliases = %q, want %q", a.Aliases, want)
				}
				// The record spelled published with a +02:00 offset. Both paths
				// keep the instant in UTC, so the two answers compare equal.
				if a.Published.Location() != time.UTC || !a.Published.Equal(time.Date(2026, 1, 2, 1, 4, 5, 0, time.UTC)) {
					t.Errorf("Published = %v, want 2026-01-02T01:04:05Z", a.Published)
				}
			},
		},
		{
			// The batch entry carries a modified of its own. The record is the
			// only source of the timestamps, because the offline index is built
			// from the archive and has no batch entry to fall back on.
			name: "a record without a modified timestamp",
			record: `{"id":"GHSA-no-modified","summary":"no modified field",
				"published":"2026-01-02T03:04:05Z",
				"affected":[{"package":{"name":"p","ecosystem":"npm"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
			check: func(t *testing.T, got []advisory.Advisory) {
				t.Helper()
				if len(got) != 1 {
					t.Fatalf("advisories = %v, want one", got)
				}
				if !got[0].Modified.IsZero() {
					t.Errorf("Modified = %v, want the zero time: the record carried none", got[0].Modified)
				}
			},
		},
		{
			// OSV filters withdrawn records out of the query API today, so this
			// record only reaches the online path if that changes. The index has
			// always dropped them, and the two must not disagree.
			name: "a withdrawn advisory",
			record: `{"id":"GHSA-withdrawn","summary":"raised against the wrong package",
				"published":"2026-01-02T03:04:05Z","modified":"2026-03-04T05:06:07Z",
				"withdrawn":"2026-03-04T05:06:07Z","database_specific":{"severity":"HIGH"},
				"affected":[{"package":{"name":"p","ecosystem":"npm"},
				"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
			check: func(t *testing.T, got []advisory.Advisory) {
				t.Helper()
				if len(got) != 0 {
					t.Errorf("advisories = %v, want none: the advisory was withdrawn", got)
				}
			},
		},
	}

	ref := model.PackageRef{Ecosystem: model.NPM, Name: "p", Version: "1.2.3"}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			online, err := onlineAdvisories(t, ref, tt.record)
			if err != nil {
				t.Fatalf("online: %v", err)
			}
			offline, err := offlineAdvisories(t, ref, tt.record)
			if err != nil {
				t.Fatalf("offline: %v", err)
			}
			if !reflect.DeepEqual(online, offline) {
				t.Fatalf("the two paths disagree\nonline:  %+v\noffline: %+v", online, offline)
			}
			t.Run("online", func(t *testing.T) { tt.check(t, online) })
			t.Run("offline", func(t *testing.T) { tt.check(t, offline) })
		})
	}
}
