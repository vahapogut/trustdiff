package depsdev

import (
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
)

// similarRoutes maps escaped request paths to the recorded fixtures.
var similarRoutes = map[string]string{
	"/systems/NPM/packages/jost:similarlyNamedPackages":          "similar-jost.json",
	"/systems/NPM/packages/express:similarlyNamedPackages":       "similar-express.json",
	"/systems/NPM/packages/@types%2Fnode:similarlyNamedPackages": "similar-types-node.json",
}

// batchFixtures maps a batch endpoint to its recorded answer.
var batchFixtures = map[string]string{
	"versionbatch":  "versionbatch.json",
	"findingsbatch": "findingsbatch.json",
}

// unknownVersion is the version the generated responder reports as unknown.
const unknownVersion = "0.0.0-unknown"

// server serves the recorded fixtures and remembers every request it got, so
// tests can assert on paths, bodies and request counts. A batch request is
// answered the way deps.dev answers it: one response per request, in request
// order, taken from the recorded batch by the echoed request. respond, when
// set, replaces the fixture answer of the batch endpoints.
type server struct {
	*httptest.Server
	t       *testing.T
	mu      sync.Mutex
	paths   []string
	batches map[string][]batchRequest
	respond func(endpoint string, req batchRequest) (int, []byte)
}

func newServer(t *testing.T) *server {
	t.Helper()
	fixtures := map[string][]byte{}
	for _, file := range []string{"versionbatch.json", "findingsbatch.json", "similar-jost.json", "similar-express.json", "similar-types-node.json", "similar-not-found.json"} {
		fixtures[file] = fixture(t, file)
	}
	s := &server{t: t, batches: map[string][]batchRequest{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		s.mu.Lock()
		s.paths = append(s.paths, r.Method+" "+path)
		s.mu.Unlock()
		if r.Method == http.MethodPost {
			s.servePost(w, r, strings.TrimPrefix(path, "/"), fixtures)
			return
		}
		if file, ok := similarRoutes[path]; ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixtures[file])
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(fixtures["similar-not-found.json"])
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) servePost(w http.ResponseWriter, r *http.Request, endpoint string, fixtures map[string][]byte) {
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "want application/json", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var req batchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.batches[endpoint] = append(s.batches[endpoint], req)
	respond := s.respond
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if respond != nil {
		status, answer := respond(endpoint, req)
		w.WriteHeader(status)
		_, _ = w.Write(answer)
		return
	}
	file, ok := batchFixtures[endpoint]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = w.Write(s.selectResponses(fixtures[file], req))
}

// selectResponses answers a batch request from a recorded batch: the recorded
// response of each request, in request order, as deps.dev answers. A request
// the recording does not cover fails the test and gets an echo-only response,
// so a typo in a test cannot pass as a version deps.dev does not know.
func (s *server) selectResponses(recorded []byte, req batchRequest) []byte {
	var doc batchPage
	if err := json.Unmarshal(recorded, &doc); err != nil {
		s.t.Errorf("decoding the recorded batch: %v", err)
		return page(nil, "")
	}
	byKey := make(map[string]json.RawMessage, len(doc.Responses))
	for _, raw := range doc.Responses {
		var r struct {
			Request batchItem `json:"request"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			s.t.Errorf("decoding a recorded response: %v", err)
			continue
		}
		byKey[r.Request.key()] = raw
	}
	out := make([]json.RawMessage, 0, len(req.Requests))
	for _, it := range req.Requests {
		raw, ok := byKey[it.key()]
		if !ok {
			s.t.Errorf("no recorded response for %s", it)
			raw, _ = json.Marshal(map[string]batchItem{"request": it})
		}
		out = append(out, raw)
	}
	return page(out, "")
}

// requests returns the recorded bodies sent to a batch endpoint.
func (s *server) requests(endpoint string) []batchRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.batches[endpoint])
}

// count returns how many requests the server has seen.
func (s *server) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.paths)
}

// countOf returns how many times a "METHOD /path" line was requested.
func (s *server) countOf(line string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.paths {
		if p == line {
			n++
		}
	}
	return n
}

// seen reports whether a "METHOD /path" line was requested.
func (s *server) seen(line string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.paths, line)
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return data
}

// newClient builds a client pointed at the fixture server. dir is the
// httpcache directory, shared between clients when a test observes the cache.
// Retries are off so an error answer fails fast.
func newClient(t *testing.T, s *server, dir string, offline bool) *Client {
	t.Helper()
	return newClientAt(t, s, dir, offline, nil, nil)
}

// newClientAt is newClient with a clock for the cache TTLs (nil means the wall
// clock) and a logger (nil discards).
func newClientAt(t *testing.T, s *server, dir string, offline bool, now func() time.Time, log *slog.Logger) *Client {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpcache.New(httpcache.Options{
		Dir:       dir,
		Offline:   offline,
		UserAgent: "trustdiff-test",
		Retries:   -1,
		// The shared client allows 10 requests per second per host with a burst
		// of one; tests should not wait for that.
		HostRPS: map[string]float64{u.Host: 1000},
		Now:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return New(h, WithBaseURL(s.URL+"/"), WithLogger(log))
}

func ref(s string) model.PackageRef { return model.MustParseRef(s) }

func ts(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad timestamp %q: %v", s, err)
	}
	return parsed
}

// generated answers a versionbatch from its own request: every version is
// known except unknownVersion, and is published on the day its patch number
// names, so a test can tell answers apart without a fixture per case.
func generated(items []batchItem) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(items))
	for _, it := range items {
		r := versionResponse{Request: it}
		if v := it.VersionKey; v != nil && v.Version != unknownVersion {
			day, _ := strconv.Atoi(strings.TrimPrefix(v.Version, "1.0."))
			r.Version = &versionDoc{VersionKey: *v, PublishedAt: fmt.Sprintf("2024-01-%02dT00:00:00Z", day)}
		}
		raw, _ := json.Marshal(r)
		out = append(out, raw)
	}
	return out
}

// page encodes one batch answer.
func page(responses []json.RawMessage, next string) []byte {
	body, _ := json.Marshal(batchPage{Responses: responses, NextPageToken: next})
	return body
}

// generatedRefs builds npm refs pkg1@1.0.1 ... pkgN@1.0.N.
func generatedRefs(n int) []model.PackageRef {
	out := make([]model.PackageRef, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, ref(fmt.Sprintf("npm:pkg%d@1.0.%d", i, i)))
	}
	return out
}

func TestVersionsFixture(t *testing.T) {
	s := newServer(t)
	c := newClient(t, s, t.TempDir(), false)
	ctx := context.Background()

	refs := []model.PackageRef{
		ref("npm:express@4.19.2"),
		ref("pypi:requests@2.32.3"),
		ref("npm:@sigstore/bundle@3.1.0"),
		ref("cargo:serde@1.0.210"),
		ref("npm:express@99.99.99"),
		ref("deno:std@1.0.0"),
		ref("npm:express"),
	}
	got, err := c.Versions(ctx, refs)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}

	tests := []struct {
		ref  model.PackageRef
		want *VersionFacts
	}{
		{ref("npm:express@4.19.2"), &VersionFacts{
			Found:        true,
			PublishedAt:  ts(t, "2024-03-25T14:30:36Z"),
			AdvisoryKeys: []string{"GHSA-qw6h-vgh9-j6wx"},
			CooldownEnd:  ts(t, "2024-03-25T14:30:36Z"),
		}},
		{ref("pypi:requests@2.32.3"), &VersionFacts{
			Found:        true,
			PublishedAt:  ts(t, "2024-05-29T15:37:47Z"),
			AdvisoryKeys: []string{"GHSA-9hjg-9r4m-mvj7", "GHSA-gc5v-m9x4-r6x2", "PYSEC-2026-1872", "PYSEC-2026-2275"},
			CooldownEnd:  ts(t, "2024-06-03T15:37:47Z"),
		}},
		{ref("npm:@sigstore/bundle@3.1.0"), &VersionFacts{
			Found:               true,
			PublishedAt:         ts(t, "2025-02-04T20:35:48Z"),
			AttestationVerified: true,
			SLSAVerified:        true,
			CooldownEnd:         ts(t, "2025-02-19T20:35:48Z"),
		}},
		{ref("cargo:serde@1.0.210"), &VersionFacts{
			Found:       true,
			PublishedAt: ts(t, "2024-09-06T18:17:42Z"),
			CooldownEnd: ts(t, "2024-09-16T18:17:42Z"),
		}},
		// deps.dev answered with the echoed request only.
		{ref("npm:express@99.99.99"), &VersionFacts{}},
		// No version to ask about, answered without a request.
		{ref("npm:express"), &VersionFacts{}},
		// deps.dev has no Deno system.
		{ref("deno:std@1.0.0"), nil},
	}
	for _, tt := range tests {
		facts, ok := got[tt.ref]
		if tt.want == nil {
			if ok {
				t.Errorf("%s: present with %+v, want absent", tt.ref, facts)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: absent, want %+v", tt.ref, *tt.want)
			continue
		}
		if !reflect.DeepEqual(facts, *tt.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tt.ref, facts, *tt.want)
		}
	}
	if len(got) != len(tests)-1 {
		t.Errorf("Versions returned %d entries, want %d", len(got), len(tests)-1)
	}

	// One POST carrying the five supported, versioned refs in order, spelled
	// the way deps.dev expects.
	bodies := s.requests("versionbatch")
	if len(bodies) != 1 {
		t.Fatalf("versionbatch requests = %d, want 1", len(bodies))
	}
	want := []batchItem{
		{VersionKey: &versionKey{System: "NPM", Name: "express", Version: "4.19.2"}},
		{VersionKey: &versionKey{System: "PYPI", Name: "requests", Version: "2.32.3"}},
		{VersionKey: &versionKey{System: "NPM", Name: "@sigstore/bundle", Version: "3.1.0"}},
		{VersionKey: &versionKey{System: "CARGO", Name: "serde", Version: "1.0.210"}},
		{VersionKey: &versionKey{System: "NPM", Name: "express", Version: "99.99.99"}},
	}
	if !reflect.DeepEqual(bodies[0].Requests, want) {
		t.Errorf("versionbatch body:\n got %s\nwant %s", itemsJSON(bodies[0].Requests), itemsJSON(want))
	}
	if bodies[0].PageToken != "" {
		t.Errorf("first page sent pageToken %q", bodies[0].PageToken)
	}
}

func itemsJSON(items []batchItem) string {
	b, _ := json.Marshal(items)
	return string(b)
}

func TestFindingsFixture(t *testing.T) {
	s := newServer(t)
	c := newClient(t, s, t.TempDir(), false)
	ctx := context.Background()

	refs := []model.PackageRef{
		ref("npm:flatmap-stream@0.1.1"),
		ref("npm:request@2.88.2"),
		ref("pypi:boto3@1.43.90"),
		ref("npm:express@4.19.2"),
		ref("npm:express@99.99.99"),
		ref("npm:flatmap-stream"),
		ref("jsr:@std/path@1.0.0"),
	}
	got, err := c.Findings(ctx, refs)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}

	tests := []struct {
		ref  model.PackageRef
		want []Finding
	}{
		// npm removed the version, so it is NOT_FOUND while the package-scoped
		// MALICIOUS and VULNERABLE findings are appended.
		{ref("npm:flatmap-stream@0.1.1"), []Finding{
			{Type: "NOT_FOUND", Risk: "RISK_CRITICAL"},
			{Type: "MALICIOUS", Risk: "RISK_CRITICAL"},
			{Type: "VULNERABLE", Risk: "RISK_CRITICAL"},
		}},
		// The package-scoped DEPRECATED repeats the version's and is folded in.
		{ref("npm:request@2.88.2"), []Finding{
			{Type: "DEPRECATED", Risk: "RISK_MEDIUM", Detail: "request has been deprecated, see https://github.com/request/request/issues/3142"},
		}},
		{ref("pypi:boto3@1.43.90"), []Finding{
			{Type: "COOLDOWN", Risk: "RISK_HIGH", Detail: "in cooldown until 2026-09-13T19:22:28Z"},
		}},
		{ref("npm:express@4.19.2"), []Finding{
			{Type: "REMEDIATION", Risk: "RISK_INFORMATIONAL"},
		}},
		{ref("npm:express@99.99.99"), []Finding{
			{Type: "NOT_FOUND", Risk: "RISK_CRITICAL"},
		}},
		// A package request gets the package-scoped findings only.
		{ref("npm:flatmap-stream"), []Finding{
			{Type: "MALICIOUS", Risk: "RISK_CRITICAL"},
			{Type: "VULNERABLE", Risk: "RISK_CRITICAL"},
		}},
		{ref("jsr:@std/path@1.0.0"), nil},
	}
	for _, tt := range tests {
		if findings := got[tt.ref]; !slices.Equal(findings, tt.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tt.ref, findings, tt.want)
		}
	}

	bodies := s.requests("findingsbatch")
	if len(bodies) != 1 {
		t.Fatalf("findingsbatch requests = %d, want 1", len(bodies))
	}
	if n := len(bodies[0].Requests); n != 6 {
		t.Fatalf("findingsbatch body has %d requests, want 6: %s", n, itemsJSON(bodies[0].Requests))
	}
	last := bodies[0].Requests[5]
	if last.VersionKey != nil || last.PackageKey == nil || *last.PackageKey != (packageKey{System: "NPM", Name: "flatmap-stream"}) {
		t.Errorf("versionless ref sent as %s, want a packageKey", itemsJSON([]batchItem{last}))
	}
}

func TestFindingDetail(t *testing.T) {
	c := New(nil)
	tests := []struct {
		name string
		doc  findingDoc
		want Finding
	}{
		{"bare", findingDoc{Type: "MALICIOUS", Risk: "RISK_CRITICAL"}, Finding{Type: "MALICIOUS", Risk: "RISK_CRITICAL"}},
		{"deprecated", findingDoc{Type: "DEPRECATED", Risk: "RISK_MEDIUM", DeprecatedContext: &deprecatedContext{Reason: "use other"}},
			Finding{Type: "DEPRECATED", Risk: "RISK_MEDIUM", Detail: "use other"}},
		{"cooldown", findingDoc{Type: "COOLDOWN", Risk: "RISK_HIGH", CooldownContext: &cooldownContext{End: "2026-09-13T19:22:28Z"}},
			Finding{Type: "COOLDOWN", Risk: "RISK_HIGH", Detail: "in cooldown until 2026-09-13T19:22:28Z"}},
		{"cooldown with bad end", findingDoc{Type: "COOLDOWN", Risk: "RISK_HIGH", CooldownContext: &cooldownContext{End: "soon"}},
			Finding{Type: "COOLDOWN", Risk: "RISK_HIGH"}},
		{"low usage", findingDoc{Type: "LOW_USAGE", Risk: "RISK_LOW", LowUsageContext: &lowUsageContext{AlternativePackages: []string{"lodash", "underscore"}}},
			Finding{Type: "LOW_USAGE", Risk: "RISK_LOW", Detail: "packages with similar names and higher usage: lodash, underscore"}},
	}
	for _, tt := range tests {
		if got := c.finding(ref("npm:x@1.0.0"), tt.doc); got != tt.want {
			t.Errorf("%s: got %+v, want %+v", tt.name, got, tt.want)
		}
	}
}

func TestVersionsChunking(t *testing.T) {
	s := newServer(t)
	s.respond = func(_ string, req batchRequest) (int, []byte) {
		return http.StatusOK, page(generated(req.Requests), "")
	}
	c := newClient(t, s, t.TempDir(), false)
	c.batchSize = 2
	ctx := context.Background()

	refs := generatedRefs(5)
	// A duplicate is sent once; an unknown version is sent and stays Found false.
	refs = append(refs, refs[4], ref("npm:pkg9@"+unknownVersion))
	got, err := c.Versions(ctx, refs)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}

	bodies := s.requests("versionbatch")
	sizes := make([]int, 0, len(bodies))
	for _, b := range bodies {
		sizes = append(sizes, len(b.Requests))
	}
	if want := []int{2, 2, 2}; !slices.Equal(sizes, want) {
		t.Fatalf("chunk sizes = %v, want %v", sizes, want)
	}
	var sent []string
	for _, b := range bodies {
		for _, it := range b.Requests {
			sent = append(sent, it.VersionKey.Name+"@"+it.VersionKey.Version)
		}
	}
	wantSent := []string{"pkg1@1.0.1", "pkg2@1.0.2", "pkg3@1.0.3", "pkg4@1.0.4", "pkg5@1.0.5", "pkg9@" + unknownVersion}
	if !slices.Equal(sent, wantSent) {
		t.Errorf("sent %v, want %v", sent, wantSent)
	}

	if len(got) != 6 {
		t.Errorf("Versions returned %d entries, want 6", len(got))
	}
	for i := 1; i <= 5; i++ {
		r := ref(fmt.Sprintf("npm:pkg%d@1.0.%d", i, i))
		want := VersionFacts{Found: true, PublishedAt: ts(t, fmt.Sprintf("2024-01-%02dT00:00:00Z", i))}
		if facts := got[r]; !reflect.DeepEqual(facts, want) {
			t.Errorf("%s: got %+v, want %+v", r, facts, want)
		}
	}
	if facts := got[ref("npm:pkg9@"+unknownVersion)]; facts.Found {
		t.Errorf("unknown version reported Found: %+v", facts)
	}
}

func TestVersionsPagination(t *testing.T) {
	s := newServer(t)
	const pageSize = 2
	s.respond = func(_ string, req batchRequest) (int, []byte) {
		all := generated(req.Requests)
		start := 0
		if req.PageToken != "" {
			start, _ = strconv.Atoi(strings.TrimPrefix(req.PageToken, "page-"))
		}
		end := min(start+pageSize, len(all))
		next := ""
		if end < len(all) {
			next = "page-" + strconv.Itoa(end)
		}
		return http.StatusOK, page(all[start:end], next)
	}
	c := newClient(t, s, t.TempDir(), false)
	ctx := context.Background()

	refs := generatedRefs(5)
	got, err := c.Versions(ctx, refs)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	bodies := s.requests("versionbatch")
	tokens := make([]string, 0, len(bodies))
	for _, b := range bodies {
		tokens = append(tokens, b.PageToken)
		if !reflect.DeepEqual(b.Requests, bodies[0].Requests) {
			t.Errorf("a follow-up page changed the requests: %s", itemsJSON(b.Requests))
		}
	}
	if want := []string{"", "page-2", "page-4"}; !slices.Equal(tokens, want) {
		t.Errorf("page tokens = %q, want %q", tokens, want)
	}
	for i, r := range refs {
		want := VersionFacts{Found: true, PublishedAt: ts(t, fmt.Sprintf("2024-01-%02dT00:00:00Z", i+1))}
		if facts := got[r]; !reflect.DeepEqual(facts, want) {
			t.Errorf("%s: got %+v, want %+v", r, facts, want)
		}
	}
}

func TestVersionsPaginationBound(t *testing.T) {
	s := newServer(t)
	// Every page names a fresh token, so each follow-up is a new body and a
	// new request rather than a cache hit.
	var pages atomic.Int64
	s.respond = func(_ string, req batchRequest) (int, []byte) {
		return http.StatusOK, page(generated(req.Requests), "page-"+strconv.FormatInt(pages.Add(1), 10))
	}
	c := newClient(t, s, t.TempDir(), false)
	_, err := c.Versions(context.Background(), generatedRefs(1))
	if err == nil || !strings.Contains(err.Error(), "pages") {
		t.Fatalf("endless pagination error = %v, want a page bound error", err)
	}
	if n := len(s.requests("versionbatch")); n != maxPages {
		t.Errorf("followed %d pages, want %d", n, maxPages)
	}
}

func TestVersionsAlignment(t *testing.T) {
	refs := generatedRefs(4)
	published := func(i int) VersionFacts {
		return VersionFacts{Found: true, PublishedAt: time.Date(2024, 1, i, 0, 0, 0, 0, time.UTC)}
	}
	// rewrite decodes, edits and re-encodes the generated answers.
	rewrite := func(answers []json.RawMessage, edit func(i int, r *versionResponse)) []json.RawMessage {
		out := make([]json.RawMessage, 0, len(answers))
		for i, raw := range answers {
			var r versionResponse
			if err := json.Unmarshal(raw, &r); err != nil {
				panic(err)
			}
			edit(i, &r)
			b, _ := json.Marshal(r)
			out = append(out, b)
		}
		return out
	}

	inOrder := map[model.PackageRef]VersionFacts{refs[0]: published(1), refs[1]: published(2), refs[2]: published(3), refs[3]: published(4)}

	tests := []struct {
		name  string
		shape func([]json.RawMessage) []json.RawMessage
		want  map[model.PackageRef]VersionFacts
		// wantErr is a fragment of the error a short or misplaced answer must
		// produce instead of a map with Found false entries.
		wantErr string
		// wantWarn is a fragment of the warning logged when an echo names
		// another request of the batch.
		wantWarn string
	}{
		{
			name: "in order with echoed requests",
			shape: func(a []json.RawMessage) []json.RawMessage {
				return a
			},
			want: inOrder,
		},
		{
			name: "in order without echoed requests",
			shape: func(a []json.RawMessage) []json.RawMessage {
				return rewrite(a, func(_ int, r *versionResponse) { r.Request = batchItem{} })
			},
			want: inOrder,
		},
		{
			name: "echo spelled differently",
			shape: func(a []json.RawMessage) []json.RawMessage {
				return rewrite(a, func(_ int, r *versionResponse) {
					r.Request.VersionKey.Name = strings.ToUpper(r.Request.VersionKey.Name)
				})
			},
			want: inOrder,
		},
		{
			// One response per request, so the position decides even when the
			// echo names another request: deps.dev echoes the first spelling of
			// a collapsed request, which is exactly this shape. The echo is
			// only reported.
			name: "echo names another request of the batch",
			shape: func(a []json.RawMessage) []json.RawMessage {
				return rewrite(a, func(_ int, r *versionResponse) {
					r.Request.VersionKey.Name = "pkg1"
					r.Request.VersionKey.Version = "1.0.1"
				})
			},
			want:     inOrder,
			wantWarn: "echoes another request",
		},
		{
			// Fewer answers than requests and nothing to match on: an error,
			// never a guess and never Found false.
			name: "short without echoed requests",
			shape: func(a []json.RawMessage) []json.RawMessage {
				return rewrite(a[:3], func(_ int, r *versionResponse) { r.Request = batchItem{} })
			},
			wantErr: "versionbatch of 4 requests: 3 responses",
		},
		{
			// Fewer answers, placed by their echo, but two refs got none: still
			// an error, since Found false would be read as "not indexed".
			name: "short with echoed requests",
			shape: func(a []json.RawMessage) []json.RawMessage {
				return a[1:3]
			},
			wantErr: "versionbatch of 4 requests: 2 responses, none for npm:pkg1@1.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newServer(t)
			s.respond = func(_ string, req batchRequest) (int, []byte) {
				return http.StatusOK, page(tt.shape(generated(req.Requests)), "")
			}
			var logged strings.Builder
			c := newClientAt(t, s, t.TempDir(), false, nil, slog.New(slog.NewTextHandler(&logged, nil)))
			got, err := c.Versions(context.Background(), refs)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Versions = %+v, %v; want an error mentioning %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Versions: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("\n got %+v\nwant %+v", got, tt.want)
			}
			if warned := strings.Contains(logged.String(), "echoes another request"); warned != (tt.wantWarn != "") {
				t.Errorf("warning logged = %v, want %v; log:\n%s", warned, tt.wantWarn != "", logged.String())
			}
		})
	}
}

// TestVersionsCollapsedRequests replays the recorded answer to two spellings
// of one PyPI version: deps.dev answered both, in order, and echoed the first
// spelling for both, so only the position tells the responses apart.
func TestVersionsCollapsedRequests(t *testing.T) {
	s := newServer(t)
	s.respond = func(_ string, _ batchRequest) (int, []byte) {
		return http.StatusOK, fixture(t, "versionbatch-collapse.json")
	}
	c := newClient(t, s, t.TempDir(), false)
	// Built by hand: ParseRef would fold Requests to the PEP 503 form.
	refs := []model.PackageRef{
		{Ecosystem: model.PyPI, Name: "Requests", Version: "2.32.3"},
		{Ecosystem: model.PyPI, Name: "requests", Version: "2.32.3"},
	}
	got, err := c.Versions(context.Background(), refs)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	want := VersionFacts{
		Found:        true,
		PublishedAt:  ts(t, "2024-05-29T15:37:47Z"),
		AdvisoryKeys: []string{"GHSA-9hjg-9r4m-mvj7", "GHSA-gc5v-m9x4-r6x2", "PYSEC-2026-1872", "PYSEC-2026-2275"},
		CooldownEnd:  ts(t, "2024-06-03T15:37:47Z"),
	}
	for _, r := range refs {
		if facts := got[r]; !reflect.DeepEqual(facts, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", r, facts, want)
		}
	}
	bodies := s.requests("versionbatch")
	if len(bodies) != 1 || len(bodies[0].Requests) != 2 || bodies[0].Requests[0].VersionKey.Name != "Requests" || bodies[0].Requests[1].VersionKey.Name != "requests" {
		t.Errorf("versionbatch bodies = %d, want one carrying both spellings as given", len(bodies))
	}
}

// TestVersionsCaseSensitiveNames replays the recorded answer for JSONStream
// and jsonstream, two npm packages: the name a ref carries reaches the wire
// unchanged, and the mixed-case one is the package deps.dev knows.
func TestVersionsCaseSensitiveNames(t *testing.T) {
	s := newServer(t)
	s.respond = func(_ string, _ batchRequest) (int, []byte) {
		return http.StatusOK, fixture(t, "versionbatch-jsonstream.json")
	}
	c := newClient(t, s, t.TempDir(), false)
	upper, err := model.ParseRef("npm:JSONStream@1.3.5")
	if err != nil {
		t.Fatal(err)
	}
	lower := ref("npm:jsonstream@1.3.5")
	got, err := c.Versions(context.Background(), []model.PackageRef{upper, lower})
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	want := VersionFacts{Found: true, PublishedAt: ts(t, "2018-10-14T01:24:01Z"), CooldownEnd: ts(t, "2018-10-29T01:24:01Z")}
	if facts := got[upper]; !reflect.DeepEqual(facts, want) {
		t.Errorf("%s:\n got %+v\nwant %+v", upper, facts, want)
	}
	if facts := got[lower]; facts.Found {
		t.Errorf("%s: Found with %+v, want the echo-only answer", lower, facts)
	}
	bodies := s.requests("versionbatch")
	if len(bodies) != 1 {
		t.Fatalf("versionbatch requests = %d, want 1", len(bodies))
	}
	wantSent := []batchItem{
		{VersionKey: &versionKey{System: "NPM", Name: "JSONStream", Version: "1.3.5"}},
		{VersionKey: &versionKey{System: "NPM", Name: "jsonstream", Version: "1.3.5"}},
	}
	if !reflect.DeepEqual(bodies[0].Requests, wantSent) {
		t.Errorf("versionbatch body:\n got %s\nwant %s", itemsJSON(bodies[0].Requests), itemsJSON(wantSent))
	}
}

func TestFindingsAlignment(t *testing.T) {
	// Each answer names its version in the finding so a wrong match shows.
	answer := func(it batchItem, echo bool) json.RawMessage {
		r := findingsResponse{Findings: &findingsDoc{
			RequestedVersion: &versionFindingsDoc{Findings: []findingDoc{{Type: "DEPRECATED", Risk: "RISK_MEDIUM", DeprecatedContext: &deprecatedContext{Reason: it.VersionKey.Version}}}},
		}}
		if echo {
			r.Request = it
		}
		b, _ := json.Marshal(r)
		return b
	}
	tests := []struct {
		name    string
		shape   func(items []batchItem) []json.RawMessage
		wantErr string
	}{
		{
			name: "in order without echoed requests",
			shape: func(items []batchItem) []json.RawMessage {
				out := make([]json.RawMessage, 0, len(items))
				for _, it := range items {
					out = append(out, answer(it, false))
				}
				return out
			},
		},
		{
			name: "short with echoed requests",
			shape: func(items []batchItem) []json.RawMessage {
				return []json.RawMessage{answer(items[1], true)}
			},
			wantErr: "findingsbatch of 3 requests: 1 responses, none for npm:pkg1@1.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newServer(t)
			s.respond = func(_ string, req batchRequest) (int, []byte) {
				return http.StatusOK, page(tt.shape(req.Requests), "")
			}
			c := newClient(t, s, t.TempDir(), false)
			refs := generatedRefs(3)
			got, err := c.Findings(context.Background(), refs)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Findings = %+v, %v; want an error mentioning %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Findings: %v", err)
			}
			for _, r := range refs {
				want := []Finding{{Type: "DEPRECATED", Risk: "RISK_MEDIUM", Detail: r.Version}}
				if !slices.Equal(got[r], want) {
					t.Errorf("%s: got %+v, want %+v", r, got[r], want)
				}
			}
		})
	}
}

func TestUnsupportedEcosystems(t *testing.T) {
	tests := []struct {
		name     string
		refs     []model.PackageRef
		wantErr  error
		wantKeys []model.PackageRef
	}{
		{"only deno and jsr", []model.PackageRef{ref("deno:std@1.0.0"), ref("jsr:@std/path@1.0.0")}, ErrUnsupported, nil},
		{"mixed", []model.PackageRef{ref("deno:std@1.0.0"), ref("npm:express@4.19.2")}, nil, []model.PackageRef{ref("npm:express@4.19.2")}},
		{"empty", nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run("versions "+tt.name, func(t *testing.T) {
			s := newServer(t)
			c := newClient(t, s, t.TempDir(), false)
			got, err := c.Versions(context.Background(), tt.refs)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if s.count() != 0 {
					t.Errorf("made %d requests for unsupported refs", s.count())
				}
				return
			}
			checkKeys(t, got, tt.wantKeys)
			if len(tt.wantKeys) == 0 && s.count() != 0 {
				t.Errorf("made %d requests for no refs", s.count())
			}
		})
		t.Run("findings "+tt.name, func(t *testing.T) {
			s := newServer(t)
			c := newClient(t, s, t.TempDir(), false)
			got, err := c.Findings(context.Background(), tt.refs)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if s.count() != 0 {
					t.Errorf("made %d requests for unsupported refs", s.count())
				}
				return
			}
			checkKeys(t, got, tt.wantKeys)
		})
	}

	s := newServer(t)
	c := newClient(t, s, t.TempDir(), false)
	if _, err := c.SimilarNames(context.Background(), model.Deno, "std"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("SimilarNames(deno) error = %v, want ErrUnsupported", err)
	}
	if s.count() != 0 {
		t.Errorf("SimilarNames(deno) made %d requests", s.count())
	}
}

// checkKeys asserts the map holds exactly the wanted refs.
func checkKeys[V any](t *testing.T, got map[model.PackageRef]V, want []model.PackageRef) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for _, r := range want {
		if _, ok := got[r]; !ok {
			t.Errorf("%s absent from %v", r, got)
		}
	}
}

func TestSimilarNames(t *testing.T) {
	tests := []struct {
		name     string
		eco      model.Ecosystem
		pkg      string
		want     []string
		wantPath string
	}{
		{"neighbors", model.NPM, "jost", []string{"@types/jest", "jose"}, "/systems/NPM/packages/jost:similarlyNamedPackages"},
		{"popular package", model.NPM, "express", []string{}, "/systems/NPM/packages/express:similarlyNamedPackages"},
		{"scoped name", model.NPM, "@types/node", []string{}, "/systems/NPM/packages/@types%2Fnode:similarlyNamedPackages"},
		{"unknown package", model.NPM, "@types/noed", []string{}, "/systems/NPM/packages/@types%2Fnoed:similarlyNamedPackages"},
		{"pypi system", model.PyPI, "requests", []string{}, "/systems/PYPI/packages/requests:similarlyNamedPackages"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newServer(t)
			c := newClient(t, s, t.TempDir(), false)
			got, err := c.SimilarNames(context.Background(), tt.eco, tt.pkg)
			if err != nil {
				t.Fatalf("SimilarNames: %v", err)
			}
			names := make([]string, 0, len(got))
			for _, sim := range got {
				names = append(names, sim.Name)
				if sim.Popularity != 0 {
					t.Errorf("%s: Popularity = %d, want 0 (deps.dev sends none)", sim.Name, sim.Popularity)
				}
			}
			if !slices.Equal(names, tt.want) {
				t.Errorf("names = %v, want %v", names, tt.want)
			}
			if got == nil {
				t.Error("SimilarNames returned a nil slice, want empty")
			}
			if !s.seen("GET " + tt.wantPath) {
				t.Errorf("path %s not requested; saw %v", tt.wantPath, s.paths)
			}
		})
	}
}

func TestSimilarNamesEmptyName(t *testing.T) {
	s := newServer(t)
	c := newClient(t, s, t.TempDir(), false)
	if _, err := c.SimilarNames(context.Background(), model.NPM, ""); err == nil {
		t.Fatal("SimilarNames with an empty name succeeded")
	}
	if s.count() != 0 {
		t.Errorf("empty name made %d requests", s.count())
	}
}

func TestCacheAndOffline(t *testing.T) {
	s := newServer(t)
	dir := t.TempDir()
	ctx := context.Background()
	vrefs := []model.PackageRef{ref("npm:express@4.19.2"), ref("npm:express@99.99.99")}
	frefs := []model.PackageRef{ref("npm:request@2.88.2")}

	online := newClient(t, s, dir, false)
	wantVersions, err := online.Versions(ctx, vrefs)
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	wantFindings, err := online.Findings(ctx, frefs)
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	wantSimilar, err := online.SimilarNames(ctx, model.NPM, "jost")
	if err != nil {
		t.Fatalf("SimilarNames: %v", err)
	}
	warm := s.count()
	if warm != 3 {
		t.Fatalf("warming made %d requests, want 3", warm)
	}

	// The same questions again are answered from the cache, online or not.
	for _, offline := range []bool{false, true} {
		c := newClient(t, s, dir, offline)
		gotVersions, err := c.Versions(ctx, vrefs)
		if err != nil || !reflect.DeepEqual(gotVersions, wantVersions) {
			t.Errorf("offline=%v Versions = %+v, %v; want %+v", offline, gotVersions, err, wantVersions)
		}
		gotFindings, err := c.Findings(ctx, frefs)
		if err != nil || !reflect.DeepEqual(gotFindings, wantFindings) {
			t.Errorf("offline=%v Findings = %+v, %v; want %+v", offline, gotFindings, err, wantFindings)
		}
		gotSimilar, err := c.SimilarNames(ctx, model.NPM, "jost")
		if err != nil || !reflect.DeepEqual(gotSimilar, wantSimilar) {
			t.Errorf("offline=%v SimilarNames = %+v, %v; want %+v", offline, gotSimilar, err, wantSimilar)
		}
		if n := s.count(); n != warm {
			t.Errorf("offline=%v made %d new requests", offline, n-warm)
		}
	}

	// A different body is a different cache entry, so offline it is a miss.
	cold := newClient(t, s, t.TempDir(), true)
	if _, err := cold.Versions(ctx, vrefs); !errors.Is(err, httpcache.ErrOffline) {
		t.Errorf("cold offline Versions error = %v, want ErrOffline", err)
	}
	if _, err := cold.Findings(ctx, frefs); !errors.Is(err, httpcache.ErrOffline) {
		t.Errorf("cold offline Findings error = %v, want ErrOffline", err)
	}
	if _, err := cold.SimilarNames(ctx, model.NPM, "jost"); !errors.Is(err, httpcache.ErrOffline) {
		t.Errorf("cold offline SimilarNames error = %v, want ErrOffline", err)
	}
	warmed := newClient(t, s, dir, true)
	if _, err := warmed.Versions(ctx, []model.PackageRef{ref("npm:express@4.18.0")}); !errors.Is(err, httpcache.ErrOffline) {
		t.Errorf("offline Versions with an unseen body error = %v, want ErrOffline", err)
	}
	if n := s.count(); n != warm {
		t.Errorf("offline clients made %d requests", n-warm)
	}
}

// TestCacheTTLs pins the documented lifetimes with a settable clock: batch
// answers six hours, similarly named packages a day. The durations are spelled
// out rather than taken from the constants, so a wrong constant fails here.
func TestCacheTTLs(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	start := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	now := start
	c := newClientAt(t, s, t.TempDir(), false, func() time.Time { return now }, nil)
	vrefs := []model.PackageRef{ref("npm:express@4.19.2")}
	frefs := []model.PackageRef{ref("npm:request@2.88.2")}
	call := func() {
		t.Helper()
		if _, err := c.Versions(ctx, vrefs); err != nil {
			t.Fatalf("Versions: %v", err)
		}
		if _, err := c.Findings(ctx, frefs); err != nil {
			t.Fatalf("Findings: %v", err)
		}
		if _, err := c.SimilarNames(ctx, model.NPM, "jost"); err != nil {
			t.Fatalf("SimilarNames: %v", err)
		}
	}
	const (
		versions = "POST /versionbatch"
		findings = "POST /findingsbatch"
		similar  = "GET /systems/NPM/packages/jost:similarlyNamedPackages"
	)
	steps := []struct {
		name                                    string
		at                                      time.Duration
		wantVersions, wantFindings, wantSimilar int
	}{
		{"first call", 0, 1, 1, 1},
		{"just under six hours", 6*time.Hour - time.Second, 1, 1, 1},
		{"just over six hours", 6*time.Hour + time.Second, 2, 2, 1},
		{"just under a day", 24*time.Hour - time.Second, 3, 3, 1},
		{"just over a day", 24*time.Hour + time.Second, 3, 3, 2},
	}
	for _, step := range steps {
		now = start.Add(step.at)
		call()
		got := []int{s.countOf(versions), s.countOf(findings), s.countOf(similar)}
		want := []int{step.wantVersions, step.wantFindings, step.wantSimilar}
		if !slices.Equal(got, want) {
			t.Errorf("%s: requests (versionbatch, findingsbatch, similar) = %v, want %v", step.name, got, want)
		}
	}
}

func TestBatchErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		check   func(t *testing.T, err error)
		wantErr string
	}{
		{
			name:   "client error",
			status: http.StatusBadRequest,
			body:   `{"error":"bad request"}`,
			check: func(t *testing.T, err error) {
				var se *httpcache.StatusError
				if !errors.As(err, &se) || se.StatusCode != http.StatusBadRequest || se.Method != http.MethodPost {
					t.Errorf("error = %v, want a POST StatusError 400", err)
				}
			},
		},
		{
			name:    "not found",
			status:  http.StatusNotFound,
			body:    "no such method",
			wantErr: "unexpected status 404",
		},
		{
			name:    "malformed json",
			status:  http.StatusOK,
			body:    `{"responses":[`,
			wantErr: "decoding versionbatch response",
		},
		{
			name:    "malformed entry",
			status:  http.StatusOK,
			body:    `{"responses":[42]}`,
			wantErr: "decoding versionbatch response 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newServer(t)
			s.respond = func(string, batchRequest) (int, []byte) { return tt.status, []byte(tt.body) }
			c := newClient(t, s, t.TempDir(), false)
			_, err := c.Versions(context.Background(), generatedRefs(1))
			if err == nil {
				t.Fatal("Versions succeeded")
			}
			if tt.check != nil {
				tt.check(t, err)
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestSystem(t *testing.T) {
	tests := []struct {
		eco  model.Ecosystem
		want string
	}{
		{model.NPM, "NPM"},
		{model.PyPI, "PYPI"},
		{model.Cargo, "CARGO"},
		{model.Deno, ""},
		{model.JSR, ""},
		{model.Ecosystem("maven"), ""},
	}
	for _, tt := range tests {
		if got := System(tt.eco); got != tt.want {
			t.Errorf("System(%q) = %q, want %q", tt.eco, got, tt.want)
		}
	}
}

func TestWithBaseURLTrimsSlash(t *testing.T) {
	c := New(nil, WithBaseURL("http://example.invalid/v3alpha///"))
	if c.base != "http://example.invalid/v3alpha" {
		t.Errorf("base = %q", c.base)
	}
	if c.batchSize != BatchSize {
		t.Errorf("batchSize = %d, want %d", c.batchSize, BatchSize)
	}
}
