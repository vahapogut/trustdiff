package jsr

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// response is one canned answer of the fixture server.
type response struct {
	status int
	body   []byte
}

// routes maps a request path to its answers. A versions path has one answer per
// page, in page order; every other path has exactly one. The fixture server
// serves both jsr.io and api.jsr.io from the same handler because their paths
// cannot collide: the registry API's start with "/@" and the management API's
// with "/scopes/".
type routes map[string][]response

// fixtureRoutes is what the recorded fixtures answer. Anything else answers like
// the real hosts do, which newServer takes care of.
func fixtureRoutes(t *testing.T) routes {
	t.Helper()
	single := map[string]string{
		"/@std/fs/meta.json":                                      "std-fs-meta.json",
		"/scopes/std/packages/fs":                                 "std-fs-package.json",
		"/scopes/std/packages/fs/versions/1.0.24/dependencies":    "std-fs-1.0.24-dependencies.json",
		"/scopes/std/packages/fs/downloads":                       "std-fs-downloads.json",
		"/scopes/std/members":                                     "std-members.json",
		"/@luca/cases/meta.json":                                  "luca-cases-meta.json",
		"/scopes/luca/packages/cases":                             "luca-cases-package.json",
		"/scopes/luca/packages/cases/versions/1.0.0/dependencies": "luca-cases-1.0.0-dependencies.json",
		"/@luca/flag/meta.json":                                   "luca-flag-meta.json",
		"/scopes/luca/packages/flag":                              "luca-flag-package.json",
		"/scopes/luca/members":                                    "luca-members.json",
		"/@oak/oak/meta.json":                                     "oak-oak-meta.json",
		"/scopes/oak/packages/oak":                                "oak-oak-package.json",
		"/scopes/oak/packages/oak/versions/17.2.0/dependencies":   "oak-oak-17.2.0-dependencies.json",
		"/@hono/hono/meta.json":                                   "hono-hono-meta.json",
		"/scopes/hono/packages/hono":                              "hono-hono-package.json",
	}
	paged := map[string][]string{
		"/scopes/std/packages/fs/versions":     {"std-fs-versions.json"},
		"/scopes/luca/packages/cases/versions": {"luca-cases-versions.json"},
		"/scopes/luca/packages/flag/versions":  {"luca-flag-versions.json"},
		"/scopes/oak/packages/oak/versions":    {"oak-oak-versions.json"},
		"/scopes/hono/packages/hono/versions":  {"hono-hono-versions-page1.json", "hono-hono-versions-page2.json"},
	}
	out := make(routes, len(single)+len(paged))
	for path, name := range single {
		out[path] = []response{{status: http.StatusOK, body: fixture(t, name)}}
	}
	for path, names := range paged {
		pages := make([]response, 0, len(names))
		for _, name := range names {
			pages = append(pages, response{status: http.StatusOK, body: fixture(t, name)})
		}
		out[path] = pages
	}
	return out
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

// server serves routes and counts the requests per URI, so a test can assert
// that both pages of a paginated list were fetched.
type server struct {
	*httptest.Server
	mu     sync.Mutex
	hits   map[string]int
	routes routes
}

func newServer(t *testing.T, r routes) *server {
	t.Helper()
	s := &server{hits: map[string]int{}, routes: r}
	// The two hosts answer a 404 differently, and api.jsr.io says in its body
	// which of the three things was not found. The fixture server reproduces that
	// so the client is never accidentally written against one shape.
	registryNotFound := fixture(t, "meta-not-found.txt")
	notFoundBodies := []struct {
		match func(path string) bool
		body  []byte
	}{
		{match: func(p string) bool { return strings.HasSuffix(p, "/members") }, body: fixture(t, "scope-not-found.json")},
		{match: func(p string) bool { return strings.Contains(p, "/versions/") }, body: fixture(t, "version-not-found.json")},
	}
	packageNotFound := fixture(t, "package-not-found.json")
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.mu.Lock()
		s.hits[req.URL.RequestURI()]++
		s.mu.Unlock()
		if ua := req.Header.Get("User-Agent"); !strings.HasPrefix(ua, "trustdiff") {
			t.Errorf("request %s without the identifying User-Agent, got %q", req.URL.Path, ua)
		}
		// The registry API refuses to serve data to a caller that asks for HTML,
		// so the client must never send an Accept header that allows it.
		if accept := req.Header.Get("Accept"); strings.Contains(accept, "text/html") {
			t.Errorf("request %s with Accept %q, which asks the registry for a rendered page", req.URL.Path, accept)
		}
		pages, ok := s.routes[req.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			if strings.HasPrefix(req.URL.Path, "/@") {
				_, _ = w.Write(registryNotFound)
				return
			}
			for _, nf := range notFoundBodies {
				if nf.match(req.URL.Path) {
					_, _ = w.Write(nf.body)
					return
				}
			}
			_, _ = w.Write(packageNotFound)
			return
		}
		index := 0
		if p := req.URL.Query().Get("page"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			index = n - 1
		}
		if index >= len(pages) {
			// What the real endpoint answers past the last page: the envelope
			// with no items.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[],"total":0}`))
			return
		}
		w.WriteHeader(pages[index].status)
		_, _ = w.Write(pages[index].body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) requests(uri string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[uri]
}

// newClient wires a client to the fixture server through a fresh cache
// directory. Both bases point at the one server, as explained on routes.
func newClient(t *testing.T, srv *server) *Client {
	t.Helper()
	h, err := httpcache.New(httpcache.Options{
		Dir:       t.TempDir(),
		UserAgent: "trustdiff/test (+https://github.com/vahapogut/trustdiff)",
		Retries:   -1,
	})
	if err != nil {
		t.Fatalf("httpcache.New: %v", err)
	}
	return New(h, WithRegistryBase(srv.URL), WithAPIBase(srv.URL))
}

func fixtureClient(t *testing.T) (*Client, *server) {
	t.Helper()
	srv := newServer(t, fixtureRoutes(t))
	return newClient(t, srv), srv
}

// clientWithout serves every fixture except the named paths, which answer 404,
// so a test can see what the client does when one endpoint is unavailable.
func clientWithout(t *testing.T, paths ...string) (*Client, *server) {
	t.Helper()
	r := fixtureRoutes(t)
	for _, p := range paths {
		delete(r, p)
	}
	srv := newServer(t, r)
	return newClient(t, srv), srv
}

// clientWithBody serves one path with a body of the test's choosing.
func clientWithBody(t *testing.T, path string, body []byte) (*Client, *server) {
	t.Helper()
	r := fixtureRoutes(t)
	r[path] = []response{{status: http.StatusOK, body: body}}
	srv := newServer(t, r)
	return newClient(t, srv), srv
}

func at(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parsing time %q: %v", s, err)
	}
	return parsed
}

func jsrRef(name, ver string) model.PackageRef {
	return model.PackageRef{Ecosystem: model.JSR, Name: name, Version: ver}
}

// find returns one version of a list, or fails the test.
func find(t *testing.T, list *registry.VersionList, ver string) *model.VersionInfo {
	t.Helper()
	got := registry.Find(list, ver)
	if got == nil {
		t.Fatalf("version %s missing from the list of %s", ver, list.Name)
	}
	return got
}

// TestVersionsPackageFields checks what the client reads for a package as a
// whole from meta.json and from the management API's package record.
func TestVersionsPackageFields(t *testing.T) {
	tests := []struct {
		name       string
		ask        string
		wantName   string
		wantLatest string
		wantCount  int
		created    string
		modified   string
		first      string
		last       string
	}{
		{
			name:       "scoped package with many versions",
			ask:        "@std/fs",
			wantName:   "@std/fs",
			wantLatest: "1.0.24",
			wantCount:  69,
			created:    "2023-12-22T03:19:20.157401Z",
			modified:   "2024-03-13T02:23:41.070982Z",
			first:      "0.196.0",
			last:       "1.0.24",
		},
		{
			name:       "package with a single version",
			ask:        "@luca/cases",
			wantName:   "@luca/cases",
			wantLatest: "1.0.0",
			wantCount:  1,
			created:    "2024-03-06T12:28:36.287162Z",
			modified:   "2024-03-06T12:30:42.072795Z",
			first:      "1.0.0",
			last:       "1.0.0",
		},
		{
			name:       "package whose meta.json predates the createdAt field",
			ask:        "@luca/flag",
			wantName:   "@luca/flag",
			wantLatest: "1.0.1",
			wantCount:  2,
			created:    "2023-12-14T23:05:13.518606Z",
			modified:   "2024-05-03T15:20:30.960886Z",
			first:      "1.0.0",
			last:       "1.0.1",
		},
		{
			name:       "package with npm dependencies",
			ask:        "@oak/oak",
			wantName:   "@oak/oak",
			wantLatest: "17.2.0",
			wantCount:  32,
			created:    "2024-01-11T06:10:03.496216Z",
			modified:   "2024-03-01T04:23:01.583567Z",
			first:      "12.6.2",
			last:       "17.2.0",
		},
	}
	client, _ := fixtureClient(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := client.Versions(context.Background(), tt.ask)
			if err != nil {
				t.Fatalf("Versions(%s): %v", tt.ask, err)
			}
			if list.Ecosystem != model.JSR {
				t.Errorf("ecosystem = %s, want %s", list.Ecosystem, model.JSR)
			}
			if list.Name != tt.wantName {
				t.Errorf("name = %q, want %q", list.Name, tt.wantName)
			}
			if list.Latest != tt.wantLatest {
				t.Errorf("latest = %q, want %q", list.Latest, tt.wantLatest)
			}
			if len(list.Versions) != tt.wantCount {
				t.Errorf("version count = %d, want %d", len(list.Versions), tt.wantCount)
			}
			if want := at(t, tt.created); !list.Created.Equal(want) {
				t.Errorf("created = %s, want %s", list.Created, want)
			}
			if want := at(t, tt.modified); !list.Modified.Equal(want) {
				t.Errorf("modified = %s, want %s", list.Modified, want)
			}
			if list.Deprecated != "" {
				t.Errorf("deprecated = %q, want empty for a package that is not archived", list.Deprecated)
			}
			// Maintainers cost a request of their own; Owners is the method for them.
			if len(list.Maintainers) != 0 {
				t.Errorf("maintainers = %v, want none on the version list", list.Maintainers)
			}
			if got := list.Versions[0].Ref.Version; got != tt.first {
				t.Errorf("first version = %q, want %q", got, tt.first)
			}
			if got := list.Versions[len(list.Versions)-1].Ref.Version; got != tt.last {
				t.Errorf("last version = %q, want %q", got, tt.last)
			}
			for _, v := range list.Versions {
				if v.Ref.Ecosystem != model.JSR || v.Ref.Name != tt.wantName {
					t.Fatalf("version %s carries ref %s, want the package's own scoped name", v.Ref.Version, v.Ref)
				}
			}
		})
	}
}

// TestVersionsPerVersionFields checks the facts the client maps onto one
// version: the publish time and where it came from, the publisher, the yank
// state, the prerelease flag and the provenance.
func TestVersionsPerVersionFields(t *testing.T) {
	tests := []struct {
		name            string
		pkg             string
		version         string
		published       string
		publisher       string
		yanked          bool
		prerelease      bool
		provenance      model.ProvenanceKind
		verified        bool
		wantNoPublisher bool
	}{
		{
			// meta.json carries the publish time for this package, and the
			// management API carries a Rekor log id, which is an attestation.
			name:       "attested release",
			pkg:        "@std/fs",
			version:    "1.0.24",
			published:  "2026-05-26T09:57:22.811747Z",
			publisher:  "Bartek Iwańczuk",
			provenance: model.ProvenanceAttestation,
			verified:   true,
		},
		{
			// Yanked in meta.json, and published before JSR wrote provenance.
			name:       "yanked release without provenance",
			pkg:        "@std/fs",
			version:    "0.229.0",
			published:  "2024-04-29T17:22:46.657031Z",
			publisher:  "Luca Casonato",
			yanked:     true,
			provenance: model.ProvenanceNone,
		},
		{
			name:       "the second yanked release",
			pkg:        "@std/fs",
			version:    "0.228.0",
			published:  "2024-04-29T16:05:08.013711Z",
			publisher:  "Luca Casonato",
			yanked:     true,
			provenance: model.ProvenanceNone,
		},
		{
			name:       "prerelease",
			pkg:        "@std/fs",
			version:    "1.0.0-rc.4",
			published:  "2024-07-09T06:17:08.026528Z",
			publisher:  "Yoshiya Hinosawa",
			prerelease: true,
			provenance: model.ProvenanceAttestation,
			verified:   true,
		},
		{
			// A release of the same package with no Rekor log id, which is what a
			// publish without the GitHub Actions integration leaves behind.
			name:       "release without provenance",
			pkg:        "@std/fs",
			version:    "1.0.12",
			published:  "2025-02-14T07:31:06.006132Z",
			publisher:  "Yoshiya Hinosawa",
			provenance: model.ProvenanceNone,
		},
		{
			// meta.json has no createdAt for this package at all, so the publish
			// time can only come from the management API's versions list.
			name:            "publish time from the management API alone",
			pkg:             "@luca/flag",
			version:         "1.0.1",
			published:       "2024-01-26T19:05:08.325363Z",
			provenance:      model.ProvenanceNone,
			wantNoPublisher: true,
		},
		{
			name:            "the older version of the same package",
			pkg:             "@luca/flag",
			version:         "1.0.0",
			published:       "2023-12-15T11:19:06.411796Z",
			provenance:      model.ProvenanceNone,
			wantNoPublisher: true,
		},
		{
			name:       "single version of a single-version package",
			pkg:        "@luca/cases",
			version:    "1.0.0",
			published:  "2024-03-06T12:30:12.551225Z",
			publisher:  "Luca Casonato",
			provenance: model.ProvenanceAttestation,
			verified:   true,
		},
	}
	client, _ := fixtureClient(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := client.Versions(context.Background(), tt.pkg)
			if err != nil {
				t.Fatalf("Versions(%s): %v", tt.pkg, err)
			}
			got := find(t, list, tt.version)
			if want := at(t, tt.published); !got.PublishedAt.Equal(want) {
				t.Errorf("published_at = %s, want %s", got.PublishedAt, want)
			}
			switch {
			case tt.wantNoPublisher:
				if got.Publisher != nil {
					t.Errorf("publisher = %v, want none for a version the registry records no user for", got.Publisher)
				}
			case got.Publisher == nil:
				t.Errorf("publisher = none, want %q", tt.publisher)
			case got.Publisher.Name != tt.publisher:
				t.Errorf("publisher = %q, want %q", got.Publisher.Name, tt.publisher)
			}
			if got.Yanked != tt.yanked {
				t.Errorf("yanked = %v, want %v", got.Yanked, tt.yanked)
			}
			if got.Prerelease != tt.prerelease {
				t.Errorf("prerelease = %v, want %v", got.Prerelease, tt.prerelease)
			}
			if got.Provenance.Kind != tt.provenance {
				t.Errorf("provenance kind = %q, want %q", got.Provenance.Kind, tt.provenance)
			}
			if got.Provenance.Verified != tt.verified {
				t.Errorf("provenance verified = %v, want %v", got.Provenance.Verified, tt.verified)
			}
			// JSR carries no workflow identity, no yank message, no package-level
			// digest and no weekly count per version, and none of those may be
			// invented from something else.
			if got.Provenance.Identity != "" {
				t.Errorf("provenance identity = %q, want empty: the API carries no workflow identity", got.Provenance.Identity)
			}
			if got.Deprecated != "" {
				t.Errorf("deprecated = %q, want empty: JSR records no yank message", got.Deprecated)
			}
			if got.Integrity != "" {
				t.Errorf("integrity = %q, want empty: JSR has no package-level digest", got.Integrity)
			}
			if got.WeeklyDownloads != -1 {
				t.Errorf("weekly downloads = %d, want -1: JSR has no weekly count per version", got.WeeklyDownloads)
			}
			// JSR has no install-time script mechanism, so an empty script map is
			// a fact and must not be reported as a facet that was not gathered.
			if got.HasInstallScript() {
				t.Errorf("scripts = %v, want none: JSR has no install-time scripts", got.Scripts)
			}
			if reason, ok := got.Unknown[model.FacetScripts]; ok {
				t.Errorf("scripts marked unknown (%q), want them recorded as absent", reason)
			}
			if len(got.Maintainers) != 0 {
				t.Errorf("maintainers = %v, want none: JSR records no maintainer set per version", got.Maintainers)
			}
		})
	}
}

// TestVersionsOrdering checks that the list is ascending by semantic version
// even though meta.json's versions object has no order of its own, and that
// prereleases sort before the release they lead up to.
func TestVersionsOrdering(t *testing.T) {
	client, _ := fixtureClient(t)
	list, err := client.Versions(context.Background(), "@std/fs")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	order := make([]string, len(list.Versions))
	for i, v := range list.Versions {
		order[i] = v.Ref.Version
	}
	want := []string{"0.229.3", "1.0.0-rc.1", "1.0.0-rc.2", "1.0.0-rc.3", "1.0.0-rc.4", "1.0.0-rc.5", "1.0.0-rc.6", "1.0.0", "1.0.1"}
	start := -1
	for i, v := range order {
		if v == want[0] {
			start = i
			break
		}
	}
	if start < 0 || start+len(want) > len(order) {
		t.Fatalf("version %s not found with room for its successors in %v", want[0], order)
	}
	for i, w := range want {
		if order[start+i] != w {
			t.Fatalf("order around the 1.0.0 release = %v, want %v", order[start:start+len(want)], want)
		}
	}
	// The order must not depend on the map iteration the client starts from.
	second, err := client.Versions(context.Background(), "@std/fs")
	if err != nil {
		t.Fatalf("Versions again: %v", err)
	}
	for i, v := range second.Versions {
		if v.Ref.Version != order[i] {
			t.Fatalf("a second call ordered the list differently at %d: %q then %q", i, order[i], v.Ref.Version)
		}
	}
}

// TestVersionsPagination checks that a package with more versions than one page
// holds is read completely, and that the pages are asked for by number.
func TestVersionsPagination(t *testing.T) {
	client, srv := fixtureClient(t)
	list, err := client.Versions(context.Background(), "@hono/hono")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(list.Versions) != 146 {
		t.Fatalf("version count = %d, want 146", len(list.Versions))
	}
	for _, uri := range []string{
		"/scopes/hono/packages/hono/versions?limit=100&page=1",
		"/scopes/hono/packages/hono/versions?limit=100&page=2",
	} {
		if srv.requests(uri) != 1 {
			t.Errorf("requests to %s = %d, want 1", uri, srv.requests(uri))
		}
	}
	if got := srv.requests("/scopes/hono/packages/hono/versions?limit=100&page=3"); got != 0 {
		t.Errorf("requests past the last page = %d, want 0: the total says when to stop", got)
	}
	// A version from each page must carry the publisher the second request
	// brought, which is what proves both pages were merged.
	first := find(t, list, "4.13.7")
	if first.Publisher == nil || first.Publisher.Name != "Yusuke Wada" {
		t.Errorf("publisher of 4.13.7 = %v, want Yusuke Wada from page 1", first.Publisher)
	}
	last := find(t, list, "4.4.0")
	if last.Publisher == nil || last.Publisher.Name != "Yusuke Wada" {
		t.Errorf("publisher of 4.4.0 = %v, want Yusuke Wada from page 2", last.Publisher)
	}
}

// TestVersionsWithoutManagementAPI checks the best-effort rule: meta.json alone
// still answers with the complete version set and the yank state, and every
// version names the provenance facet in Unknown instead of reporting "none".
func TestVersionsWithoutManagementAPI(t *testing.T) {
	client, _ := clientWithout(t,
		"/scopes/std/packages/fs/versions",
		"/scopes/std/packages/fs",
	)
	list, err := client.Versions(context.Background(), "@std/fs")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(list.Versions) != 69 {
		t.Fatalf("version count = %d, want 69 from meta.json alone", len(list.Versions))
	}
	if !list.Created.IsZero() || !list.Modified.IsZero() {
		t.Errorf("created/modified = %s/%s, want zero without the package record", list.Created, list.Modified)
	}
	v := find(t, list, "1.0.24")
	if v.Publisher != nil {
		t.Errorf("publisher = %v, want none without the management API", v.Publisher)
	}
	if v.Provenance.Kind != model.ProvenanceNone {
		t.Errorf("provenance kind = %q, want none", v.Provenance.Kind)
	}
	reason, ok := v.Unknown[model.FacetProvenance]
	if !ok {
		t.Fatal("provenance not marked unknown, so a check would read the zero value as a fact")
	}
	if !strings.Contains(reason, "jsr:") || !strings.Contains(reason, "@std/fs") {
		t.Errorf("reason = %q, want it to name what failed", reason)
	}
	// meta.json still carries the publish time and the yank state for this
	// package, so the checks that need them are not affected.
	if want := at(t, "2026-05-26T09:57:22.811747Z"); !v.PublishedAt.Equal(want) {
		t.Errorf("published_at = %s, want %s from meta.json", v.PublishedAt, want)
	}
	if yanked := find(t, list, "0.229.0"); !yanked.Yanked {
		t.Error("yanked flag lost when the management API was unavailable")
	}
}

// TestVersionsArchivedPackage checks that a package archived on JSR reports a
// package-level deprecation, since archival is a flag with no message of its own.
func TestVersionsArchivedPackage(t *testing.T) {
	body := editJSON(t, "luca-cases-package.json", func(doc map[string]any) {
		doc["isArchived"] = true
	})
	client, _ := clientWithBody(t, "/scopes/luca/packages/cases", body)
	list, err := client.Versions(context.Background(), "@luca/cases")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if list.Deprecated != archivedMessage {
		t.Errorf("deprecated = %q, want %q", list.Deprecated, archivedMessage)
	}
}

// TestVersionInfo checks the per-version detail, above all the dependency map:
// npm dependencies are left out, and a package imported from several sub-exports
// appears once.
func TestVersionInfo(t *testing.T) {
	tests := []struct {
		name     string
		ref      model.PackageRef
		wantDeps map[string]string
	}{
		{
			name: "dependencies deduplicated across sub-exports",
			ref:  jsrRef("@std/fs", "1.0.24"),
			wantDeps: map[string]string{
				"@std/internal": "^1.0.14",
				"@std/path":     "^1.1.5",
			},
		},
		{
			name: "npm dependencies excluded",
			ref:  jsrRef("@oak/oak", "17.2.0"),
			wantDeps: map[string]string{
				"@oak/commons":     "^1.0",
				"@std/assert":      "^1.0",
				"@std/bytes":       "^1.0",
				"@std/http":        "^1.0",
				"@std/media-types": "^1.0",
				"@std/path":        "^1.0",
			},
		},
		{
			name:     "no dependencies at all",
			ref:      jsrRef("@luca/cases", "1.0.0"),
			wantDeps: nil,
		},
	}
	client, _ := fixtureClient(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := client.VersionInfo(context.Background(), tt.ref)
			if err != nil {
				t.Fatalf("VersionInfo(%s): %v", tt.ref, err)
			}
			if info.Ref != tt.ref {
				t.Errorf("ref = %s, want %s", info.Ref, tt.ref)
			}
			if len(info.Dependencies) != len(tt.wantDeps) {
				t.Fatalf("dependencies = %v, want %v", info.Dependencies, tt.wantDeps)
			}
			for name, want := range tt.wantDeps {
				if got := info.Dependencies[name]; got != want {
					t.Errorf("dependency %s = %q, want %q", name, got, want)
				}
			}
			if len(info.OptionalDependencies) != 0 {
				t.Errorf("optional dependencies = %v, want none: JSR declares no optional kind", info.OptionalDependencies)
			}
			if _, ok := info.Unknown[model.FacetDependencies]; ok {
				t.Errorf("dependencies marked unknown although they were fetched: %v", info.Unknown)
			}
		})
	}
}

// TestVersionInfoDependenciesUnavailable checks that a version whose dependency
// list could not be fetched still comes back, with the facet named in Unknown so
// that only the dependency check is skipped.
func TestVersionInfoDependenciesUnavailable(t *testing.T) {
	client, _ := clientWithout(t, "/scopes/std/packages/fs/versions/1.0.24/dependencies")
	ref := jsrRef("@std/fs", "1.0.24")
	info, err := client.VersionInfo(context.Background(), ref)
	if err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	if len(info.Dependencies) != 0 {
		t.Errorf("dependencies = %v, want none", info.Dependencies)
	}
	reason, ok := info.Unknown[model.FacetDependencies]
	if !ok {
		t.Fatal("dependencies not marked unknown, so a check would read an empty map as a fact")
	}
	if !strings.Contains(reason, "@std/fs@1.0.24") {
		t.Errorf("reason = %q, want it to name the version that failed", reason)
	}
	// The rest of the version must still be there.
	if info.Publisher == nil || info.Publisher.Name != "Bartek Iwańczuk" {
		t.Errorf("publisher = %v, want it kept when only the dependencies failed", info.Publisher)
	}
	if info.Provenance.Kind != model.ProvenanceAttestation {
		t.Errorf("provenance kind = %q, want attestation", info.Provenance.Kind)
	}
}

// TestOwners checks the scope member set, which is what JSR has in place of
// package owners.
func TestOwners(t *testing.T) {
	tests := []struct {
		name string
		ask  string
		want []string
	}{
		{name: "several members", ask: "@std/fs", want: []string{"Leo Kettmeir", "Ryan Dahl"}},
		{name: "one member", ask: "@luca/cases", want: []string{"Luca Casonato"}},
		{name: "another package in the same scope", ask: "@luca/flag", want: []string{"Luca Casonato"}},
	}
	client, _ := fixtureClient(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owners, err := client.Owners(context.Background(), tt.ask)
			if err != nil {
				t.Fatalf("Owners(%s): %v", tt.ask, err)
			}
			if len(owners) != len(tt.want) {
				t.Fatalf("owners = %v, want %v", owners, tt.want)
			}
			for i, want := range tt.want {
				if owners[i].Name != want {
					t.Errorf("owner %d = %q, want %q", i, owners[i].Name, want)
				}
			}
		})
	}
}

// TestDownloads checks the weekly figure the client reduces the daily buckets to,
// and the two answers that are not a number.
func TestDownloads(t *testing.T) {
	t.Run("weekly total", func(t *testing.T) {
		client, _ := fixtureClient(t)
		got, err := client.Downloads(context.Background(), "@std/fs")
		if err != nil {
			t.Fatalf("Downloads: %v", err)
		}
		// The seven days ending at the newest bucket of the recorded answer
		// (2026-09-09): 88027 through the registry API and 11894 through the npm
		// compatibility layer.
		const want = 99921
		if got != want {
			t.Errorf("weekly downloads = %d, want %d", got, want)
		}
	})

	t.Run("no counts is unsupported", func(t *testing.T) {
		client, _ := clientWithBody(t, "/scopes/std/packages/fs/downloads", []byte(`{"total":[],"recentVersions":[]}`))
		_, err := client.Downloads(context.Background(), "@std/fs")
		if !errors.Is(err, registry.ErrUnsupported) {
			t.Errorf("error = %v, want ErrUnsupported", err)
		}
	})

	t.Run("unknown package is not found", func(t *testing.T) {
		client, _ := fixtureClient(t)
		_, err := client.Downloads(context.Background(), "@luca/no-such-package")
		if !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("error = %v, want ErrNotFound", err)
		}
	})
}

// TestNotFound covers everything that must be reported as registry.ErrNotFound:
// a package the registry does not serve, a version it does not list, and a name
// that could not be a JSR name at all, which no request could change.
func TestNotFound(t *testing.T) {
	client, srv := fixtureClient(t)
	ctx := context.Background()

	t.Run("unknown package", func(t *testing.T) {
		_, err := client.Versions(ctx, "@luca/no-such-package")
		if !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("error = %v, want ErrNotFound", err)
		}
	})

	t.Run("unknown version", func(t *testing.T) {
		_, err := client.VersionInfo(ctx, jsrRef("@luca/flag", "9.9.9"))
		if !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("error = %v, want ErrNotFound", err)
		}
		// meta.json is what says which versions exist, so no request may be sent
		// for the version itself.
		if got := srv.requests("/scopes/luca/packages/flag/versions/9.9.9/dependencies"); got != 0 {
			t.Errorf("requests for the unknown version = %d, want 0", got)
		}
	})

	t.Run("unknown scope", func(t *testing.T) {
		_, err := client.Owners(ctx, "@nosuchscope/anything")
		if !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("error = %v, want ErrNotFound", err)
		}
	})

	names := []struct {
		name string
		ask  string
	}{
		{name: "empty", ask: ""},
		{name: "no scope marker", ask: "flag"},
		{name: "no package part", ask: "@luca"},
		{name: "empty package part", ask: "@luca/"},
		{name: "empty scope", ask: "@/flag"},
		{name: "scope too short", ask: "@l/flag"},
		{name: "scope too long", ask: "@abcdefghijklmnopqrstu/flag"},
		{name: "package too short", ask: "@luca/f"},
		{name: "uppercase scope", ask: "@Luca/flag"},
		{name: "uppercase package", ask: "@luca/Flag"},
		{name: "underscore", ask: "@luca/my_flag"},
		{name: "dot", ask: "@luca/my.flag"},
		{name: "leading dash", ask: "@luca/-flag"},
		{name: "trailing dash", ask: "@luca/flag-"},
		{name: "double dash", ask: "@luca/my--flag"},
		{name: "leading digit in the scope", ask: "@1uca/flag"},
		{name: "nested slash", ask: "@luca/flag/extra"},
		{name: "path traversal", ask: "@luca/../etc"},
	}
	for _, tt := range names {
		t.Run("impossible name: "+tt.name, func(t *testing.T) {
			if _, err := client.Versions(ctx, tt.ask); !errors.Is(err, registry.ErrNotFound) {
				t.Errorf("Versions error = %v, want ErrNotFound", err)
			}
			if _, err := client.Owners(ctx, tt.ask); !errors.Is(err, registry.ErrNotFound) {
				t.Errorf("Owners error = %v, want ErrNotFound", err)
			}
			if _, err := client.Downloads(ctx, tt.ask); !errors.Is(err, registry.ErrNotFound) {
				t.Errorf("Downloads error = %v, want ErrNotFound", err)
			}
		})
	}
}

// TestVersionInfoArguments checks the two calls that are wrong before any
// request is made.
func TestVersionInfoArguments(t *testing.T) {
	client, _ := fixtureClient(t)
	t.Run("another ecosystem", func(t *testing.T) {
		_, err := client.VersionInfo(context.Background(), model.PackageRef{Ecosystem: model.NPM, Name: "hono", Version: "4.13.7"})
		if err == nil || !strings.Contains(err.Error(), "not a jsr ref") {
			t.Errorf("error = %v, want one saying the ref is not a jsr ref", err)
		}
	})
	t.Run("no version", func(t *testing.T) {
		_, err := client.VersionInfo(context.Background(), model.PackageRef{Ecosystem: model.JSR, Name: "@luca/flag"})
		if err == nil || !strings.Contains(err.Error(), "a version is required") {
			t.Errorf("error = %v, want one saying a version is required", err)
		}
	})
}

// TestMalformedResponses checks that every endpoint answering with something the
// client cannot read is reported and never panics. A management API answer that
// cannot be read is best effort and must not fail the call at all.
func TestMalformedResponses(t *testing.T) {
	ctx := context.Background()
	notJSON := []byte("<!doctype html><html><body>not json</body></html>")

	t.Run("meta.json is not json", func(t *testing.T) {
		client, _ := clientWithBody(t, "/@luca/flag/meta.json", notJSON)
		_, err := client.Versions(ctx, "@luca/flag")
		if err == nil || !strings.Contains(err.Error(), "decoding") {
			t.Errorf("error = %v, want a decoding error", err)
		}
	})

	t.Run("meta.json names no package", func(t *testing.T) {
		client, _ := clientWithBody(t, "/@luca/flag/meta.json", []byte(`{"latest":"1.0.1","versions":{"1.0.1":{}}}`))
		_, err := client.Versions(ctx, "@luca/flag")
		if err == nil || !strings.Contains(err.Error(), "names no package") {
			t.Errorf("error = %v, want one saying the document names no package", err)
		}
	})

	t.Run("meta.json versions is not an object", func(t *testing.T) {
		client, _ := clientWithBody(t, "/@luca/flag/meta.json", []byte(`{"scope":"luca","name":"flag","versions":["1.0.1"]}`))
		_, err := client.Versions(ctx, "@luca/flag")
		if err == nil || !strings.Contains(err.Error(), "decoding") {
			t.Errorf("error = %v, want a decoding error", err)
		}
	})

	t.Run("meta.json lists a version that is not a version", func(t *testing.T) {
		client, _ := clientWithBody(t, "/@luca/flag/meta.json",
			[]byte(`{"scope":"luca","name":"flag","latest":"1.0.1","versions":{"1.0.1":{},"not-a-version":{}}}`))
		list, err := client.Versions(ctx, "@luca/flag")
		if err != nil {
			t.Fatalf("Versions: %v", err)
		}
		if len(list.Versions) != 2 {
			t.Fatalf("version count = %d, want both entries kept", len(list.Versions))
		}
		// An unparsable version sorts in front and is neither a prerelease nor
		// dropped: a spelling nobody expected must not make a release vanish.
		if got := list.Versions[0].Ref.Version; got != "not-a-version" {
			t.Errorf("first version = %q, want the unparsable one in front", got)
		}
		if list.Versions[0].Prerelease {
			t.Error("an unparsable version was reported as a prerelease")
		}
	})

	t.Run("versions list is not json", func(t *testing.T) {
		client, _ := clientWithBody(t, "/scopes/luca/packages/flag/versions", notJSON)
		list, err := client.Versions(ctx, "@luca/flag")
		if err != nil {
			t.Fatalf("Versions: %v, want the list from meta.json alone", err)
		}
		v := find(t, list, "1.0.1")
		if _, ok := v.Unknown[model.FacetProvenance]; !ok {
			t.Error("provenance not marked unknown after an unreadable versions list")
		}
	})

	t.Run("package record is not json", func(t *testing.T) {
		client, _ := clientWithBody(t, "/scopes/luca/packages/flag", notJSON)
		list, err := client.Versions(ctx, "@luca/flag")
		if err != nil {
			t.Fatalf("Versions: %v, want the list without the package record", err)
		}
		if !list.Created.IsZero() {
			t.Errorf("created = %s, want zero", list.Created)
		}
		if len(list.Versions) != 2 {
			t.Errorf("version count = %d, want 2", len(list.Versions))
		}
	})

	t.Run("dependencies are not json", func(t *testing.T) {
		client, _ := clientWithBody(t, "/scopes/luca/packages/cases/versions/1.0.0/dependencies", notJSON)
		info, err := client.VersionInfo(ctx, jsrRef("@luca/cases", "1.0.0"))
		if err != nil {
			t.Fatalf("VersionInfo: %v, want the version without its dependencies", err)
		}
		if _, ok := info.Unknown[model.FacetDependencies]; !ok {
			t.Error("dependencies not marked unknown after an unreadable list")
		}
	})

	t.Run("members are not json", func(t *testing.T) {
		client, _ := clientWithBody(t, "/scopes/luca/members", notJSON)
		if _, err := client.Owners(ctx, "@luca/flag"); err == nil {
			t.Error("error = nil, want a decoding error")
		}
	})

	t.Run("downloads are not json", func(t *testing.T) {
		client, _ := clientWithBody(t, "/scopes/std/packages/fs/downloads", notJSON)
		if _, err := client.Downloads(ctx, "@std/fs"); err == nil {
			t.Error("error = nil, want a decoding error")
		}
	})

	t.Run("json with null in every nullable field", func(t *testing.T) {
		body := []byte(`{"items":[{"scope":"luca","package":"flag","version":"1.0.1","user":null,` +
			`"yanked":false,"usesNpm":false,"rekorLogId":null,"readmePath":null,` +
			`"createdAt":"2024-01-26T19:05:08.325363Z","updatedAt":"2024-02-28T12:23:44.543826Z"}],"total":1}`)
		client, _ := clientWithBody(t, "/scopes/luca/packages/flag/versions", body)
		list, err := client.Versions(ctx, "@luca/flag")
		if err != nil {
			t.Fatalf("Versions: %v", err)
		}
		v := find(t, list, "1.0.1")
		if v.Publisher != nil || v.Provenance.Kind != model.ProvenanceNone {
			t.Errorf("publisher = %v, provenance = %q, want neither", v.Publisher, v.Provenance.Kind)
		}
	})

	t.Run("versions list with an empty first page", func(t *testing.T) {
		client, _ := clientWithBody(t, "/scopes/luca/packages/flag/versions", []byte(`{"items":[],"total":2}`))
		list, err := client.Versions(ctx, "@luca/flag")
		if err != nil {
			t.Fatalf("Versions: %v", err)
		}
		if len(list.Versions) != 2 {
			t.Errorf("version count = %d, want 2 from meta.json", len(list.Versions))
		}
	})
}

// TestUnexpectedStatus checks that a status the client has no rule for is
// reported with the status in it rather than decoded as if it were data.
func TestUnexpectedStatus(t *testing.T) {
	r := fixtureRoutes(t)
	r["/@luca/flag/meta.json"] = []response{{status: http.StatusTeapot, body: []byte("{}")}}
	client := newClient(t, newServer(t, r))
	_, err := client.Versions(context.Background(), "@luca/flag")
	if err == nil || !strings.Contains(err.Error(), "unexpected status 418") {
		t.Errorf("error = %v, want one naming the status", err)
	}
}

// TestCaching checks that the documents a package needs are fetched once per
// client, which is what keeps a scan of many versions to a few requests.
func TestCaching(t *testing.T) {
	client, srv := fixtureClient(t)
	ctx := context.Background()
	for range 3 {
		if _, err := client.Versions(ctx, "@luca/cases"); err != nil {
			t.Fatalf("Versions: %v", err)
		}
		if _, err := client.VersionInfo(ctx, jsrRef("@luca/cases", "1.0.0")); err != nil {
			t.Fatalf("VersionInfo: %v", err)
		}
	}
	for _, uri := range []string{
		"/@luca/cases/meta.json",
		"/scopes/luca/packages/cases",
		"/scopes/luca/packages/cases/versions?limit=100&page=1",
		"/scopes/luca/packages/cases/versions/1.0.0/dependencies",
	} {
		if got := srv.requests(uri); got != 1 {
			t.Errorf("requests to %s = %d, want 1", uri, got)
		}
	}
}

// TestEndpointsNotRequested holds the client to the two endpoints the package
// comment says nothing in the model comes from. Both are recorded in testdata so
// their shape stays on the record, and neither may cost a request.
func TestEndpointsNotRequested(t *testing.T) {
	client, srv := fixtureClient(t)
	ctx := context.Background()
	if _, err := client.Versions(ctx, "@std/fs"); err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if _, err := client.VersionInfo(ctx, jsrRef("@std/fs", "1.0.24")); err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	for _, uri := range []string{
		"/@std/fs/1.0.24_meta.json",
		"/scopes/std/packages/fs/versions/1.0.24",
	} {
		if got := srv.requests(uri); got != 0 {
			t.Errorf("requests to %s = %d, want 0: nothing in the model comes from it", uri, got)
		}
	}
	// The downloads endpoint is only for Downloads, so a version lookup must not
	// pay for it either.
	if got := srv.requests("/scopes/std/packages/fs/downloads"); got != 0 {
		t.Errorf("requests to the downloads endpoint = %d, want 0 outside Downloads", got)
	}
	// Nor may a version lookup fetch the scope members: Owners is the method for them.
	if got := srv.requests("/scopes/std/members"); got != 0 {
		t.Errorf("requests to the members endpoint = %d, want 0 outside Owners", got)
	}
}

// editJSON decodes a JSON fixture, lets the test change it and re-encodes it.
func editJSON(t *testing.T, name string, edit func(doc map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, name), &doc); err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
	edit(doc)
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encoding %s: %v", name, err)
	}
	return data
}
