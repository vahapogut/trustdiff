package crates

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// fixtureRoutes maps the request paths of the recorded fixtures to their
// bodies. Anything else answers like the real hosts: the API with the recorded
// 404 body, static.crates.io with a bare 403.
func fixtureRoutes(t *testing.T) map[string]response {
	t.Helper()
	files := map[string]string{
		"/api/v1/crates/serde":                                "serde.json",
		"/api/v1/crates/serde/owners":                         "serde-owners.json",
		"/api/v1/crates/serde/1.0.229/dependencies":           "serde-1.0.229-dependencies.json",
		"/api/v1/crates/cfg-if":                               "cfg-if.json",
		"/api/v1/crates/memoffset":                            "memoffset.json",
		"/api/v1/crates/memoffset/0.9.1/dependencies":         "memoffset-0.9.1-dependencies.json",
		"/crates/memoffset/memoffset-0.9.1.crate":             "memoffset-0.9.1.crate",
		"/api/v1/crates/async-recursion":                      "async-recursion.json",
		"/api/v1/crates/async-recursion/1.1.1/dependencies":   "async-recursion-1.1.1-dependencies.json",
		"/crates/async-recursion/async-recursion-1.1.1.crate": "async-recursion-1.1.1.crate",
		"/api/v1/crates/paste":                                "paste.json",
		"/api/v1/crates/paste/1.0.15/dependencies":            "paste-1.0.15-dependencies.json",
		"/crates/paste/paste-1.0.15.crate":                    "paste-1.0.15.crate",
		"/api/v1/crates/rand_core":                            "rand_core.json",
		"/api/v1/crates/serde/9.9.9/dependencies":             "serde-9.9.9-dependencies.json",
		"/api/v1/crates/trustdiff-no-such-crate-zz":           "not-found.json",
		"/api/v1/crates/trustdiff-no-such-crate-zz/owners":    "not-found.json",
	}
	routes := make(map[string]response, len(files))
	for path, name := range files {
		status := http.StatusOK
		if name == "not-found.json" || strings.HasPrefix(name, "serde-9.9.9") {
			status = http.StatusNotFound
		}
		routes[path] = response{status: status, body: fixture(t, name)}
	}
	return routes
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

// server serves routes and counts the requests per path.
type server struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

func newServer(t *testing.T, routes map[string]response) *server {
	t.Helper()
	s := &server{hits: map[string]int{}}
	notFound := fixture(t, "not-found.json")
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		s.mu.Unlock()
		if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "trustdiff") {
			t.Errorf("request %s without the identifying User-Agent, got %q", r.URL.Path, ua)
		}
		if resp, ok := routes[r.URL.Path]; ok {
			w.WriteHeader(resp.status)
			_, _ = w.Write(resp.body)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/crates/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(notFound)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) requests(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

// newClient wires a client to the fixture server through a fresh cache directory.
func newClient(t *testing.T, srv *server, dir string, offline bool) *Client {
	t.Helper()
	h, err := httpcache.New(httpcache.Options{
		Dir:       dir,
		Offline:   offline,
		UserAgent: "trustdiff/test (+https://github.com/vahapogut/trustdiff)",
		Retries:   -1,
	})
	if err != nil {
		t.Fatalf("httpcache.New: %v", err)
	}
	return New(h, WithAPIBase(srv.URL+"/api/v1/"), WithStaticBase(srv.URL+"/crates/"))
}

func fixtureClient(t *testing.T) (*Client, *server) {
	t.Helper()
	srv := newServer(t, fixtureRoutes(t))
	return newClient(t, srv, t.TempDir(), false), srv
}

// modifiedFixture decodes a JSON fixture, lets the test change it and re-encodes it.
func modifiedFixture(t *testing.T, name string, edit func(doc map[string]any)) []byte {
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

// setVersionField changes one field of one versions[] entry.
func setVersionField(t *testing.T, doc map[string]any, num, field string, value any) {
	t.Helper()
	versions, _ := doc["versions"].([]any)
	for _, v := range versions {
		entry, _ := v.(map[string]any)
		if entry["num"] == num {
			entry[field] = value
			return
		}
	}
	t.Fatalf("version %s not in the fixture", num)
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func cargoRef(name, ver string) model.PackageRef {
	return model.PackageRef{Ecosystem: model.Cargo, Name: name, Version: ver}
}

// versionWant lists the fields a test checks on one version of a list.
type versionWant struct {
	num         string
	publishedAt time.Time
	publisher   string // "" means nil
	prerelease  bool
	yanked      bool
	integrity   string
	provenance  model.Provenance
}

func TestVersionsMapsTheCrateDocument(t *testing.T) {
	tests := []struct {
		name        string
		wantLatest  string
		wantCreated time.Time
		wantCount   int
		versions    []versionWant
	}{
		{
			name:        "serde",
			wantLatest:  "1.0.229",
			wantCreated: at("2014-12-05T20:20:39.487502Z"),
			wantCount:   316,
			versions: []versionWant{
				{
					num: "1.0.229", publishedAt: at("2026-07-18T23:05:13.266456Z"), publisher: "dtolnay",
					integrity:  "4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba",
					provenance: model.Provenance{Kind: model.ProvenanceNone},
				},
				{
					num: "1.0.95", publishedAt: at("2019-07-16T17:25:50.437072Z"), publisher: "dtolnay", yanked: true,
					integrity:  "e47a9fd6b2d2d2330b19b0b3e5248a170a5acd6356fd88c7bb30362ef9c70567",
					provenance: model.Provenance{Kind: model.ProvenanceNone},
				},
				{
					num: "1.0.172-alpha.0", publishedAt: at("2023-07-19T21:03:53.726968Z"), publisher: "dtolnay", prerelease: true,
					integrity:  "0c4d129c1e009c34022bfa546ef5f80a299e232db60e57fcdffed0882d736d16",
					provenance: model.Provenance{Kind: model.ProvenanceNone},
				},
				{
					// Published before crates.io recorded publishers: published_by is null.
					num: "0.0.0", publishedAt: at("2014-12-05T20:20:39.631482Z"),
					integrity:  "d1bb2d9926b9bd18e51fc8edd663e311ff3b1fb96c9d4689854f8686f7c6c216",
					provenance: model.Provenance{Kind: model.ProvenanceNone},
				},
			},
		},
		{
			name:        "cfg-if",
			wantLatest:  "1.0.4",
			wantCreated: at("2015-07-08T01:11:24.485040Z"),
			wantCount:   16,
			versions: []versionWant{
				{
					num: "1.0.2", publishedAt: at("2025-08-19T19:09:07.077988Z"), publisher: "rust-lang-owner", yanked: true,
					integrity:  "9aeec81361cbe5564f44e79538fc112002f70a448966f9160591c2bd5706dfad",
					provenance: model.Provenance{Kind: model.ProvenanceNone},
				},
			},
		},
		{
			name:       "rand_core",
			wantLatest: "0.10.1",
			wantCount:  42,
			versions: []versionWant{
				{
					// Trusted publishing: trustpub_data present and published_by null.
					num: "0.10.1", publishedAt: at("2026-04-13T15:26:43.049921Z"),
					integrity:  "63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69",
					provenance: model.Provenance{Kind: model.ProvenanceTrustedPublisher, Verified: true, Identity: "github:rust-random/rand_core"},
				},
				{
					num: "0.10.0-rc-6", prerelease: true,
					provenance: model.Provenance{Kind: model.ProvenanceTrustedPublisher, Verified: true, Identity: "github:rust-random/rand_core"},
				},
				{
					// A token publish after the crate moved to trusted publishing.
					num: "0.4.3", publishedAt: at("2026-09-02T07:50:31.835434Z"), publisher: "dhardy",
					integrity:  "0e5937858e6fd18cd595d558f90bb5de3b72ae23f9e3763af0e805949b04ef60",
					provenance: model.Provenance{Kind: model.ProvenanceNone},
				},
				{num: "0.6.1", publisher: "dhardy", yanked: true, provenance: model.Provenance{Kind: model.ProvenanceNone}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := fixtureClient(t)
			list, err := c.Versions(context.Background(), tt.name)
			if err != nil {
				t.Fatalf("Versions: %v", err)
			}
			if list.Ecosystem != model.Cargo || list.Name != tt.name {
				t.Errorf("list identity = %s:%s, want cargo:%s", list.Ecosystem, list.Name, tt.name)
			}
			if list.Latest != tt.wantLatest {
				t.Errorf("Latest = %q, want %q", list.Latest, tt.wantLatest)
			}
			if !tt.wantCreated.IsZero() && !list.Created.Equal(tt.wantCreated) {
				t.Errorf("Created = %v, want %v", list.Created, tt.wantCreated)
			}
			if list.Modified.IsZero() {
				t.Errorf("Modified is zero, want crate.updated_at")
			}
			if len(list.Versions) != tt.wantCount {
				t.Fatalf("len(Versions) = %d, want %d", len(list.Versions), tt.wantCount)
			}
			for _, want := range tt.versions {
				got := registry.Find(list, want.num)
				if got == nil {
					t.Errorf("version %s missing", want.num)
					continue
				}
				checkVersion(t, got, want)
			}
		})
	}
}

func checkVersion(t *testing.T, got *model.VersionInfo, want versionWant) { //nolint:gocritic // the expectation is a literal at every call site; by value reads better
	t.Helper()
	if got.Ref.Ecosystem != model.Cargo || got.Ref.Version != want.num {
		t.Errorf("%s: Ref = %v", want.num, got.Ref)
	}
	if !want.publishedAt.IsZero() && !got.PublishedAt.Equal(want.publishedAt) {
		t.Errorf("%s: PublishedAt = %v, want %v", want.num, got.PublishedAt, want.publishedAt)
	}
	switch {
	case want.publisher == "" && got.Publisher != nil:
		t.Errorf("%s: Publisher = %+v, want nil", want.num, got.Publisher)
	case want.publisher != "" && (got.Publisher == nil || got.Publisher.Name != want.publisher):
		t.Errorf("%s: Publisher = %+v, want %q", want.num, got.Publisher, want.publisher)
	}
	if got.Prerelease != want.prerelease {
		t.Errorf("%s: Prerelease = %v, want %v", want.num, got.Prerelease, want.prerelease)
	}
	if got.Yanked != want.yanked {
		t.Errorf("%s: Yanked = %v, want %v", want.num, got.Yanked, want.yanked)
	}
	if want.integrity != "" && got.Integrity != want.integrity {
		t.Errorf("%s: Integrity = %q, want %q", want.num, got.Integrity, want.integrity)
	}
	if got.Provenance != want.provenance {
		t.Errorf("%s: Provenance = %+v, want %+v", want.num, got.Provenance, want.provenance)
	}
	if got.WeeklyDownloads != -1 {
		t.Errorf("%s: WeeklyDownloads = %d, want -1 (unknown per version)", want.num, got.WeeklyDownloads)
	}
	if got.Scripts != nil || got.Dependencies != nil {
		t.Errorf("%s: Versions must not fill Scripts or Dependencies, got %v / %v", want.num, got.Scripts, got.Dependencies)
	}
}

func TestVersionsYankMessageBecomesDeprecated(t *testing.T) {
	routes := fixtureRoutes(t)
	routes["/api/v1/crates/cfg-if"] = response{status: http.StatusOK, body: modifiedFixture(t, "cfg-if.json", func(doc map[string]any) {
		setVersionField(t, doc, "1.0.2", "yank_message", "breaks the MSRV")
		setVersionField(t, doc, "1.0.3", "yank_message", "not yanked, message ignored")
	})}
	c := newClient(t, newServer(t, routes), t.TempDir(), false)
	list, err := c.Versions(context.Background(), "cfg-if")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if got := registry.Find(list, "1.0.2").Deprecated; got != "breaks the MSRV" {
		t.Errorf("yanked 1.0.2 Deprecated = %q, want the yank message", got)
	}
	if got := registry.Find(list, "1.0.3").Deprecated; got != "" {
		t.Errorf("unyanked 1.0.3 Deprecated = %q, want empty", got)
	}
}

func TestVersionsNotFoundAndInvalidNames(t *testing.T) {
	tests := []struct {
		name         string
		wantRequests int
	}{
		{name: "trustdiff-no-such-crate-zz", wantRequests: 1},
		{name: "", wantRequests: 0},
		{name: "../serde", wantRequests: 0},
		{name: "serde json", wantRequests: 0},
		{name: "-leading-dash", wantRequests: 0},
		{name: "with/slash", wantRequests: 0},
		{name: strings.Repeat("a", 65), wantRequests: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, srv := fixtureClient(t)
			list, err := c.Versions(context.Background(), tt.name)
			if !errors.Is(err, registry.ErrNotFound) {
				t.Fatalf("Versions(%q) = %v, %v; want ErrNotFound", tt.name, list, err)
			}
			if list != nil {
				t.Errorf("list = %v, want nil", list)
			}
			var total int
			srv.mu.Lock()
			for _, n := range srv.hits {
				total += n
			}
			srv.mu.Unlock()
			if total != tt.wantRequests {
				t.Errorf("%d requests, want %d", total, tt.wantRequests)
			}
		})
	}
}

func TestVersionsCachesTheCrateDocument(t *testing.T) {
	c, srv := fixtureClient(t)
	for range 3 {
		if _, err := c.Versions(context.Background(), "serde"); err != nil {
			t.Fatalf("Versions: %v", err)
		}
	}
	if _, err := c.Downloads(context.Background(), "serde"); err != nil {
		t.Fatalf("Downloads: %v", err)
	}
	if n := srv.requests("/api/v1/crates/serde"); n != 1 {
		t.Errorf("crate document fetched %d times, want 1 (cached for an hour)", n)
	}
}

func TestOwners(t *testing.T) {
	tests := []struct {
		name    string
		want    []model.Publisher
		wantErr error
	}{
		{name: "serde", want: []model.Publisher{{Name: "dtolnay"}, {Name: "github:serde-rs:publish"}}},
		{name: "trustdiff-no-such-crate-zz", wantErr: registry.ErrNotFound},
		{name: "bad name", wantErr: registry.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := fixtureClient(t)
			got, err := c.Owners(context.Background(), tt.name)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Owners = %v, %v; want error %v", got, err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Owners = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Owners[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDownloadsIsTheNinetyDayTotalPerWeek(t *testing.T) {
	tests := []struct {
		name    string
		routes  func(map[string]response)
		want    int64
		wantErr error
	}{
		{name: "serde", want: 297018728 / 13},
		{name: "memoffset", want: 118765150 / 13},
		{
			name: "cfg-if",
			routes: func(r map[string]response) {
				r["/api/v1/crates/cfg-if"] = response{status: http.StatusOK, body: modifiedFixture(t, "cfg-if.json", func(doc map[string]any) {
					doc["crate"].(map[string]any)["recent_downloads"] = nil
				})}
			},
			wantErr: registry.ErrUnsupported,
		},
		{name: "trustdiff-no-such-crate-zz", wantErr: registry.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := fixtureRoutes(t)
			if tt.routes != nil {
				tt.routes(routes)
			}
			c := newClient(t, newServer(t, routes), t.TempDir(), false)
			got, err := c.Downloads(context.Background(), tt.name)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Downloads = %d, %v; want error %v", got, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Downloads = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestVersionInfo(t *testing.T) {
	tests := []struct {
		ref       model.PackageRef
		wantDeps  map[string]string
		wantS     map[string]string
		publisher string
		// wantErr is checked with errors.Is; wantInfo says whether a value comes with it.
		wantErr  error
		wantInfo bool
	}{
		{
			// No archive fixture: the static host answers 403 like S3 does for a
			// missing file, so the metadata comes back with ErrNotInspected.
			ref:       cargoRef("serde", "1.0.229"),
			wantDeps:  map[string]string{"serde_core": "=1.0.229", "serde_derive": "^1"},
			publisher: "dtolnay",
			wantErr:   ErrNotInspected,
			wantInfo:  true,
		},
		{
			// build.rs in the archive, no build key in the normalized manifest;
			// the build dependency autocfg and the dev dependency doc-comment are excluded.
			ref:       cargoRef("memoffset", "0.9.1"),
			wantS:     map[string]string{ScriptBuild: "build script runs at compile time"},
			publisher: "Gilnaa",
			wantInfo:  true,
		},
		{
			ref:       cargoRef("async-recursion", "1.1.1"),
			wantDeps:  map[string]string{"proc-macro2": "^1.0", "quote": "^1.0", "syn": "^2.0"},
			wantS:     map[string]string{ScriptProcMacro: "procedural macro runs at compile time"},
			publisher: "dcchut",
			wantInfo:  true,
		},
		{
			ref: cargoRef("paste", "1.0.15"),
			wantS: map[string]string{
				ScriptBuild:     "build script runs at compile time",
				ScriptProcMacro: "procedural macro runs at compile time",
			},
			publisher: "dtolnay",
			wantInfo:  true,
		},
		{ref: cargoRef("serde", "9.9.9"), wantErr: registry.ErrNotFound},
		{ref: cargoRef("trustdiff-no-such-crate-zz", "1.0.0"), wantErr: registry.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.ref.String(), func(t *testing.T) {
			c, _ := fixtureClient(t)
			info, err := c.VersionInfo(context.Background(), tt.ref)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VersionInfo = %+v, %v; want error %v", info, err, tt.wantErr)
			}
			if (info != nil) != tt.wantInfo {
				t.Fatalf("info = %+v, want present=%v", info, tt.wantInfo)
			}
			if info == nil {
				return
			}
			if info.Ref != tt.ref {
				t.Errorf("Ref = %v, want %v", info.Ref, tt.ref)
			}
			if info.Publisher == nil || info.Publisher.Name != tt.publisher {
				t.Errorf("Publisher = %+v, want %q", info.Publisher, tt.publisher)
			}
			if info.Integrity == "" || info.PublishedAt.IsZero() {
				t.Errorf("Integrity %q / PublishedAt %v not filled", info.Integrity, info.PublishedAt)
			}
			if !maps.Equal(info.Dependencies, tt.wantDeps) {
				t.Errorf("Dependencies = %v, want %v", info.Dependencies, tt.wantDeps)
			}
			if !maps.Equal(info.Scripts, tt.wantS) {
				t.Errorf("Scripts = %v, want %v", info.Scripts, tt.wantS)
			}
			if info.HasInstallScript() != (len(tt.wantS) > 0) {
				t.Errorf("HasInstallScript = %v", info.HasInstallScript())
			}
		})
	}
}

func TestVersionInfoRejectsBadRefs(t *testing.T) {
	tests := []model.PackageRef{
		{Ecosystem: model.Cargo, Name: "serde"},
		{Ecosystem: model.NPM, Name: "serde", Version: "1.0.229"},
	}
	for _, ref := range tests {
		t.Run(ref.String(), func(t *testing.T) {
			c, srv := fixtureClient(t)
			info, err := c.VersionInfo(context.Background(), ref)
			if err == nil || info != nil {
				t.Fatalf("VersionInfo = %+v, %v; want an error and no value", info, err)
			}
			if n := srv.requests("/api/v1/crates/serde"); n != 0 {
				t.Errorf("%d requests made for a ref that cannot be answered", n)
			}
		})
	}
}

func TestVersionInfoPrefersUntargetedAndRequiredDependencies(t *testing.T) {
	deps := `{"dependencies":[
		{"crate_id":"serde_derive","req":"=1.0.219","optional":false,"target":"cfg(any())","kind":"normal"},
		{"crate_id":"serde_derive","req":"^1","optional":true,"target":null,"kind":"normal"},
		{"crate_id":"libc","req":"^0.2","optional":true,"target":null,"kind":"normal"},
		{"crate_id":"libc","req":"^0.2.100","optional":false,"target":null,"kind":"normal"},
		{"crate_id":"winapi","req":"^0.3","optional":false,"target":"cfg(windows)","kind":"normal"},
		{"crate_id":"cc","req":"^1","optional":false,"target":null,"kind":"build"},
		{"crate_id":"trybuild","req":"^1","optional":false,"target":null,"kind":"dev"},
		{"crate_id":"odd","req":"^1","optional":false,"target":null,"kind":"unknown-kind"}
	]}`
	routes := fixtureRoutes(t)
	routes["/api/v1/crates/serde/1.0.229/dependencies"] = response{status: http.StatusOK, body: []byte(deps)}
	c := newClient(t, newServer(t, routes), t.TempDir(), false)
	info, err := c.VersionInfo(context.Background(), cargoRef("serde", "1.0.229"))
	if !errors.Is(err, ErrNotInspected) || info == nil {
		t.Fatalf("VersionInfo = %+v, %v", info, err)
	}
	want := map[string]string{"serde_derive": "^1", "libc": "^0.2.100", "winapi": "^0.3"}
	if !maps.Equal(info.Dependencies, want) {
		t.Errorf("Dependencies = %v, want %v", info.Dependencies, want)
	}
}

func TestVersionInfoDependenciesNotFound(t *testing.T) {
	// The crate document lists the version but the dependency endpoint does not:
	// the recorded 404 body is what crates.io answers for an unknown version.
	routes := fixtureRoutes(t)
	routes["/api/v1/crates/serde/1.0.229/dependencies"] = routes["/api/v1/crates/serde/9.9.9/dependencies"]
	c := newClient(t, newServer(t, routes), t.TempDir(), false)
	info, err := c.VersionInfo(context.Background(), cargoRef("serde", "1.0.229"))
	if !errors.Is(err, registry.ErrNotFound) || info != nil {
		t.Fatalf("VersionInfo = %+v, %v; want ErrNotFound and no value", info, err)
	}
}

func TestVersionInfoChecksumMismatchIsNeverInspected(t *testing.T) {
	routes := fixtureRoutes(t)
	tampered := append([]byte(nil), fixture(t, "paste-1.0.15.crate")...)
	tampered = append(tampered, 0)
	routes["/crates/paste/paste-1.0.15.crate"] = response{status: http.StatusOK, body: tampered}
	c := newClient(t, newServer(t, routes), t.TempDir(), false)
	info, err := c.VersionInfo(context.Background(), cargoRef("paste", "1.0.15"))
	if !errors.Is(err, ErrNotInspected) || !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("error = %v, want ErrNotInspected wrapping ErrChecksumMismatch", err)
	}
	if info == nil || info.Scripts != nil {
		t.Fatalf("info = %+v, want the metadata with empty Scripts", info)
	}
	if !strings.Contains(err.Error(), "57c0d7b74b563b49d38dae00a0c37d4d6de9b432382b2892f0574ddcae73fd0a") {
		t.Errorf("error should name the registry checksum: %v", err)
	}
}

func TestVersionInfoArchiveSizeCap(t *testing.T) {
	tests := []struct {
		name string
		// crateSize is what the crate document claims; maxArchive the client cap.
		crateSize    int64
		maxArchive   int64
		wantDownload bool
	}{
		{name: "metadata above the cap skips the download", crateSize: MaxArchiveBytes + 1, maxArchive: MaxArchiveBytes, wantDownload: false},
		{name: "body above the cap after download", crateSize: 50, maxArchive: 100, wantDownload: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := fixtureRoutes(t)
			routes["/api/v1/crates/memoffset"] = response{status: http.StatusOK, body: modifiedFixture(t, "memoffset.json", func(doc map[string]any) {
				setVersionField(t, doc, "0.9.1", "crate_size", tt.crateSize)
			})}
			srv := newServer(t, routes)
			c := newClient(t, srv, t.TempDir(), false)
			c.maxArchive = tt.maxArchive
			info, err := c.VersionInfo(context.Background(), cargoRef("memoffset", "0.9.1"))
			if !errors.Is(err, ErrNotInspected) || !errors.Is(err, ErrArchiveTooLarge) {
				t.Fatalf("error = %v, want ErrNotInspected wrapping ErrArchiveTooLarge", err)
			}
			if info == nil || info.Scripts != nil {
				t.Fatalf("info = %+v, want the metadata with empty Scripts", info)
			}
			if got := srv.requests("/crates/memoffset/memoffset-0.9.1.crate") > 0; got != tt.wantDownload {
				t.Errorf("archive downloaded = %v, want %v", got, tt.wantDownload)
			}
		})
	}
}

func TestVersionInfoArchiveDownloadFailures(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   []byte
	}{
		{name: "403 like S3", status: http.StatusForbidden},
		{name: "404", status: http.StatusNotFound},
		{name: "not an archive", status: http.StatusOK, body: []byte("<html>maintenance</html>")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := fixtureRoutes(t)
			body := tt.body
			if tt.status == http.StatusOK {
				// Keep the checksum honest so the failure is the archive itself.
				routes["/api/v1/crates/memoffset"] = response{status: http.StatusOK, body: modifiedFixture(t, "memoffset.json", func(doc map[string]any) {
					setVersionField(t, doc, "0.9.1", "checksum", sha256Hex(body))
				})}
			}
			routes["/crates/memoffset/memoffset-0.9.1.crate"] = response{status: tt.status, body: body}
			c := newClient(t, newServer(t, routes), t.TempDir(), false)
			info, err := c.VersionInfo(context.Background(), cargoRef("memoffset", "0.9.1"))
			if !errors.Is(err, ErrNotInspected) {
				t.Fatalf("error = %v, want ErrNotInspected", err)
			}
			if errors.Is(err, ErrArchiveTooLarge) || errors.Is(err, ErrChecksumMismatch) {
				t.Errorf("error = %v, wrong cause", err)
			}
			if info == nil || info.Scripts != nil || info.Publisher == nil {
				t.Fatalf("info = %+v, want the metadata with empty Scripts", info)
			}
		})
	}
}

func TestOffline(t *testing.T) {
	dir := t.TempDir()
	srv := newServer(t, fixtureRoutes(t))

	t.Run("cold cache", func(t *testing.T) {
		c := newClient(t, srv, dir, true)
		list, err := c.Versions(context.Background(), "memoffset")
		if !errors.Is(err, httpcache.ErrOffline) || list != nil {
			t.Fatalf("Versions = %v, %v; want ErrOffline", list, err)
		}
		info, err := c.VersionInfo(context.Background(), cargoRef("memoffset", "0.9.1"))
		if !errors.Is(err, httpcache.ErrOffline) || info != nil {
			t.Fatalf("VersionInfo = %v, %v; want ErrOffline and no value", info, err)
		}
	})

	// Warm the metadata only; the archive stays unfetched.
	online := newClient(t, srv, dir, false)
	if _, err := online.Versions(context.Background(), "memoffset"); err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if _, err := online.dependencies(context.Background(), "memoffset", cargoRef("memoffset", "0.9.1")); err != nil {
		t.Fatalf("dependencies: %v", err)
	}

	t.Run("metadata cached, archive not", func(t *testing.T) {
		c := newClient(t, srv, dir, true)
		info, err := c.VersionInfo(context.Background(), cargoRef("memoffset", "0.9.1"))
		if !errors.Is(err, ErrNotInspected) || !errors.Is(err, httpcache.ErrOffline) {
			t.Fatalf("error = %v, want ErrNotInspected wrapping ErrOffline", err)
		}
		if info == nil || info.Scripts != nil || info.Publisher == nil {
			t.Fatalf("info = %+v, want the cached metadata with empty Scripts", info)
		}
	})

	// One inspection online is served forever afterwards.
	if _, err := online.VersionInfo(context.Background(), cargoRef("memoffset", "0.9.1")); err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	t.Run("archive cached", func(t *testing.T) {
		c := newClient(t, srv, dir, true)
		info, err := c.VersionInfo(context.Background(), cargoRef("memoffset", "0.9.1"))
		if err != nil {
			t.Fatalf("VersionInfo: %v", err)
		}
		if _, ok := info.Scripts[ScriptBuild]; !ok {
			t.Errorf("Scripts = %v, want the build script", info.Scripts)
		}
	})
	if n := srv.requests("/crates/memoffset/memoffset-0.9.1.crate"); n != 1 {
		t.Errorf("archive fetched %d times, want 1", n)
	}
}

func TestEcosystem(t *testing.T) {
	if got := New(nil).Ecosystem(); got != model.Cargo {
		t.Errorf("Ecosystem = %s, want cargo", got)
	}
}
