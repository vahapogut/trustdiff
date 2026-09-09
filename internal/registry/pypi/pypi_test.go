package pypi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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

// route pairs a request path with the recorded fixture and status that answer it.
type route struct {
	file   string
	status int
}

// fixtures maps every path the tests exercise to its recording under testdata.
// Anything else is answered like PyPI answers an unknown project: 404 with the
// recorded not-found body.
var fixtures = map[string]route{
	"/pypi/sampleproject/json":       {"sampleproject.json", http.StatusOK},
	"/pypi/requests/json":            {"requests.json", http.StatusOK},
	"/pypi/pycrypto/json":            {"pycrypto.json", http.StatusOK},
	"/pypi/sampleproject/4.0.0/json": {"sampleproject-4.0.0.json", http.StatusOK},
	"/pypi/requests/2.32.0/json":     {"requests-2.32.0.json", http.StatusOK},
	"/pypi/pycrypto/2.6.1/json":      {"pycrypto-2.6.1.json", http.StatusOK},
	"/pypi/requests/2.32.99/json":    {"requests-2.32.99.json", http.StatusNotFound},
	"/integrity/sampleproject/4.0.0/sampleproject-4.0.0-py3-none-any.whl/provenance": {"provenance-sampleproject-4.0.0.json", http.StatusOK},
	"/integrity/requests/2.32.0/requests-2.32.0-py3-none-any.whl/provenance":         {"provenance-requests-2.32.0.json", http.StatusNotFound},
	"/integrity/pycrypto/2.6.1/pycrypto-2.6.1.tar.gz/provenance":                     {"provenance-pycrypto-2.6.1.json", http.StatusNotFound},
}

// request is what the fake registry saw.
type request struct {
	Path   string
	Accept string
}

// server is an httptest server that serves the fixtures and records requests.
type server struct {
	*httptest.Server
	mu   sync.Mutex
	seen []request
	// fail forces a status for a path, to simulate an outage of one endpoint.
	fail map[string]int
	// bodies overrides the body for a path, to serve a fixture-derived document.
	bodies map[string][]byte
}

func newServer(t *testing.T) *server {
	t.Helper()
	s := &server{fail: map[string]int{}, bodies: map[string][]byte{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, request{Path: r.URL.Path, Accept: r.Header.Get("Accept")})
		status, forced := s.fail[r.URL.Path]
		body, overridden := s.bodies[r.URL.Path]
		s.mu.Unlock()
		if forced {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if overridden {
			_, _ = w.Write(body)
			return
		}
		rt, ok := fixtures[r.URL.Path]
		if !ok {
			rt = route{"not-found.json", http.StatusNotFound}
		}
		w.WriteHeader(rt.status)
		_, _ = w.Write(fixture(t, rt.file))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *server) requests() []request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]request(nil), s.seen...)
}

func (s *server) paths() []string {
	reqs := s.requests()
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = r.Path
	}
	return out
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return data
}

// newClient builds a client on a fresh cache directory, without retries so an
// outage test does not wait for backoff, and with a generous rate limit for the
// test server so a handful of requests do not take a second.
func newClient(t *testing.T, s *server, opts ...Option) (*Client, string) {
	t.Helper()
	dir := t.TempDir()
	h, err := httpcache.New(httpcache.Options{
		UserAgent: "trustdiff-test",
		Dir:       dir,
		Retries:   -1,
		Timeout:   5 * time.Second,
		HostRPS:   map[string]float64{strings.TrimPrefix(s.URL, "http://"): 1000},
	})
	if err != nil {
		t.Fatalf("httpcache.New: %v", err)
	}
	opts = append([]Option{WithBaseURL(s.URL)}, opts...)
	return New(h, opts...), dir
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

func find(t *testing.T, list *registry.VersionList, ver string) *model.VersionInfo {
	t.Helper()
	v := registry.Find(list, ver)
	if v == nil {
		t.Fatalf("version %s missing from %s (%d versions)", ver, list.Name, len(list.Versions))
	}
	return v
}

func TestEcosystem(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	if got := c.Ecosystem(); got != model.PyPI {
		t.Fatalf("Ecosystem() = %q, want %q", got, model.PyPI)
	}
}

func TestVersionsHealthy(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	list, err := c.Versions(context.Background(), "sampleproject")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if list.Ecosystem != model.PyPI || list.Name != "sampleproject" {
		t.Errorf("list identity = %s:%s, want pypi:sampleproject", list.Ecosystem, list.Name)
	}
	if list.Latest != "4.0.0" {
		t.Errorf("Latest = %q, want 4.0.0", list.Latest)
	}
	if len(list.Versions) != 7 {
		t.Errorf("len(Versions) = %d, want 7", len(list.Versions))
	}
	wantOwners := []model.Publisher{{Name: "org:pypa"}}
	if len(list.Maintainers) != 1 || list.Maintainers[0] != wantOwners[0] {
		t.Errorf("Maintainers = %v, want %v", list.Maintainers, wantOwners)
	}
	if !list.Created.IsZero() || !list.Modified.IsZero() || list.Deprecated != "" {
		t.Errorf("Created, Modified and Deprecated should stay empty for PyPI, got %v %v %q", list.Created, list.Modified, list.Deprecated)
	}

	latest := find(t, list, "4.0.0")
	if want := (model.PackageRef{Ecosystem: model.PyPI, Name: "sampleproject", Version: "4.0.0"}); latest.Ref != want {
		t.Errorf("Ref = %v, want %v", latest.Ref, want)
	}
	// Earliest of the wheel (22:37:09) and the sdist (22:37:10).
	if want := mustTime(t, "2024-11-06T22:37:09.220617Z"); !latest.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", latest.PublishedAt, want)
	}
	if latest.Yanked || latest.Prerelease || latest.Publisher != nil || latest.Maintainers != nil || latest.Deprecated != "" {
		t.Errorf("4.0.0 flags = yanked %v prerelease %v publisher %v maintainers %v deprecated %q", latest.Yanked, latest.Prerelease, latest.Publisher, latest.Maintainers, latest.Deprecated)
	}
	if latest.Scripts != nil {
		t.Errorf("Scripts = %v for a release with a wheel, want none", latest.Scripts)
	}
	if want := "sha256:c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b"; latest.Integrity != want {
		t.Errorf("Integrity = %q, want the wheel digest %q", latest.Integrity, want)
	}
	if latest.WeeklyDownloads != -1 {
		t.Errorf("WeeklyDownloads = %d, want -1", latest.WeeklyDownloads)
	}

	// 1.3.1 has a wheel from 2019, a second wheel uploaded in 2020 and an sdist
	// one second after the first wheel: the release dates from the first upload.
	if v := find(t, list, "1.3.1"); !v.PublishedAt.Equal(mustTime(t, "2019-11-04T20:36:25.256613Z")) {
		t.Errorf("1.3.1 PublishedAt = %v, want the first upload", v.PublishedAt)
	}
	// 1.0 is listed with no files at all.
	if v := find(t, list, "1.0"); !v.PublishedAt.IsZero() || v.Yanked || v.Integrity != "" || v.Scripts != nil {
		t.Errorf("1.0 (no files) = published %v yanked %v integrity %q scripts %v, want all zero", v.PublishedAt, v.Yanked, v.Integrity, v.Scripts)
	}

	if want := []string{"/pypi/sampleproject/json"}; !equalStrings(s.paths(), want) {
		t.Errorf("requests = %v, want %v", s.paths(), want)
	}
	if accept := s.requests()[0].Accept; accept != "application/json" {
		t.Errorf("Accept = %q, want application/json", accept)
	}
}

func TestVersionsYankedAndPrerelease(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	list, err := c.Versions(context.Background(), "requests")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if list.Latest != "2.34.2" {
		t.Errorf("Latest = %q, want 2.34.2", list.Latest)
	}
	if len(list.Versions) != 163 {
		t.Errorf("len(Versions) = %d, want 163", len(list.Versions))
	}
	tests := []struct {
		version    string
		yanked     bool
		prerelease bool
		published  string
	}{
		{"2.32.0", true, false, "2024-05-20T16:08:19.530618Z"},
		{"2.32.1", true, false, "2024-05-20T22:08:45.850542Z"},
		{"2.32.2", false, false, "2024-05-21T18:51:29.562156Z"},
		{"2.34.0.dev1", false, true, "2026-05-03T20:21:40.509155Z"},
		{"2.34.2", false, false, "2026-05-14T19:25:26.443000Z"},
		{"0.0.1", false, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			v := find(t, list, tc.version)
			if v.Yanked != tc.yanked {
				t.Errorf("Yanked = %v, want %v", v.Yanked, tc.yanked)
			}
			if v.Prerelease != tc.prerelease {
				t.Errorf("Prerelease = %v, want %v", v.Prerelease, tc.prerelease)
			}
			var want time.Time
			if tc.published != "" {
				want = mustTime(t, tc.published)
			}
			if !v.PublishedAt.Equal(want) {
				t.Errorf("PublishedAt = %v, want %v", v.PublishedAt, want)
			}
		})
	}
	wantOwners := []model.Publisher{{Name: "Lukasa"}, {Name: "graffatcolmingov"}, {Name: "nateprewitt"}}
	if !equalPublishers(list.Maintainers, wantOwners) {
		t.Errorf("Maintainers = %v, want %v", list.Maintainers, wantOwners)
	}
}

func TestVersionsSdistOnly(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	list, err := c.Versions(context.Background(), "pycrypto")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if list.Latest != "2.6.1" || len(list.Versions) != 13 {
		t.Errorf("Latest = %q with %d versions, want 2.6.1 with 13", list.Latest, len(list.Versions))
	}
	want := map[string]string{sdistScriptKey: sdistScriptValue}
	for _, v := range list.Versions {
		switch v.Ref.Version {
		case "1.9a2", "1.9a5", "1.9a6", "2.0":
			// Listed without files: nothing to install and nothing to flag.
			if v.Scripts != nil || !v.PublishedAt.IsZero() {
				t.Errorf("%s: Scripts = %v, PublishedAt = %v, want none for a release without files", v.Ref.Version, v.Scripts, v.PublishedAt)
			}
			if strings.HasPrefix(v.Ref.Version, "1.9a") && !v.Prerelease {
				t.Errorf("%s: Prerelease = false, want true", v.Ref.Version)
			}
		default:
			if len(v.Scripts) != 1 || v.Scripts[sdistScriptKey] != want[sdistScriptKey] {
				t.Errorf("%s: Scripts = %v, want %v", v.Ref.Version, v.Scripts, want)
			}
			if !v.HasInstallScript() {
				t.Errorf("%s: HasInstallScript() = false", v.Ref.Version)
			}
		}
	}
	v := find(t, list, "2.6.1")
	if want := "sha256:f2ce1e989b272cfcb677616763e0a2e7ec659effa67a88aa92b3a65528f60a3c"; v.Integrity != want {
		t.Errorf("2.6.1 Integrity = %q, want the sdist digest %q", v.Integrity, want)
	}
	if want := mustTime(t, "2014-06-20T08:10:20.813938Z"); !v.PublishedAt.Equal(want) {
		t.Errorf("2.6.1 PublishedAt = %v, want %v", v.PublishedAt, want)
	}
}

func TestVersionsOrderIsDeterministic(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	first, err := c.Versions(context.Background(), "requests")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := c.Versions(context.Background(), "requests")
		if err != nil {
			t.Fatalf("Versions again: %v", err)
		}
		for j := range first.Versions {
			if again.Versions[j].Ref != first.Versions[j].Ref {
				t.Fatalf("run %d: position %d is %s, was %s", i, j, again.Versions[j].Ref, first.Versions[j].Ref)
			}
		}
	}
}

func TestVersionsNotFound(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	_, err := c.Versions(context.Background(), "trustdiff-this-project-does-not-exist-9f3a")
	if !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("Versions error = %v, want registry.ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "trustdiff-this-project-does-not-exist-9f3a") {
		t.Errorf("error %q does not name the project", err)
	}
}

func TestVersionsOffline(t *testing.T) {
	s := newServer(t)
	h, err := httpcache.New(httpcache.Options{UserAgent: "trustdiff-test", Dir: t.TempDir(), Offline: true})
	if err != nil {
		t.Fatalf("httpcache.New: %v", err)
	}
	c := New(h, WithBaseURL(s.URL))
	if _, err := c.Versions(context.Background(), "requests"); !errors.Is(err, httpcache.ErrOffline) {
		t.Fatalf("offline Versions error = %v, want httpcache.ErrOffline", err)
	}
	if len(s.paths()) != 0 {
		t.Errorf("offline client made requests: %v", s.paths())
	}
}

func TestVersionInfoHealthy(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	info, err := c.VersionInfo(context.Background(), model.MustParseRef("pypi:sampleproject@4.0.0"))
	if err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	if want := (model.PackageRef{Ecosystem: model.PyPI, Name: "sampleproject", Version: "4.0.0"}); info.Ref != want {
		t.Errorf("Ref = %v, want %v", info.Ref, want)
	}
	if want := mustTime(t, "2024-11-06T22:37:09.220617Z"); !info.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", info.PublishedAt, want)
	}
	// The dev and test extras are not installed by a plain pip install.
	if want := map[string]string{"peppercorn": ""}; !equalMaps(info.Dependencies, want) {
		t.Errorf("Dependencies = %v, want %v", info.Dependencies, want)
	}
	wantOptional := map[string]string{
		"check-manifest": `; extra == "dev"`,
		"coverage":       `; extra == "test"`,
	}
	if !equalMaps(info.OptionalDependencies, wantOptional) {
		t.Errorf("OptionalDependencies = %v, want %v", info.OptionalDependencies, wantOptional)
	}
	if info.Scripts != nil {
		t.Errorf("Scripts = %v, want none for a release with a wheel", info.Scripts)
	}
	wantProv := model.Provenance{Kind: model.ProvenanceAttestation, Verified: false, Identity: "github:pypa/sampleproject/release.yml"}
	if info.Provenance != wantProv {
		t.Errorf("Provenance = %+v, want %+v", info.Provenance, wantProv)
	}
	if info.Unknown != nil {
		t.Errorf("Unknown = %v, want nothing unknown", info.Unknown)
	}
	if want := "sha256:c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b"; info.Integrity != want {
		t.Errorf("Integrity = %q, want %q", info.Integrity, want)
	}
	if info.Yanked || info.Prerelease || info.Deprecated != "" || info.Publisher != nil || info.Maintainers != nil || info.WeeklyDownloads != -1 {
		t.Errorf("unexpected fields: yanked %v prerelease %v deprecated %q publisher %v maintainers %v downloads %d",
			info.Yanked, info.Prerelease, info.Deprecated, info.Publisher, info.Maintainers, info.WeeklyDownloads)
	}
	want := []request{
		{"/pypi/sampleproject/4.0.0/json", "application/json"},
		{"/integrity/sampleproject/4.0.0/sampleproject-4.0.0-py3-none-any.whl/provenance", "application/vnd.pypi.integrity.v1+json"},
	}
	if got := s.requests(); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("requests = %v, want %v", got, want)
	}
}

func TestVersionInfoYanked(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	info, err := c.VersionInfo(context.Background(), model.MustParseRef("pypi:requests@2.32.0"))
	if err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	if !info.Yanked {
		t.Errorf("Yanked = false for a yanked release")
	}
	// The wheel of 2.32.0 predates PEP 740 support: the integrity API answers 404.
	if want := (model.Provenance{Kind: model.ProvenanceNone}); info.Provenance != want {
		t.Errorf("Provenance = %+v, want %+v", info.Provenance, want)
	}
	// requires_dist spells charset-normalizer with a dash here and with an
	// underscore in 2.34.2; both must map to the same key. The socks and
	// use-chardet-on-py3 extras are optional.
	wantDeps := map[string]string{
		"charset-normalizer": "<4,>=2",
		"idna":               "<4,>=2.5",
		"urllib3":            "<3,>=1.21.1",
		"certifi":            ">=2017.4.17",
	}
	if !equalMaps(info.Dependencies, wantDeps) {
		t.Errorf("Dependencies = %v, want %v", info.Dependencies, wantDeps)
	}
	wantOptional := map[string]string{
		"pysocks": `!=1.5.7,>=1.5.6; extra == "socks"`,
		"chardet": `<6,>=3.0.2; extra == "use-chardet-on-py3"`,
	}
	if !equalMaps(info.OptionalDependencies, wantOptional) {
		t.Errorf("OptionalDependencies = %v, want %v", info.OptionalDependencies, wantOptional)
	}
	if want := "sha256:f2c3881dddb70d056c5bd7600a4fae312b2a300e39be6a118d30b90bd27262b5"; info.Integrity != want {
		t.Errorf("Integrity = %q, want the wheel digest %q", info.Integrity, want)
	}
	wantPaths := []string{"/pypi/requests/2.32.0/json", "/integrity/requests/2.32.0/requests-2.32.0-py3-none-any.whl/provenance"}
	if !equalStrings(s.paths(), wantPaths) {
		t.Errorf("requests = %v, want %v", s.paths(), wantPaths)
	}
}

func TestVersionInfoSdistOnly(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	info, err := c.VersionInfo(context.Background(), model.MustParseRef("pypi:pycrypto@2.6.1"))
	if err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	if want := map[string]string{sdistScriptKey: sdistScriptValue}; !equalMaps(info.Scripts, want) {
		t.Errorf("Scripts = %v, want %v", info.Scripts, want)
	}
	if info.Dependencies != nil {
		t.Errorf("Dependencies = %v, want none (requires_dist is null)", info.Dependencies)
	}
	if want := (model.Provenance{Kind: model.ProvenanceNone}); info.Provenance != want {
		t.Errorf("Provenance = %+v, want %+v", info.Provenance, want)
	}
	if want := "sha256:f2ce1e989b272cfcb677616763e0a2e7ec659effa67a88aa92b3a65528f60a3c"; info.Integrity != want {
		t.Errorf("Integrity = %q, want the sdist digest %q", info.Integrity, want)
	}
	if want := mustTime(t, "2014-06-20T08:10:20.813938Z"); !info.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", info.PublishedAt, want)
	}
	// With no wheel the sdist is the file whose provenance is asked for.
	wantPaths := []string{"/pypi/pycrypto/2.6.1/json", "/integrity/pycrypto/2.6.1/pycrypto-2.6.1.tar.gz/provenance"}
	if !equalStrings(s.paths(), wantPaths) {
		t.Errorf("requests = %v, want %v", s.paths(), wantPaths)
	}
}

func TestVersionInfoErrors(t *testing.T) {
	tests := []struct {
		name    string
		ref     model.PackageRef
		fail    map[string]int
		wantErr error
	}{
		{
			name:    "unknown version",
			ref:     model.MustParseRef("pypi:requests@2.32.99"),
			wantErr: registry.ErrNotFound,
		},
		{
			name:    "unknown project",
			ref:     model.MustParseRef("pypi:trustdiff-this-project-does-not-exist-9f3a@1.0"),
			wantErr: registry.ErrNotFound,
		},
		{
			name: "version required",
			ref:  model.MustParseRef("pypi:requests"),
		},
		{
			name: "wrong ecosystem",
			ref:  model.MustParseRef("npm:express@4.19.2"),
		},
		{
			name: "release endpoint down",
			ref:  model.MustParseRef("pypi:sampleproject@4.0.0"),
			fail: map[string]int{"/pypi/sampleproject/4.0.0/json": http.StatusServiceUnavailable},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			for path, status := range tc.fail {
				s.fail[path] = status
			}
			c, _ := newClient(t, s)
			info, err := c.VersionInfo(context.Background(), tc.ref)
			if err == nil {
				t.Fatalf("VersionInfo = %+v, want an error", info)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVersionInfoProvenanceUnavailable(t *testing.T) {
	// The integrity API failing with anything but a 404 leaves provenance
	// unknown and keeps everything the release JSON said, so that only TD004 is
	// skipped rather than every registry-backed check.
	s := newServer(t)
	path := "/integrity/sampleproject/4.0.0/sampleproject-4.0.0-py3-none-any.whl/provenance"
	s.fail[path] = http.StatusForbidden
	var buf strings.Builder
	c, _ := newClient(t, s, WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	info, err := c.VersionInfo(context.Background(), model.MustParseRef("pypi:sampleproject@4.0.0"))
	if err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	if info.Provenance != (model.Provenance{}) {
		t.Errorf("Provenance = %+v, want the zero value while unknown", info.Provenance)
	}
	reason, ok := info.Unknown[model.FacetProvenance]
	if !ok || !strings.Contains(reason, "403") || !strings.Contains(reason, "sampleproject 4.0.0") {
		t.Errorf("Unknown[provenance] = %q (%v), want the failed lookup with its status", reason, ok)
	}
	if want := map[string]string{"peppercorn": ""}; !equalMaps(info.Dependencies, want) {
		t.Errorf("Dependencies = %v, want %v (the rest of the version stays)", info.Dependencies, want)
	}
	if info.PublishedAt.IsZero() || info.Integrity == "" {
		t.Errorf("PublishedAt %v / Integrity %q not filled", info.PublishedAt, info.Integrity)
	}
	if !strings.Contains(buf.String(), "provenance not gathered") {
		t.Errorf("log = %q, want a warning about the provenance lookup", buf.String())
	}
	// A 404 still means none, with nothing unknown.
	known, err := c.VersionInfo(context.Background(), model.MustParseRef("pypi:requests@2.32.0"))
	if err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	if known.Provenance.Kind != model.ProvenanceNone || known.Unknown != nil {
		t.Errorf("requests 2.32.0 = provenance %+v unknown %v, want none and nothing unknown", known.Provenance, known.Unknown)
	}
}

func TestOwners(t *testing.T) {
	// A project JSON without the ownership object, derived from the recorded
	// sampleproject response so every other field keeps its real shape.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(fixture(t, "sampleproject.json"), &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	delete(doc, "ownership")
	withoutOwnership, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}

	tests := []struct {
		name    string
		project string
		want    []model.Publisher
		wantErr error
	}{
		{name: "owners only", project: "requests", want: []model.Publisher{{Name: "Lukasa"}, {Name: "graffatcolmingov"}, {Name: "nateprewitt"}}},
		{name: "organization only", project: "sampleproject", want: []model.Publisher{{Name: "org:pypa"}}},
		{name: "two owners", project: "PyCrypto", want: []model.Publisher{{Name: "amk"}, {Name: "dlitz"}}},
		{name: "ownership absent", project: "no-ownership", wantErr: registry.ErrUnsupported},
		{name: "unknown project", project: "trustdiff-this-project-does-not-exist-9f3a", wantErr: registry.ErrNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			s.bodies["/pypi/no-ownership/json"] = withoutOwnership
			c, _ := newClient(t, s)
			got, err := c.Owners(context.Background(), tc.project)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Owners error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Owners: %v", err)
			}
			if !equalPublishers(got, tc.want) {
				t.Errorf("Owners = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOwnersSharesTheProjectFetch(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	ctx := context.Background()
	if _, err := c.Versions(ctx, "requests"); err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if _, err := c.Owners(ctx, "requests"); err != nil {
		t.Fatalf("Owners: %v", err)
	}
	if want := []string{"/pypi/requests/json"}; !equalStrings(s.paths(), want) {
		t.Errorf("requests = %v, want the project JSON fetched once", s.paths())
	}
}

func TestDownloadsUnsupported(t *testing.T) {
	s := newServer(t)
	c, _ := newClient(t, s)
	n, err := c.Downloads(context.Background(), "requests")
	if !errors.Is(err, registry.ErrUnsupported) {
		t.Fatalf("Downloads error = %v, want registry.ErrUnsupported", err)
	}
	if n != -1 {
		t.Errorf("Downloads = %d, want -1", n)
	}
	if len(s.paths()) != 0 {
		t.Errorf("Downloads made requests: %v", s.paths())
	}
}

func TestNamesAreNormalizedInURLs(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"requests", "/pypi/requests/json"},
		{"Requests", "/pypi/requests/json"},
		{"Zope.Interface", "/pypi/zope-interface/json"},
		{"typing_extensions", "/pypi/typing-extensions/json"},
		{"ruamel.yaml", "/pypi/ruamel-yaml/json"},
		{"A__b..c--d", "/pypi/a-b-c-d/json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(t)
			c, _ := newClient(t, s)
			ctx := context.Background()
			_, _ = c.Versions(ctx, tc.name)
			_, _ = c.Owners(ctx, tc.name)
			for _, p := range s.paths() {
				if p != tc.want {
					t.Errorf("request path %q, want %q", p, tc.want)
				}
			}
		})
	}
	t.Run("release route", func(t *testing.T) {
		s := newServer(t)
		c, _ := newClient(t, s)
		_, err := c.VersionInfo(context.Background(), model.PackageRef{Ecosystem: model.PyPI, Name: "PyCrypto", Version: "2.6.1"})
		if err != nil {
			t.Fatalf("VersionInfo: %v", err)
		}
		if got := s.paths()[0]; got != "/pypi/pycrypto/2.6.1/json" {
			t.Errorf("request path %q, want /pypi/pycrypto/2.6.1/json", got)
		}
	})
}

// cacheMeta is the readable half of an httpcache entry, enough to see the TTL
// each URL was stored with.
type cacheMeta struct {
	URL string `json:"url"`
	TTL string `json:"ttl"`
}

// readCacheTTLs maps every cached URL to the TTL string httpcache recorded.
func readCacheTTLs(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	ttls := map[string]string{}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var m cacheMeta
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("decode %s: %v", e.Name(), err)
		}
		ttls[strings.TrimPrefix(m.URL, "http://")] = m.TTL
	}
	return ttls
}

func TestCacheTTLs(t *testing.T) {
	s := newServer(t)
	c, dir := newClient(t, s)
	ctx := context.Background()
	if _, err := c.Versions(ctx, "sampleproject"); err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if _, err := c.VersionInfo(ctx, model.MustParseRef("pypi:sampleproject@4.0.0")); err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	if _, err := c.VersionInfo(ctx, model.MustParseRef("pypi:pycrypto@2.6.1")); err != nil {
		t.Fatalf("VersionInfo: %v", err)
	}
	host := strings.TrimPrefix(s.URL, "http://")
	want := map[string]string{
		host + "/pypi/sampleproject/json": "1h0m0s",
		// The release JSON carries the yanked flag, so it is refreshed hourly;
		// only the PEP 740 provenance of a file is immutable.
		host + "/pypi/sampleproject/4.0.0/json":                                                 "1h0m0s",
		host + "/pypi/pycrypto/2.6.1/json":                                                      "1h0m0s",
		host + "/integrity/sampleproject/4.0.0/sampleproject-4.0.0-py3-none-any.whl/provenance": "forever",
		// A 404 is cached too, capped at the default TTL by the shared client.
		host + "/integrity/pycrypto/2.6.1/pycrypto-2.6.1.tar.gz/provenance": "1h0m0s",
	}
	if got := readCacheTTLs(t, dir); !equalMaps(got, want) {
		t.Errorf("cache TTLs = %v, want %v", got, want)
	}

	// Everything is now served from the cache: no request reaches the registry.
	before := len(s.paths())
	if _, err := c.Versions(ctx, "sampleproject"); err != nil {
		t.Fatalf("Versions again: %v", err)
	}
	if _, err := c.VersionInfo(ctx, model.MustParseRef("pypi:sampleproject@4.0.0")); err != nil {
		t.Fatalf("VersionInfo again: %v", err)
	}
	if _, err := c.VersionInfo(ctx, model.MustParseRef("pypi:pycrypto@2.6.1")); err != nil {
		t.Fatalf("VersionInfo again: %v", err)
	}
	if after := len(s.paths()); after != before {
		t.Errorf("%d requests after warm cache, want %d", after, before)
	}
}

// newClientAt is newClient on a given cache directory with a fixed clock, for
// tests that watch an entry expire.
func newClientAt(t *testing.T, s *server, dir string, now time.Time) *Client {
	t.Helper()
	h, err := httpcache.New(httpcache.Options{
		UserAgent: "trustdiff-test",
		Dir:       dir,
		Retries:   -1,
		Timeout:   5 * time.Second,
		HostRPS:   map[string]float64{strings.TrimPrefix(s.URL, "http://"): 1000},
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("httpcache.New: %v", err)
	}
	return New(h, WithBaseURL(s.URL))
}

func TestYankObservedAfterCacheExpiry(t *testing.T) {
	// requests 2.32.0 as it looked in the hours before it was yanked: the
	// recorded release JSON with every yanked flag cleared.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(fixture(t, "requests-2.32.0.json"), &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	var info map[string]any
	if err := json.Unmarshal(doc["info"], &info); err != nil {
		t.Fatalf("decode info: %v", err)
	}
	info["yanked"], info["yanked_reason"] = false, nil
	var files []map[string]any
	if err := json.Unmarshal(doc["urls"], &files); err != nil {
		t.Fatalf("decode urls: %v", err)
	}
	for _, f := range files {
		f["yanked"], f["yanked_reason"] = false, nil
	}
	var err error
	if doc["info"], err = json.Marshal(info); err != nil {
		t.Fatalf("encode info: %v", err)
	}
	if doc["urls"], err = json.Marshal(files); err != nil {
		t.Fatalf("encode urls: %v", err)
	}
	notYetYanked, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode release: %v", err)
	}

	s := newServer(t)
	const path = "/pypi/requests/2.32.0/json"
	s.bodies[path] = notYetYanked
	dir := t.TempDir()
	ref := model.MustParseRef("pypi:requests@2.32.0")
	t0 := time.Date(2024, time.May, 20, 18, 0, 0, 0, time.UTC)

	first, err := newClientAt(t, s, dir, t0).VersionInfo(context.Background(), ref)
	if err != nil {
		t.Fatalf("VersionInfo before the yank: %v", err)
	}
	if first.Yanked {
		t.Fatal("Yanked = true before the yank")
	}

	// The yank happens; the recorded fixture is what PyPI serves from now on.
	s.mu.Lock()
	delete(s.bodies, path)
	s.mu.Unlock()

	// Within the hour the cached document is served as is: no request, no yank.
	requestsBefore := len(s.paths())
	cached, err := newClientAt(t, s, dir, t0.Add(59*time.Minute)).VersionInfo(context.Background(), ref)
	if err != nil {
		t.Fatalf("VersionInfo within the TTL: %v", err)
	}
	if cached.Yanked {
		t.Error("Yanked = true from a cached document that predates the yank")
	}
	if n := len(s.paths()) - requestsBefore; n != 0 {
		t.Errorf("%d requests within the TTL, want none", n)
	}

	// Once the entry expires the release is fetched again and the yank shows up.
	requestsBefore = len(s.paths())
	fresh, err := newClientAt(t, s, dir, t0.Add(61*time.Minute)).VersionInfo(context.Background(), ref)
	if err != nil {
		t.Fatalf("VersionInfo after the TTL: %v", err)
	}
	if !fresh.Yanked {
		t.Error("Yanked = false after the cached release JSON expired")
	}
	if n := len(s.paths()) - requestsBefore; n == 0 {
		t.Error("no request after the TTL expired")
	}
}

func TestWithLogger(t *testing.T) {
	s := newServer(t)
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c, _ := newClient(t, s, WithLogger(logger))
	if _, err := c.Versions(context.Background(), "sampleproject"); err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if !strings.Contains(buf.String(), "release has no files") {
		t.Errorf("log = %q, want the no-files diagnostic for sampleproject 1.0", buf.String())
	}
	// A nil logger keeps the default instead of panicking later.
	if c := New(nil, WithLogger(nil)); c.log == nil {
		t.Error("WithLogger(nil) left the logger nil")
	}
}

func TestPublisherIdentity(t *testing.T) {
	tests := []struct {
		name string
		pub  *publisherJSON
		want string
	}{
		{"github with workflow", &publisherJSON{Kind: "GitHub", Repository: "pypa/sampleproject", Workflow: "release.yml"}, "github:pypa/sampleproject/release.yml"},
		{"gitlab", &publisherJSON{Kind: "GitLab", Repository: "group/project", Workflow: ".gitlab-ci.yml", Environment: "release"}, "gitlab:group/project/.gitlab-ci.yml"},
		{"no workflow", &publisherJSON{Kind: "GitHub", Repository: "pypa/sampleproject"}, "github:pypa/sampleproject"},
		{"no kind", &publisherJSON{Repository: "pypa/sampleproject", Workflow: "release.yml"}, "pypa/sampleproject/release.yml"},
		{"kind only", &publisherJSON{Kind: "GitHub"}, "github"},
		{"empty", &publisherJSON{}, ""},
		{"nil", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.pub.identity(); got != tc.want {
				t.Errorf("identity() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFileHelpers(t *testing.T) {
	wheel := fileJSON{Filename: "a-1.0-py3-none-any.whl", PackageType: typeWheel, UploadTimeISO: "2024-11-06T22:37:09.220617Z", Digests: map[string]string{"sha256": "aa"}}
	sdist := fileJSON{Filename: "a-1.0.tar.gz", PackageType: typeSdist, UploadTimeISO: "2024-11-06T22:37:10.868088Z", Digests: map[string]string{"sha256": "bb"}}
	legacy := fileJSON{Filename: "a-1.0.tar.gz", PackageType: typeSdist, UploadTime: "2014-06-20T08:10:20"}
	broken := fileJSON{Filename: "a-1.0.tar.gz", PackageType: typeSdist, UploadTimeISO: "yesterday", UploadTime: "noon"}
	egg := fileJSON{Filename: "a-1.0-py2.7.egg", PackageType: "bdist_egg", UploadTimeISO: "2010-01-01T00:00:00Z"}
	yankedWheel, yankedSdist := wheel, sdist
	yankedWheel.Yanked, yankedSdist.Yanked = true, true

	tests := []struct {
		name          string
		files         []fileJSON
		wantPublished string
		wantYanked    bool
		wantPreferred string
		wantSdistOnly bool
	}{
		{"wheel and sdist", []fileJSON{sdist, wheel}, "2024-11-06T22:37:09.220617Z", false, wheel.Filename, false},
		{"sdist only", []fileJSON{sdist}, "2024-11-06T22:37:10.868088Z", false, sdist.Filename, true},
		{"legacy time only", []fileJSON{legacy}, "2014-06-20T08:10:20Z", false, legacy.Filename, true},
		{"unparsable times", []fileJSON{broken}, "", false, broken.Filename, true},
		{"egg only", []fileJSON{egg}, "2010-01-01T00:00:00Z", false, "", false},
		{"all yanked", []fileJSON{yankedWheel, yankedSdist}, "2024-11-06T22:37:09.220617Z", true, wheel.Filename, false},
		{"partly yanked", []fileJSON{yankedWheel, sdist}, "2024-11-06T22:37:09.220617Z", false, wheel.Filename, false},
		{"no files", nil, "", false, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var wantTime time.Time
			if tc.wantPublished != "" {
				wantTime = mustTime(t, tc.wantPublished)
			}
			if got := earliestUpload(tc.files); !got.Equal(wantTime) {
				t.Errorf("earliestUpload = %v, want %v", got, wantTime)
			}
			if got := allYanked(tc.files); got != tc.wantYanked {
				t.Errorf("allYanked = %v, want %v", got, tc.wantYanked)
			}
			gotPreferred := ""
			if f := preferredFile(tc.files); f != nil {
				gotPreferred = f.Filename
			}
			if gotPreferred != tc.wantPreferred {
				t.Errorf("preferredFile = %q, want %q", gotPreferred, tc.wantPreferred)
			}
			if got := sdistOnly(tc.files); got != tc.wantSdistOnly {
				t.Errorf("sdistOnly = %v, want %v", got, tc.wantSdistOnly)
			}
		})
	}
}

func TestOwnershipPublishers(t *testing.T) {
	tests := []struct {
		name string
		own  *ownershipJSON
		want []model.Publisher
	}{
		{"absent", nil, nil},
		{"nobody", &ownershipJSON{}, []model.Publisher{}},
		{"organization and roles", &ownershipJSON{Organization: "pypa", Roles: []roleJSON{{"Owner", "theacodes"}, {"Maintainer", "pypa-bot"}}}, []model.Publisher{{Name: "org:pypa"}, {Name: "theacodes"}, {Name: "pypa-bot"}}},
		{"blank user skipped", &ownershipJSON{Roles: []roleJSON{{"Owner", ""}, {"Owner", "amk"}}}, []model.Publisher{{Name: "amk"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.own.publishers()
			if (got == nil) != (tc.want == nil) || !equalPublishers(got, tc.want) {
				t.Errorf("publishers() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalPublishers(a, b []model.Publisher) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
