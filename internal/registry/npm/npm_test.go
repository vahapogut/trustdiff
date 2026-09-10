package npm

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// unknownName is the package name both APIs were asked for when the 404 bodies
// were recorded; the fixture server answers it, and any other unknown path, with
// those bodies.
const unknownName = "trustdiff-no-such-package-9f3a1c"

// fixtureRoutes maps the escaped request path the client must produce to the
// recorded response that answers it. Everything else is a 404 with the recorded
// not-found body of the respective API.
var fixtureRoutes = map[string]string{
	"/isarray":                           "isarray.json",
	"/@sigstore%2Fbundle":                "sigstore-bundle.json",
	"/event-stream":                      "event-stream.json",
	"/parcel-bundler":                    "parcel-bundler.json",
	"/flatmap-stream":                    "flatmap-stream.json",
	"/JSONStream":                        "JSONStream.json",
	"/downloads/point/last-week/isarray": "downloads-isarray.json",
	"/downloads/point/last-week/@sigstore/bundle":                    "downloads-sigstore-bundle.json",
	"/downloads/point/last-week/isarray,event-stream," + unknownName: "downloads-bulk.json",
}

// fixtureServer serves the recorded fixtures and remembers every escaped path
// it was asked for, so tests can assert on name encoding and request counts.
type fixtureServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
}

func newFixtureServer(t *testing.T) *fixtureServer {
	t.Helper()
	bodies := map[string][]byte{}
	for _, file := range fixtureRoutes {
		bodies[file] = fixture(t, file)
	}
	notFound := fixture(t, "not-found.json")
	downloadsNotFound := fixture(t, "downloads-not-found.json")

	fs := &fixtureServer{}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		fs.mu.Lock()
		fs.paths = append(fs.paths, path)
		fs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if file, ok := fixtureRoutes[path]; ok {
			_, _ = w.Write(bodies[file])
			return
		}
		w.WriteHeader(http.StatusNotFound)
		if strings.HasPrefix(path, "/downloads/") {
			_, _ = w.Write(downloadsNotFound)
			return
		}
		_, _ = w.Write(notFound)
	}))
	t.Cleanup(fs.Close)
	return fs
}

// requests counts how often a path was requested.
func (fs *fixtureServer) requests(path string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := 0
	for _, p := range fs.paths {
		if p == path {
			n++
		}
	}
	return n
}

// seen returns a copy of every path requested so far, for failure messages.
func (fs *fixtureServer) seen() []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]string(nil), fs.paths...)
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return data
}

// newClient builds a client whose registry and downloads API are both the
// fixture server. dir is the httpcache directory, shared between clients when
// a test wants to observe the disk cache.
func newClient(t *testing.T, fs *fixtureServer, dir string, offline bool) *Client {
	t.Helper()
	u, err := url.Parse(fs.URL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := httpcache.New(httpcache.Options{
		Dir:       dir,
		Offline:   offline,
		UserAgent: "trustdiff-test",
		// The shared client allows 10 requests per second per host with a burst
		// of one; tests should not wait for that.
		HostRPS: map[string]float64{u.Host: 1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(h, WithRegistryURL(fs.URL), WithDownloadsURL(fs.URL), WithLogger(slog.New(slog.DiscardHandler)))
}

func ts(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad timestamp %q: %v", s, err)
	}
	return parsed
}

func npmRef(name, ver string) model.PackageRef {
	return model.PackageRef{Ecosystem: model.NPM, Name: name, Version: ver}
}

func versionStrings(list *registry.VersionList) []string {
	out := make([]string, len(list.Versions))
	for i := range list.Versions {
		out[i] = list.Versions[i].Ref.Version
	}
	return out
}

func TestVersionsHealthyPackage(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	list, err := c.Versions(ctx, "isarray")
	if err != nil {
		t.Fatal(err)
	}
	if list.Ecosystem != model.NPM || list.Name != "isarray" {
		t.Errorf("list identity = %s:%s, want npm:isarray", list.Ecosystem, list.Name)
	}
	if list.Latest != "2.0.5" {
		t.Errorf("Latest = %q, want 2.0.5", list.Latest)
	}
	if want := ts(t, "2013-05-22T19:10:00.756Z"); !list.Created.Equal(want) {
		t.Errorf("Created = %v, want %v", list.Created, want)
	}
	if want := ts(t, "2023-07-12T19:07:21.350Z"); !list.Modified.Equal(want) {
		t.Errorf("Modified = %v, want %v", list.Modified, want)
	}
	if list.Deprecated != "" {
		t.Errorf("Deprecated = %q, want empty", list.Deprecated)
	}
	if IsSecurityHolding(list) {
		t.Error("IsSecurityHolding = true for a healthy package")
	}
	wantMaintainers := []model.Publisher{{Name: "juliangruber", Email: "julian@juliangruber.com"}}
	if !reflect.DeepEqual(list.Maintainers, wantMaintainers) {
		t.Errorf("Maintainers = %+v, want %+v", list.Maintainers, wantMaintainers)
	}
	wantOrder := []string{"0.0.0", "0.0.1", "1.0.0", "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.0.5"}
	if got := versionStrings(list); !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("versions = %v, want %v", got, wantOrder)
	}

	got, err := c.VersionInfo(ctx, npmRef("isarray", "2.0.4"))
	if err != nil {
		t.Fatal(err)
	}
	want := &model.VersionInfo{
		Ref:             npmRef("isarray", "2.0.4"),
		PublishedAt:     ts(t, "2018-02-10T07:40:59.507Z"),
		Publisher:       &model.Publisher{Name: "juliangruber", Email: "julian@juliangruber.com"},
		Maintainers:     []model.Publisher{{Name: "juliangruber", Email: "julian@juliangruber.com"}},
		Provenance:      model.Provenance{Kind: model.ProvenanceSignature},
		Integrity:       "sha512-GMxXOiUirWg1xTKRipM0Ek07rX+ubx4nNVElTJdNLYmNO/2YrDkgJGw9CljXn+r4EWiDQg/8lsRdHyg2PJuUaA==",
		WeeklyDownloads: -1,
	}
	// The version declares only a test script and an empty dependencies object,
	// so neither map is set.
	if !reflect.DeepEqual(got, want) {
		t.Errorf("VersionInfo(2.0.4) =\n%+v\nwant\n%+v", got, want)
	}
	if got.HasInstallScript() {
		t.Error("HasInstallScript = true, want false")
	}

	owners, err := c.Owners(ctx, "isarray")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(owners, wantMaintainers) {
		t.Errorf("Owners = %+v, want %+v", owners, wantMaintainers)
	}
	if n := fs.requests("/isarray"); n != 1 {
		t.Errorf("packument requested %d times, want 1 (memoized per client)", n)
	}
}

func TestScopedPackageWithAttestations(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	// The slash of a scoped name is percent encoded; the spelling is sent as given.
	list, err := c.Versions(ctx, "@sigstore/bundle")
	if err != nil {
		t.Fatal(err)
	}
	if n := fs.requests("/@sigstore%2Fbundle"); n != 1 {
		t.Fatalf("scoped packument path requested %d times, want 1; paths: %v", n, fs.seen())
	}
	if list.Name != "@sigstore/bundle" || list.Latest != "5.0.0" || len(list.Versions) != 13 {
		t.Errorf("list = %s latest %s with %d versions, want @sigstore/bundle 5.0.0 with 13", list.Name, list.Latest, len(list.Versions))
	}
	if want := ts(t, "2023-07-19T16:10:34.529Z"); !list.Created.Equal(want) {
		t.Errorf("Created = %v, want %v", list.Created, want)
	}

	latest, err := c.VersionInfo(ctx, npmRef("@sigstore/bundle", "5.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	want := &model.VersionInfo{
		Ref:         npmRef("@sigstore/bundle", "5.0.0"),
		PublishedAt: ts(t, "2026-06-01T21:02:52.349Z"),
		// Trusted publishing: _npmUser is the synthetic GitHub Actions account,
		// and the publisher identity is the trusted publisher configuration.
		Publisher:       &model.Publisher{Name: "github-trusted-publisher:oidc:87d8bb4c-c894-403c-af7e-0d34d7e7327a", Email: "npm-oidc-no-reply@github.com"},
		Maintainers:     []model.Publisher{{Name: "bdehamer", Email: "brian@dehamer.com"}},
		Dependencies:    map[string]string{"@sigstore/protobuf-specs": "^0.5.0"},
		Provenance:      model.Provenance{Kind: model.ProvenanceAttestation, Verified: false},
		Integrity:       "sha512-wefjygudENbzbQMks1t5u34EP0fFoD0XvaEP7DOUP/sXKvogzEJYFw5E6pegGyp3onGWzVEYKVa3bNZWyTYX+A==",
		WeeklyDownloads: -1,
	}
	if !reflect.DeepEqual(latest, want) {
		t.Errorf("VersionInfo(5.0.0) =\n%+v\nwant\n%+v", latest, want)
	}

	// Every version of this package carries dist.attestations next to its
	// dist.signatures, 3.1.0 included: bdehamer published it with a token and the
	// workflow still produced provenance. What changed at 4.0.0 is the publishing
	// account, not the evidence, so the mapping must not weaken 3.1.0 to a
	// signature and Verified stays false until the runner consults deps.dev.
	for _, ver := range versionStrings(list) {
		info := registry.Find(list, ver)
		if info.Provenance.Kind != model.ProvenanceAttestation || info.Provenance.Verified {
			t.Errorf("%s provenance = %+v, want an unverified attestation", ver, info.Provenance)
		}
	}
	older, err := c.VersionInfo(ctx, npmRef("@sigstore/bundle", "3.1.0"))
	if err != nil {
		t.Fatal(err)
	}
	if older.Publisher == nil || older.Publisher.Name != "bdehamer" {
		t.Errorf("3.1.0 publisher = %+v, want bdehamer", older.Publisher)
	}
	if older.Provenance.Strength() != latest.Provenance.Strength() {
		t.Errorf("3.1.0 strength %d differs from 5.0.0 strength %d although both carry an attestation", older.Provenance.Strength(), latest.Provenance.Strength())
	}
	// Both trusted publishing releases went through the same configuration, so
	// they carry the same identity and TD002 sees no change between them.
	const trusted = "github-trusted-publisher:oidc:87d8bb4c-c894-403c-af7e-0d34d7e7327a"
	for _, ver := range []string{"4.0.0", "5.0.0"} {
		info := registry.Find(list, ver)
		if info.Publisher == nil || info.Publisher.Name != trusted {
			t.Errorf("%s publisher = %+v, want the trusted publisher identity %s", ver, info.Publisher, trusted)
		}
	}
	// The per-version maintainer set shrinks from two to one at 5.0.0.
	if before := registry.Find(list, "4.0.0"); len(before.Maintainers) != 2 || len(latest.Maintainers) != 1 {
		t.Errorf("maintainers at 4.0.0 = %+v and at 5.0.0 = %+v, want two then one", before.Maintainers, latest.Maintainers)
	}

	// The order the checks rely on holds between the two kinds the fixtures
	// show: isarray carries signatures only.
	signed, err := c.VersionInfo(ctx, npmRef("isarray", "2.0.4"))
	if err != nil {
		t.Fatal(err)
	}
	if signed.Provenance.Kind != model.ProvenanceSignature {
		t.Fatalf("isarray 2.0.4 provenance = %s, want signature", signed.Provenance.Kind)
	}
	if signed.Provenance.Strength() >= latest.Provenance.Strength() {
		t.Errorf("signature strength %d should be below attestation strength %d", signed.Provenance.Strength(), latest.Provenance.Strength())
	}

	// The downloads API takes the scoped name with a plain slash.
	downloads, err := c.Downloads(ctx, "@sigstore/bundle")
	if err != nil {
		t.Fatal(err)
	}
	if downloads != 7347502 {
		t.Errorf("Downloads = %d, want 7347502", downloads)
	}
	if n := fs.requests("/downloads/point/last-week/@sigstore/bundle"); n != 1 {
		t.Errorf("scoped downloads path requested %d times, want 1; paths: %v", n, fs.seen())
	}
}

func TestPublisherChangeHistory(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	list, err := c.Versions(ctx, "event-stream")
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Versions) != 84 || list.Latest != "4.0.1" {
		t.Errorf("got %d versions with latest %s, want 84 and 4.0.1", len(list.Versions), list.Latest)
	}
	// The registry lists versions in its own order, which is not publish order
	// for this package; that order is preserved.
	wantHead := []string{"0.1.0", "0.2.0", "0.2.1", "0.3.0", "0.4.0", "0.5.0"}
	if got := versionStrings(list)[:6]; !reflect.DeepEqual(got, wantHead) {
		t.Errorf("first versions = %v, want %v", got, wantHead)
	}
	// npm took the package over after the incident; that is the current owner set.
	if want := []model.Publisher{{Name: "npm", Email: "npm@npmjs.com"}}; !reflect.DeepEqual(list.Maintainers, want) {
		t.Errorf("Maintainers = %+v, want %+v", list.Maintainers, want)
	}

	// 3.3.5 is the documented handover: published by right9ctrl after 3.3.4 by dominictarr.
	ref := npmRef("event-stream", "3.3.5")
	current := registry.Find(list, ref.Version)
	if current == nil {
		t.Fatal("3.3.5 missing from the list")
	}
	if current.Publisher == nil || current.Publisher.Name != "right9ctrl" || current.Publisher.Email != "right9ctrl@outlook.com" {
		t.Errorf("3.3.5 publisher = %+v, want right9ctrl", current.Publisher)
	}
	if want := ts(t, "2018-09-05T05:27:47.219Z"); !current.PublishedAt.Equal(want) {
		t.Errorf("3.3.5 published %v, want %v", current.PublishedAt, want)
	}
	wantMaintainers := []model.Publisher{
		{Name: "dominictarr", Email: "dominic.tarr@gmail.com"},
		{Name: "right9ctrl", Email: "right9ctrl@outlook.com"},
	}
	if !reflect.DeepEqual(current.Maintainers, wantMaintainers) {
		t.Errorf("3.3.5 maintainers = %+v, want %+v", current.Maintainers, wantMaintainers)
	}
	wantDeps := map[string]string{
		"duplexer": "^0.1.1", "from": "^0.1.7", "map-stream": "0.0.7", "pause-stream": "^0.0.11",
		"split": "^1.0.1", "stream-combiner": "^0.2.2", "through": "^2.3.8",
	}
	if !reflect.DeepEqual(current.Dependencies, wantDeps) {
		t.Errorf("3.3.5 dependencies = %v, want %v", current.Dependencies, wantDeps)
	}

	previous := registry.Previous(list, ref)
	if previous == nil || previous.Ref.Version != "3.3.4" {
		t.Fatalf("Previous(3.3.5) = %+v, want 3.3.4", previous)
	}
	if previous.Publisher == nil || previous.Publisher.Name != "dominictarr" {
		t.Errorf("3.3.4 publisher = %+v, want dominictarr", previous.Publisher)
	}
	if want := ts(t, "2016-07-17T07:24:09.767Z"); !previous.PublishedAt.Equal(want) {
		t.Errorf("3.3.4 published %v, want %v", previous.PublishedAt, want)
	}
	if want := []model.Publisher{{Name: "dominictarr", Email: "dominic.tarr@gmail.com"}}; !reflect.DeepEqual(previous.Maintainers, want) {
		t.Errorf("3.3.4 maintainers = %+v, want %+v", previous.Maintainers, want)
	}

	window := registry.Window(list, ref, 5)
	wantWindow := []string{"3.3.4", "3.3.3", "3.3.2", "3.3.1", "3.3.0"}
	gotWindow := make([]string, len(window))
	for i := range window {
		gotWindow[i] = window[i].Ref.Version
		if window[i].Publisher == nil || window[i].Publisher.Name != "dominictarr" {
			t.Errorf("window entry %s publisher = %+v, want dominictarr", window[i].Ref.Version, window[i].Publisher)
		}
	}
	if !reflect.DeepEqual(gotWindow, wantWindow) {
		t.Errorf("Window(3.3.5, 5) = %v, want %v", gotWindow, wantWindow)
	}

	// 3.3.6 was unpublished: the time map still names it, the versions object does not.
	if registry.Find(list, "3.3.6") != nil {
		t.Error("3.3.6 is listed although it was unpublished")
	}
	if _, err := c.VersionInfo(ctx, npmRef("event-stream", "3.3.6")); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("VersionInfo(3.3.6) error = %v, want ErrNotFound", err)
	}

	perVersion := []struct {
		version   string
		publisher string // empty means no _npmUser recorded
		kind      model.ProvenanceKind
		integrity string
	}{
		{"2.1.2", "", model.ProvenanceSignature, "sha512-"},
		{"0.9.1", "dominictarr", model.ProvenanceNone, "sha1-0TvVQxOBVPUDFGh4ulAMAF651cs="}, // shasum only, no signatures
		{"4.0.1", "right9ctrl", model.ProvenanceSignature, "sha512-"},
	}
	for _, tt := range perVersion {
		info := registry.Find(list, tt.version)
		if info == nil {
			t.Errorf("%s missing", tt.version)
			continue
		}
		gotPublisher := ""
		if info.Publisher != nil {
			gotPublisher = info.Publisher.Name
		}
		if gotPublisher != tt.publisher {
			t.Errorf("%s publisher = %q, want %q", tt.version, gotPublisher, tt.publisher)
		}
		if info.Provenance.Kind != tt.kind {
			t.Errorf("%s provenance = %s, want %s", tt.version, info.Provenance.Kind, tt.kind)
		}
		if !strings.HasPrefix(info.Integrity, tt.integrity) {
			t.Errorf("%s integrity = %q, want prefix %q", tt.version, info.Integrity, tt.integrity)
		}
	}
}

func TestInstallScriptIntroducedAndDeprecation(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	list, err := c.Versions(ctx, "parcel-bundler")
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Versions) != 43 || list.Latest != "1.12.5" {
		t.Errorf("got %d versions with latest %s, want 43 and 1.12.5", len(list.Versions), list.Latest)
	}

	before, err := c.VersionInfo(ctx, npmRef("parcel-bundler", "1.2.0"))
	if err != nil {
		t.Fatal(err)
	}
	if before.Scripts != nil || before.HasInstallScript() {
		t.Errorf("1.2.0 scripts = %v, want none (test, format, build, prepublish and precommit are not install scripts)", before.Scripts)
	}
	after, err := c.VersionInfo(ctx, npmRef("parcel-bundler", "1.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Scripts) != 1 || !after.HasInstallScript() {
		t.Fatalf("1.2.1 scripts = %v, want exactly the postinstall", after.Scripts)
	}
	cmd := after.Scripts["postinstall"]
	if !strings.HasPrefix(cmd, `node -e "console.log(`) || !strings.Contains(cmd, "opencollective.com/parcel/donate") {
		t.Errorf("1.2.1 postinstall = %q, want the open collective banner", cmd)
	}
	if want := ts(t, "2017-12-18T20:13:20.563Z"); !after.PublishedAt.Equal(want) {
		t.Errorf("1.2.1 published %v, want %v", after.PublishedAt, want)
	}
	if prev := registry.Previous(list, after.Ref); prev == nil || prev.Ref.Version != "1.2.0" {
		t.Errorf("Previous(1.2.1) = %+v, want 1.2.0", prev)
	}
	// Every version from 1.2.1 on keeps the banner, and none before it has one.
	withScript := 0
	for i := range list.Versions {
		if list.Versions[i].HasInstallScript() {
			withScript++
		}
	}
	if withScript != 35 {
		t.Errorf("%d versions have an install script, want 35 (1.2.1 through 1.12.5)", withScript)
	}

	// Every version of parcel-bundler is deprecated, so the package is, with the
	// message of dist-tags.latest.
	wantMessage := "Parcel v1 is no longer maintained. Please migrate to v2, which is published under the 'parcel' package. See https://v2.parceljs.org/getting-started/migration for details."
	if list.Deprecated != wantMessage {
		t.Errorf("Deprecated = %q, want %q", list.Deprecated, wantMessage)
	}
	if IsSecurityHolding(list) {
		t.Error("IsSecurityHolding = true for a merely deprecated package")
	}
	for i := range list.Versions {
		if list.Versions[i].Deprecated == "" {
			t.Errorf("%s has no deprecation message", list.Versions[i].Ref.Version)
		}
	}

	prerelease := map[string]bool{"1.0.0-alpha.1": true, "1.10.0-beta.1": true, "1.0.0": false, "1.12.5": false}
	for ver, want := range prerelease {
		info := registry.Find(list, ver)
		if info == nil {
			t.Errorf("%s missing", ver)
			continue
		}
		if info.Prerelease != want {
			t.Errorf("%s prerelease = %v, want %v", ver, info.Prerelease, want)
		}
	}
	if latest := registry.LatestStable(list); latest == nil || latest.Ref.Version != "1.12.5" {
		t.Errorf("LatestStable = %+v, want 1.12.5", latest)
	}
}

func TestSecurityHoldingPlaceholder(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	list, err := c.Versions(ctx, "flatmap-stream")
	if err != nil {
		t.Fatal(err)
	}
	if !IsSecurityHolding(list) {
		t.Errorf("IsSecurityHolding = false; Deprecated = %q", list.Deprecated)
	}
	if list.Deprecated != SecurityHoldingNote {
		t.Errorf("Deprecated = %q, want %q", list.Deprecated, SecurityHoldingNote)
	}
	if list.Latest != "0.0.1-security" || len(list.Versions) != 1 {
		t.Fatalf("latest %s with %d versions, want 0.0.1-security with 1", list.Latest, len(list.Versions))
	}
	only := list.Versions[0]
	if !only.Prerelease {
		t.Error("0.0.1-security should count as a prerelease")
	}
	// No stable version exists, so a bare ref resolves to the placeholder the
	// registry points at: that is what npm install fetches and the only place
	// the holding note can reach the checks.
	if resolved := registry.LatestStable(list); resolved == nil || resolved.Ref.Version != "0.0.1-security" {
		t.Errorf("LatestStable = %+v, want the placeholder 0.0.1-security", resolved)
	}
	if only.Publisher == nil || only.Publisher.Name != "elizposadas" {
		t.Errorf("placeholder publisher = %+v, want elizposadas", only.Publisher)
	}
	if only.HasInstallScript() || len(only.Dependencies) != 0 || only.Deprecated != "" {
		t.Errorf("placeholder version = %+v, want no scripts, dependencies or deprecation of its own", only)
	}
	if want := []model.Publisher{{Name: "npm", Email: "npm@npmjs.com"}}; !reflect.DeepEqual(list.Maintainers, want) {
		t.Errorf("Maintainers = %+v, want %+v", list.Maintainers, want)
	}
	if want := ts(t, "2018-11-29T16:56:02.864Z"); !list.Created.Equal(want) {
		t.Errorf("Created = %v, want %v", list.Created, want)
	}
	// The malicious 11.1.1 is gone from versions though the time map still names it.
	if _, err := c.VersionInfo(ctx, npmRef("flatmap-stream", "11.1.1")); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("VersionInfo(11.1.1) error = %v, want ErrNotFound", err)
	}
}

func TestDownloads(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	got, err := c.Downloads(ctx, "isarray")
	if err != nil {
		t.Fatal(err)
	}
	if got != 174862265 {
		t.Errorf("Downloads(isarray) = %d, want 174862265", got)
	}
	if n := fs.requests("/downloads/point/last-week/isarray"); n != 1 {
		t.Errorf("downloads path requested %d times, want 1", n)
	}
	if _, err := c.Downloads(ctx, unknownName); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("Downloads(unknown) error = %v, want ErrNotFound", err)
	}
}

func TestBulkDownloads(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	// Unscoped names share one bulk request in first-seen order, duplicates are
	// asked once, the scoped name goes through the point endpoint and the
	// unknown name (null in the bulk answer) is left out.
	got, err := c.BulkDownloads(ctx, []string{"isarray", "event-stream", unknownName, "@sigstore/bundle", "isarray"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"isarray": 174862265, "event-stream": 5619167, "@sigstore/bundle": 7347502}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BulkDownloads = %v, want %v", got, want)
	}
	if n := fs.requests("/downloads/point/last-week/isarray,event-stream," + unknownName); n != 1 {
		t.Errorf("bulk path requested %d times, want 1; paths: %v", n, fs.seen())
	}
	if n := fs.requests("/downloads/point/last-week/@sigstore/bundle"); n != 1 {
		t.Errorf("scoped point path requested %d times, want 1; paths: %v", n, fs.seen())
	}

	// A single unscoped name would be answered in the point shape, so it is sent
	// as a point request; a scoped name the API does not know is left out too.
	got, err = c.BulkDownloads(ctx, []string{"isarray", "@trustdiff/" + unknownName})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int64{"isarray": 174862265}; !reflect.DeepEqual(got, want) {
		t.Errorf("BulkDownloads(single) = %v, want %v", got, want)
	}
	if n := fs.requests("/downloads/point/last-week/isarray"); n != 1 {
		t.Errorf("point path requested %d times, want 1; paths: %v", n, fs.seen())
	}

	// Nothing to ask means nothing asked.
	before := len(fs.seen())
	got, err = c.BulkDownloads(ctx, nil)
	if err != nil || len(got) != 0 {
		t.Errorf("BulkDownloads(nil) = %v, %v, want an empty map", got, err)
	}
	if after := len(fs.seen()); after != before {
		t.Errorf("BulkDownloads(nil) made %d requests", after-before)
	}

	// An invalid name fails before any request; a bulk answer that is not a 200
	// (the fixture server answers 404 for a chunk it does not know) is an error.
	if _, err := c.BulkDownloads(ctx, []string{"isarray", "bad name"}); err == nil {
		t.Error("no error for an invalid name")
	}
	_, err = c.BulkDownloads(ctx, []string{"trustdiff-unknown-a", "trustdiff-unknown-b"})
	if err == nil || errors.Is(err, registry.ErrNotFound) {
		t.Errorf("error for an unexpected bulk status = %v, want a plain error", err)
	}
}

func TestChunks(t *testing.T) {
	tests := []struct {
		name  string
		names []string
		n     int
		want  [][]string
	}{
		{"empty", nil, 2, [][]string{}},
		{"below the limit", []string{"a"}, 2, [][]string{{"a"}}},
		{"exactly the limit", []string{"a", "b"}, 2, [][]string{{"a", "b"}}},
		{"one over", []string{"a", "b", "c"}, 2, [][]string{{"a", "b"}, {"c"}}},
		{"two full", []string{"a", "b", "c", "d"}, 2, [][]string{{"a", "b"}, {"c", "d"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chunks(tt.names, tt.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("chunks(%v, %d) = %v, want %v", tt.names, tt.n, got, tt.want)
			}
		})
	}
}

func TestNotFoundPackage(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"Versions", func() error { _, err := c.Versions(ctx, unknownName); return err }},
		{"VersionInfo", func() error { _, err := c.VersionInfo(ctx, npmRef(unknownName, "1.0.0")); return err }},
		{"Owners", func() error { _, err := c.Owners(ctx, unknownName); return err }},
	}
	for _, tt := range tests {
		if err := tt.call(); !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("%s error = %v, want ErrNotFound", tt.name, err)
		}
	}
	// A 404 is not memoized as a packument, but httpcache caches it for an hour.
	if n := fs.requests("/" + unknownName); n != 1 {
		t.Errorf("404 packument requested %d times, want 1", n)
	}
}

func TestVersionInfoRejectsBadRefs(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	tests := []struct {
		name string
		ref  model.PackageRef
	}{
		{"other ecosystem", model.PackageRef{Ecosystem: model.PyPI, Name: "isarray", Version: "2.0.5"}},
		{"no version", npmRef("isarray", "")},
		{"invalid name", npmRef("@types", "1.0.0")},
	}
	for _, tt := range tests {
		_, err := c.VersionInfo(ctx, tt.ref)
		if err == nil {
			t.Errorf("%s: no error", tt.name)
			continue
		}
		if errors.Is(err, registry.ErrNotFound) {
			t.Errorf("%s: got ErrNotFound, want an argument error: %v", tt.name, err)
		}
	}
	if n := fs.requests("/isarray"); n != 0 {
		t.Errorf("bad refs caused %d requests, want none", n)
	}
}

func TestPackumentSharedThroughDiskCache(t *testing.T) {
	fs := newFixtureServer(t)
	dir := t.TempDir()
	ctx := context.Background()

	first := newClient(t, fs, dir, false)
	if _, err := first.Versions(ctx, "isarray"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.VersionInfo(ctx, npmRef("isarray", "2.0.5")); err != nil {
		t.Fatal(err)
	}
	// A second client with the same cache directory is served from disk.
	second := newClient(t, fs, dir, false)
	if _, err := second.Owners(ctx, "isarray"); err != nil {
		t.Fatal(err)
	}
	if n := fs.requests("/isarray"); n != 1 {
		t.Errorf("packument requested %d times across two clients, want 1", n)
	}

	// Offline with a warm cache works; offline with a cold cache is ErrOffline.
	offline := newClient(t, fs, dir, true)
	if _, err := offline.Versions(ctx, "isarray"); err != nil {
		t.Errorf("offline Versions with a warm cache: %v", err)
	}
	if _, err := offline.Versions(ctx, "event-stream"); !errors.Is(err, httpcache.ErrOffline) {
		t.Errorf("offline Versions with a cold cache error = %v, want ErrOffline", err)
	}
}

// cacheMeta is the readable half of an httpcache entry, enough to see the TTL
// each URL was stored with.
type cacheMeta struct {
	URL string `json:"url"`
	TTL string `json:"ttl"`
}

// readCacheTTLs maps every cached path to the TTL string httpcache recorded.
func readCacheTTLs(t *testing.T, dir, base string) map[string]string {
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
		ttls[strings.TrimPrefix(m.URL, base)] = m.TTL
	}
	return ttls
}

func TestCacheTTLs(t *testing.T) {
	fs := newFixtureServer(t)
	dir := t.TempDir()
	c := newClient(t, fs, dir, false)
	ctx := context.Background()

	if _, err := c.Versions(ctx, "isarray"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Downloads(ctx, "isarray"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BulkDownloads(ctx, []string{"isarray", "event-stream", unknownName}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Versions(ctx, unknownName); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("Versions(unknown) error = %v, want ErrNotFound", err)
	}
	// Every document is refreshed hourly, the 404 included; nothing is immutable
	// on its own because per-version data is read from the packument.
	want := map[string]string{
		"/isarray":                           "1h0m0s",
		"/downloads/point/last-week/isarray": "1h0m0s",
		"/downloads/point/last-week/isarray,event-stream," + unknownName: "1h0m0s",
		"/" + unknownName: "1h0m0s",
	}
	if got := readCacheTTLs(t, dir, fs.URL); !reflect.DeepEqual(got, want) {
		t.Errorf("cache TTLs = %v, want %v", got, want)
	}
}

func TestVersionsReturnsCopies(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	list, err := c.Versions(ctx, "event-stream")
	if err != nil {
		t.Fatal(err)
	}
	info := registry.Find(list, "3.3.5")
	info.Dependencies["evil"] = "1.0.0"
	info.Maintainers[0].Name = "changed"
	info.Publisher.Name = "changed"
	list.Maintainers[0].Name = "changed"

	again, err := c.VersionInfo(ctx, npmRef("event-stream", "3.3.5"))
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := again.Dependencies["evil"]; leaked {
		t.Error("a dependency added by the caller leaked into the memoized packument")
	}
	if again.Maintainers[0].Name != "dominictarr" || again.Publisher.Name != "right9ctrl" {
		t.Errorf("memoized publisher data changed: %+v %+v", again.Maintainers, again.Publisher)
	}
	owners, err := c.Owners(ctx, "event-stream")
	if err != nil {
		t.Fatal(err)
	}
	if owners[0].Name != "npm" {
		t.Errorf("memoized owners changed: %+v", owners)
	}
}

func TestEncodeName(t *testing.T) {
	tests := []struct{ name, want string }{
		{"express", "express"},
		{"@types/node", "@types%2Fnode"},
		{"@sigstore/bundle", "@sigstore%2Fbundle"},
		{"lodash.merge", "lodash.merge"},
	}
	for _, tt := range tests {
		if got := encodeName(tt.name); got != tt.want {
			t.Errorf("encodeName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestCanonicalName(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"express", "express", false},
		// Case is kept: the registry serves legacy mixed-case names as packages of their own.
		{"Express", "Express", false},
		{"JSONStream", "JSONStream", false},
		{"  isarray ", "isarray", false},
		{"@Types/Node", "@Types/Node", false},
		{"", "", true},
		{"@types", "", true},
		{"a/b", "", true},
		{"foo@1.0.0", "", true},
		{"has space", "", true},
	}
	for _, tt := range tests {
		got, err := canonicalName(tt.name)
		if (err != nil) != tt.wantErr {
			t.Errorf("canonicalName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("canonicalName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestMixedCaseNamesAreDistinctPackages(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()

	// JSONStream is requested with its own spelling and answered with its own
	// packument; the fixture server, like the registry, knows nothing under the
	// lowercase path.
	list, err := c.Versions(ctx, "JSONStream")
	if err != nil {
		t.Fatal(err)
	}
	if n := fs.requests("/JSONStream"); n != 1 {
		t.Fatalf("packument path /JSONStream requested %d times, want 1; paths: %v", n, fs.seen())
	}
	if list.Name != "JSONStream" || list.Latest != "1.3.5" || len(list.Versions) != 54 {
		t.Errorf("list = %s latest %s with %d versions, want JSONStream 1.3.5 with 54", list.Name, list.Latest, len(list.Versions))
	}
	info, err := c.VersionInfo(ctx, model.MustParseRef("npm:JSONStream@1.3.5"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Ref.Name != "JSONStream" || info.Publisher == nil || info.Publisher.Name != "dominictarr" {
		t.Errorf("1.3.5 = ref %s publisher %+v, want JSONStream by dominictarr", info.Ref, info.Publisher)
	}
	if want := map[string]string{"through": ">=2.2.7 <3", "jsonparse": "^1.2.0"}; !reflect.DeepEqual(info.Dependencies, want) {
		t.Errorf("1.3.5 dependencies = %v, want %v", info.Dependencies, want)
	}

	// The lowercase spelling is a different package, here one the fixture server
	// does not have, and the answer is never taken from the mixed-case memo.
	if _, err := c.Versions(ctx, "jsonstream"); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("Versions(jsonstream) error = %v, want ErrNotFound", err)
	}
	if n := fs.requests("/jsonstream"); n != 1 {
		t.Errorf("packument path /jsonstream requested %d times, want 1; paths: %v", n, fs.seen())
	}
}

// The remaining tests feed hand-written documents to the parser to pin the
// behavior for shapes the recorded fixtures do not contain.

func parse(t *testing.T, doc string) *packument {
	t.Helper()
	p, err := parsePackument("pkg", []byte(doc), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("parsePackument: %v", err)
	}
	return p
}

func TestParseOptionalDependenciesAreMerged(t *testing.T) {
	p := parse(t, `{"name":"pkg","dist-tags":{"latest":"1.0.0"},"time":{"1.0.0":"2026-01-02T03:04:05.000Z"},
		"versions":{"1.0.0":{"dependencies":{"a":"^1.0.0","b":"^2.0.0"},"optionalDependencies":{"b":"^2.1.0","fsevents":"2.3.2"}}}}`)
	// The optional entry wins for b, and requirements stay verbatim so that an
	// exact one such as fsevents can be resolved.
	want := map[string]string{"a": "^1.0.0", "b": "^2.1.0", "fsevents": "2.3.2"}
	if got := p.versions[0].Dependencies; !reflect.DeepEqual(got, want) {
		t.Errorf("Dependencies = %v, want %v", got, want)
	}
}

func TestParseTolerantFields(t *testing.T) {
	tests := []struct {
		name string
		doc  string // the version object of 1.0.0
		want model.VersionInfo
	}{
		{
			name: "deprecated true without a message",
			doc:  `{"deprecated":true}`,
			want: model.VersionInfo{Deprecated: "deprecated without a message"},
		},
		{
			name: "deprecated false",
			doc:  `{"deprecated":false}`,
			want: model.VersionInfo{},
		},
		{
			name: "deprecated message is trimmed",
			doc:  `{"deprecated":"  use other  "}`,
			want: model.VersionInfo{Deprecated: "use other"},
		},
		{
			name: "scripts that is not an object is ignored",
			doc:  `{"scripts":"npm test"}`,
			want: model.VersionInfo{},
		},
		{
			name: "non-string script and dependency values are dropped",
			doc:  `{"scripts":{"postinstall":"node x.js","install":{"cmd":"x"}},"dependencies":{"a":"^1","b":2}}`,
			want: model.VersionInfo{Scripts: map[string]string{"postinstall": "node x.js"}, Dependencies: map[string]string{"a": "^1"}},
		},
		{
			name: "every install script name is kept and nothing else",
			doc:  `{"scripts":{"preinstall":"a","install":"b","postinstall":"c","prepare":"d","prepublish":"e","test":"f"}}`,
			want: model.VersionInfo{Scripts: map[string]string{"preinstall": "a", "install": "b", "postinstall": "c"}},
		},
		{
			name: "maintainers that is not an array is ignored, nameless entries dropped",
			doc:  `{"maintainers":"alice <a@example.com>","_npmUser":{"email":"nobody@example.com"}}`,
			want: model.VersionInfo{},
		},
		{
			// The shape observed on @sigstore/bundle 4.0.0 and 5.0.0 (2026-09-09).
			name: "trusted publisher configuration is the publisher identity",
			doc:  `{"_npmUser":{"name":"GitHub Actions","email":"npm-oidc-no-reply@github.com","trustedPublisher":{"id":"github","oidcConfigId":"oidc:87d8bb4c-c894-403c-af7e-0d34d7e7327a"}}}`,
			want: model.VersionInfo{Publisher: &model.Publisher{Name: "github-trusted-publisher:oidc:87d8bb4c-c894-403c-af7e-0d34d7e7327a", Email: "npm-oidc-no-reply@github.com"}},
		},
		{
			name: "trusted publisher without a configuration id keeps the account name",
			doc:  `{"_npmUser":{"name":"GitHub Actions","email":"npm-oidc-no-reply@github.com","trustedPublisher":{"id":"github"}}}`,
			want: model.VersionInfo{Publisher: &model.Publisher{Name: "GitHub Actions", Email: "npm-oidc-no-reply@github.com"}},
		},
		{
			name: "trusted publisher of another shape is ignored",
			doc:  `{"_npmUser":{"name":"GitHub Actions","trustedPublisher":"github"}}`,
			want: model.VersionInfo{Publisher: &model.Publisher{Name: "GitHub Actions"}},
		},
		{
			name: "gypfile without an install script is the implicit node-gyp rebuild",
			doc:  `{"gypfile":true,"scripts":{"test":"node test.js"}}`,
			want: model.VersionInfo{Scripts: map[string]string{"install": implicitInstallScript}},
		},
		{
			name: "gypfile with a declared install script keeps the declared one",
			doc:  `{"gypfile":true,"scripts":{"install":"node-gyp rebuild --release"}}`,
			want: model.VersionInfo{Scripts: map[string]string{"install": "node-gyp rebuild --release"}},
		},
		{
			name: "gypfile with a preinstall script gets no default install",
			doc:  `{"gypfile":true,"scripts":{"preinstall":"node check.js"}}`,
			want: model.VersionInfo{Scripts: map[string]string{"preinstall": "node check.js"}},
		},
		{
			name: "gypfile that is not a boolean is not set",
			doc:  `{"gypfile":"yes","scripts":{"postinstall":"node x.js"}}`,
			want: model.VersionInfo{Scripts: map[string]string{"postinstall": "node x.js"}},
		},
		{
			name: "maintainer entries that are not objects are dropped",
			doc:  `{"maintainers":["alice",{"name":"bob","email":"b@example.com"},{"email":"x@example.com"}]}`,
			want: model.VersionInfo{Maintainers: []model.Publisher{{Name: "bob", Email: "b@example.com"}}},
		},
		{
			name: "attestations with a url only still count",
			doc:  `{"dist":{"attestations":{"url":"https://registry.npmjs.org/-/npm/v1/attestations/pkg@1.0.0"},"signatures":[{"keyid":"k","sig":"s"}]}}`,
			want: model.VersionInfo{Provenance: model.Provenance{Kind: model.ProvenanceAttestation}},
		},
		{
			name: "empty attestations object is not evidence",
			doc:  `{"dist":{"attestations":{},"signatures":[{"keyid":"k","sig":"s"}]}}`,
			want: model.VersionInfo{Provenance: model.Provenance{Kind: model.ProvenanceSignature}},
		},
		{
			name: "legacy pgp signature alone is no evidence",
			doc:  `{"dist":{"npm-signature":"-----BEGIN PGP SIGNATURE-----","integrity":"sha512-x"}}`,
			want: model.VersionInfo{Integrity: "sha512-x"},
		},
		{
			name: "shasum that is not sha1 gives no integrity",
			doc:  `{"dist":{"shasum":"abcd"}}`,
			want: model.VersionInfo{},
		},
		{
			name: "version object that is not an object keeps the publish time",
			doc:  `"broken"`,
			want: model.VersionInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := parse(t, `{"name":"pkg","dist-tags":{"latest":"1.0.0"},"time":{"1.0.0":"2026-01-02T03:04:05.000Z"},"versions":{"1.0.0":`+tt.doc+`}}`)
			if len(p.versions) != 1 {
				t.Fatalf("got %d versions, want 1", len(p.versions))
			}
			want := tt.want
			want.Ref = npmRef("pkg", "1.0.0")
			want.PublishedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
			want.WeeklyDownloads = -1
			if want.Provenance.Kind == "" {
				want.Provenance.Kind = model.ProvenanceNone
			}
			if got := p.versions[0]; !reflect.DeepEqual(got, want) {
				t.Errorf("version =\n%+v\nwant\n%+v", got, want)
			}
		})
	}
}

func TestParseTopLevelShapes(t *testing.T) {
	t.Run("registry order is kept and unpublished time entries are skipped", func(t *testing.T) {
		p := parse(t, `{"name":"pkg","dist-tags":{"latest":"1.0.0"},
			"time":{"created":"2026-01-01T00:00:00.000Z","modified":"2026-01-03T00:00:00.000Z","2.0.0":"2026-01-02T00:00:00.000Z","1.0.0":"2026-01-01T00:00:00.000Z","9.9.9":"2026-01-03T00:00:00.000Z","unpublished":{"time":"2026-01-03T00:00:00.000Z","versions":["9.9.9"]}},
			"versions":{"2.0.0":{},"1.0.0":{}}}`)
		if got, want := []string{p.versions[0].Ref.Version, p.versions[1].Ref.Version}, []string{"2.0.0", "1.0.0"}; !reflect.DeepEqual(got, want) {
			t.Errorf("order = %v, want %v", got, want)
		}
		if p.created.IsZero() || p.modified.IsZero() {
			t.Errorf("created %v modified %v, want both set", p.created, p.modified)
		}
		if _, ok := p.index["9.9.9"]; ok {
			t.Error("a version named only in the time map was listed")
		}
	})
	t.Run("all versions deprecated without latest uses the newest message", func(t *testing.T) {
		p := parse(t, `{"name":"pkg","dist-tags":{"latest":"3.0.0"},
			"time":{"1.0.0":"2026-01-01T00:00:00.000Z","2.0.0":"2026-01-02T00:00:00.000Z"},
			"versions":{"1.0.0":{"deprecated":"old"},"2.0.0":{"deprecated":"newer"}}}`)
		if p.deprecated != "newer" {
			t.Errorf("deprecated = %q, want newer", p.deprecated)
		}
	})
	t.Run("one live version keeps the package alive", func(t *testing.T) {
		p := parse(t, `{"name":"pkg","dist-tags":{"latest":"2.0.0"},"time":{},
			"versions":{"1.0.0":{"deprecated":"old"},"2.0.0":{}}}`)
		if p.deprecated != "" {
			t.Errorf("deprecated = %q, want empty", p.deprecated)
		}
	})
	t.Run("holding description on the latest version only", func(t *testing.T) {
		p := parse(t, `{"name":"pkg","description":"was a real package","dist-tags":{"latest":"0.0.1-security"},"time":{},
			"versions":{"0.0.1-security":{"description":"Security Holding Package"}}}`)
		if p.deprecated != SecurityHoldingNote {
			t.Errorf("deprecated = %q, want the holding note", p.deprecated)
		}
	})
	t.Run("no versions", func(t *testing.T) {
		p := parse(t, `{"name":"pkg","time":{"created":"2026-01-01T00:00:00.000Z","unpublished":{}}}`)
		if len(p.versions) != 0 || p.deprecated != "" || p.latest != "" {
			t.Errorf("got %+v, want an empty package", p)
		}
	})
	t.Run("versions that is not an object is an error", func(t *testing.T) {
		if _, err := parsePackument("pkg", []byte(`{"name":"pkg","versions":[]}`), slog.New(slog.DiscardHandler)); err == nil {
			t.Error("no error for an array of versions")
		}
	})
	t.Run("body that is not JSON is an error", func(t *testing.T) {
		if _, err := parsePackument("pkg", []byte(`<html>`), slog.New(slog.DiscardHandler)); err == nil {
			t.Error("no error for HTML")
		}
	})
}

// TestPrepareIsNotAnInstallScript pins finding F6 of docs/review-2026-09-10.md.
// npm runs a dependency's prepare only when the dependency comes from git or from
// a local folder, never for the registry tarball a lockfile entry names, so a
// release that adds nothing but a husky hook has added no code that any install
// will run. Recording it cost twice, and Scripts is the only input either check
// reads, so both costs are paid here: install-script-introduced blocked such a
// release, and while the previous version carried the hook the release that added
// a real postinstall reported nothing, because the check compares against a
// version it thought already had a script.
func TestPrepareIsNotAnInstallScript(t *testing.T) {
	// #nosec G304 -- a fixture of this repository.
	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "regressions",
		"f6-prepare-is-not-an-install-script", "packument.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := parsePackument("trustdiff-fixture-hooks", doc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("parsePackument: %v", err)
	}
	if len(p.versions) != 3 {
		t.Fatalf("read %d versions, want 3", len(p.versions))
	}
	base, hooked, scripted := &p.versions[0], &p.versions[1], &p.versions[2]

	for _, v := range []*model.VersionInfo{base, hooked} {
		if v.Scripts != nil {
			t.Errorf("%s Scripts = %v, want none recorded", v.Ref.Version, v.Scripts)
		}
		// This is what both checks read, and what made the release after the hook
		// look like one whose predecessor already ran code.
		if v.HasInstallScript() {
			t.Errorf("%s counts as running code at install time", v.Ref.Version)
		}
	}
	want := map[string]string{"postinstall": "node ./scripts/setup.js"}
	if !reflect.DeepEqual(scripted.Scripts, want) {
		t.Errorf("1.2.0 Scripts = %v, want the postinstall alone", scripted.Scripts)
	}
}
