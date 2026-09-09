// Package pypi is the PyPI registry client. It reads the project JSON for the
// version list and the ownership set, the per-release JSON for dependencies and
// files, and the PEP 740 integrity endpoint for provenance, and implements
// registry.Source.
//
// Endpoints, verified 2026-09-09 against https://docs.pypi.org/api/json/ and
// https://docs.pypi.org/api/integrity/ and against the live responses for
// requests, sampleproject and pycrypto (recorded under testdata):
//
//	GET https://pypi.org/pypi/<project>/json                                 project JSON, TTL 1 h
//	GET https://pypi.org/pypi/<project>/<version>/json                       release JSON, immutable
//	GET https://pypi.org/integrity/<project>/<version>/<filename>/provenance PEP 740, immutable; 404 means none
//
// Project names are normalized per PEP 503 before they enter a URL, so
// Zope.Interface, zope_interface and zope-interface all fetch /pypi/zope-interface/json.
//
// What PyPI does not expose, verified the same day: a per-version publisher
// (VersionInfo.Publisher stays nil; TD002 uses the baseline for PyPI), download
// counts (info.downloads is always -1, so Downloads returns registry.ErrUnsupported),
// and deprecation (Deprecated stays empty; the Simple API's project-status marker is
// not read yet).
package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// DefaultBaseURL is the registry the client talks to unless WithBaseURL says otherwise.
const DefaultBaseURL = "https://pypi.org"

const (
	// acceptJSON is the media type the JSON API documents for its examples.
	acceptJSON = "application/json"
	// acceptIntegrity is the media type of the integrity API. It is the default
	// when no Accept header is sent, and any other value yields 406; verified
	// 2026-09-09 against https://docs.pypi.org/api/integrity/.
	acceptIntegrity = "application/vnd.pypi.integrity.v1+json"

	// projectTTL is the freshness of the project JSON: new releases and ownership
	// changes show up within the hour.
	projectTTL = httpcache.DefaultTTL
	// releaseTTL and provenanceTTL mark data that never changes once published:
	// the files of a release and their attestations. A yank does change the
	// release JSON, but the yanked flag on the version list is refreshed hourly and
	// is what TD011 reads.
	releaseTTL    = httpcache.Forever
	provenanceTTL = httpcache.Forever

	// Wheel and source distribution package types as the JSON API spells them.
	typeWheel = "bdist_wheel"
	typeSdist = "sdist"

	// sdistScriptKey and sdistScriptValue are the Scripts entry of a release that
	// ships no wheel: pip builds it from the sdist, which runs setup.py or the
	// build backend at install time.
	sdistScriptKey   = "setup.py"
	sdistScriptValue = "sdist-only release, setup.py runs at install"

	// organizationPrefix marks an organization in a publisher name, so that an
	// organization slug is never mistaken for a user account of the same name.
	organizationPrefix = "org:"

	// uploadTimeLayout is the shape of the legacy upload_time field, UTC without a
	// zone designator: "2014-06-20T08:10:20". Verified 2026-09-09.
	uploadTimeLayout = "2006-01-02T15:04:05"
)

// Client is the PyPI client. All requests go through internal/httpcache, which
// supplies the User-Agent, the disk cache, the per-host rate limit and retries.
type Client struct {
	http *httpcache.Client
	base string
	log  *slog.Logger
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL points the client at another host, for example an httptest server
// in tests or a private mirror that serves the same JSON API.
func WithBaseURL(base string) Option {
	return func(c *Client) { c.base = strings.TrimRight(base, "/") }
}

// WithLogger routes diagnostics to l instead of discarding them.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) {
		if l != nil {
			c.log = l
		}
	}
}

// New returns a client using the shared HTTP cache.
func New(h *httpcache.Client, opts ...Option) *Client {
	c := &Client{http: h, base: DefaultBaseURL, log: slog.New(slog.DiscardHandler)}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Ecosystem implements registry.Source.
func (c *Client) Ecosystem() model.Ecosystem { return model.PyPI }

// Versions implements registry.Source from the project JSON. Every version of the
// releases map becomes an entry, ordered by version: PublishedAt is the earliest
// upload time of the release's files (zero when the release has no files), Yanked
// is true when every file is yanked, Prerelease follows PEP 440, Scripts marks an
// sdist-only release and Integrity carries the sha256 of the preferred file.
// Latest is info.version and Maintainers the ownership set. Publisher is nil
// because PyPI does not record who uploaded a release.
func (c *Client) Versions(ctx context.Context, name string) (*registry.VersionList, error) {
	name = model.NormalizeName(model.PyPI, name)
	proj, err := c.project(ctx, name)
	if err != nil {
		return nil, err
	}
	// Map order is random; a lexical sort first makes the version sort, which is
	// stable, deterministic for spellings it cannot parse.
	versions := make([]string, 0, len(proj.Releases))
	for v := range proj.Releases {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	version.Sort(model.PyPI, versions)

	list := &registry.VersionList{
		Ecosystem:   model.PyPI,
		Name:        name,
		Latest:      proj.Info.Version,
		Maintainers: proj.Ownership.publishers(),
		Versions:    make([]model.VersionInfo, 0, len(versions)),
	}
	for _, v := range versions {
		files := proj.Releases[v]
		if len(files) == 0 {
			c.log.Debug("release has no files", "package", name, "version", v)
		}
		list.Versions = append(list.Versions, fromFiles(name, v, files, false))
	}
	return list, nil
}

// VersionInfo implements registry.Source from the release JSON plus one
// provenance lookup. Dependencies come from info.requires_dist keyed by the
// normalized project name, with the specifier and any environment marker kept as
// written. Provenance queries the PEP 740 endpoint for the first wheel, or the
// sdist when there is no wheel: a bundle yields an unverified attestation naming
// the publisher, a 404 yields none. Any other failure of that lookup fails the
// call, because a zero Provenance would read as a downgrade.
func (c *Client) VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	if ref.Ecosystem != "" && ref.Ecosystem != model.PyPI {
		return nil, fmt.Errorf("pypi: %s is not a PyPI package", ref)
	}
	if ref.Version == "" {
		return nil, fmt.Errorf("pypi: %s: a version is required", ref)
	}
	name := model.NormalizeName(model.PyPI, ref.Name)
	rel, err := c.release(ctx, name, ref.Version)
	if err != nil {
		return nil, err
	}
	ver := rel.Info.Version
	if ver == "" {
		ver = ref.Version
	}
	info := fromFiles(name, ver, rel.URLs, rel.Info.Yanked)
	info.Dependencies = dependencies(rel.Info.RequiresDist, c.log)
	info.Provenance, err = c.provenance(ctx, name, ver, preferredFile(rel.URLs))
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// Owners implements registry.Source from the ownership object of the project
// JSON: one publisher per role entry, named by the user, preceded by the owning
// organization as "org:<slug>" when there is one. PyPI lists roles Owner first,
// then Maintainer, alphabetically within each. A response without the ownership
// object reports registry.ErrUnsupported.
func (c *Client) Owners(ctx context.Context, name string) ([]model.Publisher, error) {
	name = model.NormalizeName(model.PyPI, name)
	proj, err := c.project(ctx, name)
	if err != nil {
		return nil, err
	}
	if proj.Ownership == nil {
		return nil, fmt.Errorf("pypi: ownership of %s: %w", name, registry.ErrUnsupported)
	}
	return proj.Ownership.publishers(), nil
}

// Downloads implements registry.Source. The JSON API reports -1 for every count
// (verified 2026-09-09: info.downloads and every file's downloads) and PyPI has no
// other download endpoint, so the answer is -1 and registry.ErrUnsupported; TD012
// falls back to deps.dev for PyPI.
func (c *Client) Downloads(_ context.Context, name string) (int64, error) {
	name = model.NormalizeName(model.PyPI, name)
	return -1, fmt.Errorf("pypi: download counts for %s: %w", name, registry.ErrUnsupported)
}

// project fetches and decodes GET /pypi/<project>/json.
func (c *Client) project(ctx context.Context, name string) (*projectJSON, error) {
	u := c.base + "/pypi/" + url.PathEscape(name) + "/json"
	resp, err := c.http.Get(ctx, u, httpcache.Request{Accept: acceptJSON, TTL: projectTTL})
	if err != nil {
		return nil, fmt.Errorf("pypi: project %s: %w", name, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("pypi: project %s: %w", name, registry.ErrNotFound)
	}
	var proj projectJSON
	if err := json.Unmarshal(resp.Body, &proj); err != nil {
		return nil, fmt.Errorf("pypi: project %s: decoding %s: %w", name, u, err)
	}
	return &proj, nil
}

// release fetches and decodes GET /pypi/<project>/<version>/json.
func (c *Client) release(ctx context.Context, name, ver string) (*releaseJSON, error) {
	u := c.base + "/pypi/" + url.PathEscape(name) + "/" + url.PathEscape(ver) + "/json"
	resp, err := c.http.Get(ctx, u, httpcache.Request{Accept: acceptJSON, TTL: releaseTTL})
	if err != nil {
		return nil, fmt.Errorf("pypi: release %s %s: %w", name, ver, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("pypi: release %s %s: %w", name, ver, registry.ErrNotFound)
	}
	var rel releaseJSON
	if err := json.Unmarshal(resp.Body, &rel); err != nil {
		return nil, fmt.Errorf("pypi: release %s %s: decoding %s: %w", name, ver, u, err)
	}
	return &rel, nil
}

// provenance asks the integrity API about one file. A release without a file
// has nothing to attest and reports none without a request.
func (c *Client) provenance(ctx context.Context, name, ver string, f *fileJSON) (model.Provenance, error) {
	none := model.Provenance{Kind: model.ProvenanceNone}
	if f == nil || f.Filename == "" {
		return none, nil
	}
	u := c.base + "/integrity/" + url.PathEscape(name) + "/" + url.PathEscape(ver) + "/" + url.PathEscape(f.Filename) + "/provenance"
	resp, err := c.http.Get(ctx, u, httpcache.Request{Accept: acceptIntegrity, TTL: provenanceTTL})
	if err != nil {
		return model.Provenance{}, fmt.Errorf("pypi: provenance of %s %s: %w", name, ver, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return none, nil
	}
	var doc provenanceJSON
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return model.Provenance{}, fmt.Errorf("pypi: provenance of %s %s: decoding %s: %w", name, ver, u, err)
	}
	if len(doc.AttestationBundles) == 0 {
		c.log.Debug("provenance object carries no attestation bundle", "package", name, "version", ver, "file", f.Filename)
		return none, nil
	}
	// The registry served the bundle but nobody has verified the attestation
	// against the file yet; deps.dev's verified flag and a later Sigstore
	// verification raise Verified. The first bundle names the publisher; PyPI
	// records one bundle per upload and the file was uploaded once.
	return model.Provenance{
		Kind:     model.ProvenanceAttestation,
		Verified: false,
		Identity: doc.AttestationBundles[0].Publisher.identity(),
	}, nil
}

// projectJSON is the subset of GET /pypi/<project>/json the client reads. Field
// names verified 2026-09-09 against the live response for requests and against
// https://docs.pypi.org/api/json/. The documentation lists releases as deprecated
// in favor of the Index API; it is still served and is the only place the JSON API
// pairs every version with its files. The ownership object is documented and
// present on every live response seen; it is a pointer so that its absence can be
// told from an empty one.
type projectJSON struct {
	Info      infoJSON              `json:"info"`
	Releases  map[string][]fileJSON `json:"releases"`
	Ownership *ownershipJSON        `json:"ownership"`
}

// releaseJSON is the subset of GET /pypi/<project>/<version>/json the client
// reads: the same info object for that version plus its files under urls; there
// is no releases key. Verified 2026-09-09.
type releaseJSON struct {
	Info infoJSON   `json:"info"`
	URLs []fileJSON `json:"urls"`
}

// infoJSON is the info object. version is the latest version on the project
// route and the requested one on the release route; requires_dist is null for
// releases that declared no dependencies (pycrypto 2.6.1); yanked and
// yanked_reason describe the release on the release route. Verified 2026-09-09.
type infoJSON struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	RequiresDist []string `json:"requires_dist"`
	Yanked       bool     `json:"yanked"`
	YankedReason string   `json:"yanked_reason"`
}

// fileJSON is one distribution file as listed under releases[<version>] and
// urls. packagetype is sdist or bdist_wheel for everything uploaded this decade
// (older releases carry bdist_egg and friends); upload_time_iso_8601 is RFC 3339
// with microseconds and Z, upload_time the same instant without a zone; digests
// carries blake2b_256, md5 and sha256. Verified 2026-09-09.
type fileJSON struct {
	Filename      string            `json:"filename"`
	PackageType   string            `json:"packagetype"`
	UploadTimeISO string            `json:"upload_time_iso_8601"`
	UploadTime    string            `json:"upload_time"`
	Yanked        bool              `json:"yanked"`
	YankedReason  string            `json:"yanked_reason"`
	Digests       map[string]string `json:"digests"`
}

// uploadTime parses upload_time_iso_8601 and falls back to upload_time.
func (f *fileJSON) uploadTime() (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, f.UploadTimeISO); err == nil {
		return t, true
	}
	if t, err := time.Parse(uploadTimeLayout, f.UploadTime); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// ownershipJSON is the ownership object: roles sorted Owner before Maintainer and
// alphabetically within each role, empty when none are assigned; organization is
// the owning organization's slug or null. Verified 2026-09-09 against the live
// responses (requests: three owners, no organization; sampleproject: no roles,
// organization pypa) and the documentation.
type ownershipJSON struct {
	Organization string     `json:"organization"`
	Roles        []roleJSON `json:"roles"`
}

type roleJSON struct {
	Role string `json:"role"`
	User string `json:"user"`
}

// publishers renders the ownership set: the organization first, then the roles
// as PyPI lists them. nil when the object is absent, empty when it lists nobody.
func (o *ownershipJSON) publishers() []model.Publisher {
	if o == nil {
		return nil
	}
	out := make([]model.Publisher, 0, len(o.Roles)+1)
	if o.Organization != "" {
		out = append(out, model.Publisher{Name: organizationPrefix + o.Organization})
	}
	for _, r := range o.Roles {
		if r.User == "" {
			continue
		}
		out = append(out, model.Publisher{Name: r.User})
	}
	return out
}

// provenanceJSON is the PEP 740 provenance object served by the integrity API:
// attestation_bundles, each with a publisher and its attestations, and a format
// version. Verified 2026-09-09 against the live answers for sampleproject 4.0.0,
// requests 2.34.2 and urllib3 2.5.0 and against https://docs.pypi.org/api/integrity/.
type provenanceJSON struct {
	AttestationBundles []bundleJSON `json:"attestation_bundles"`
	Version            int          `json:"version"`
}

type bundleJSON struct {
	Publisher    *publisherJSON    `json:"publisher"`
	Attestations []json.RawMessage `json:"attestations"`
}

// publisherJSON is the Trusted Publishing identity of a bundle. kind is GitHub or
// GitLab, repository the owner/name slug, workflow the workflow file name and
// environment the deployment environment, empty when none was used. Some bundles
// also carry claims (null when seen); it is not read. Verified 2026-09-09.
type publisherJSON struct {
	Kind        string `json:"kind"`
	Repository  string `json:"repository"`
	Workflow    string `json:"workflow"`
	Environment string `json:"environment"`
}

// identity renders the publisher as <kind>:<repository>/<workflow> in lowercase
// kind, for example github:pypa/sampleproject/release.yml, dropping the parts
// that are missing. Empty for a bundle without a publisher.
func (p *publisherJSON) identity() string {
	if p == nil {
		return ""
	}
	id := p.Repository
	if p.Workflow != "" {
		if id != "" {
			id += "/"
		}
		id += p.Workflow
	}
	if kind := strings.ToLower(strings.TrimSpace(p.Kind)); kind != "" {
		if id == "" {
			return kind
		}
		return kind + ":" + id
	}
	return id
}

// fromFiles fills the fields both routes carry per release. yanked is the
// release-level flag of the release route; the project route has none, so a
// release counts as yanked there when every file is.
func fromFiles(name, ver string, files []fileJSON, yanked bool) model.VersionInfo {
	info := model.VersionInfo{
		Ref:             model.PackageRef{Ecosystem: model.PyPI, Name: name, Version: ver},
		PublishedAt:     earliestUpload(files),
		Prerelease:      version.IsPrerelease(model.PyPI, ver),
		Yanked:          yanked || allYanked(files),
		WeeklyDownloads: -1,
	}
	if f := preferredFile(files); f != nil {
		if sum := f.Digests["sha256"]; sum != "" {
			info.Integrity = "sha256:" + sum
		}
	}
	if sdistOnly(files) {
		info.Scripts = map[string]string{sdistScriptKey: sdistScriptValue}
	}
	return info
}

// earliestUpload is the publish time of a release: the earliest upload among its
// files, since a release exists from its first file on. Zero when no file has a
// parsable time.
func earliestUpload(files []fileJSON) time.Time {
	var earliest time.Time
	for i := range files {
		t, ok := files[i].uploadTime()
		if ok && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	return earliest
}

// allYanked reports whether the release has files and every one of them is yanked.
func allYanked(files []fileJSON) bool {
	if len(files) == 0 {
		return false
	}
	for i := range files {
		if !files[i].Yanked {
			return false
		}
	}
	return true
}

// preferredFile is the file that stands for the release: the first wheel, else
// the first sdist, else nil. It is the file whose digest and provenance the
// release reports.
func preferredFile(files []fileJSON) *fileJSON {
	for i := range files {
		if files[i].PackageType == typeWheel {
			return &files[i]
		}
	}
	for i := range files {
		if files[i].PackageType == typeSdist {
			return &files[i]
		}
	}
	return nil
}

// sdistOnly reports whether the release ships a source distribution and no wheel,
// so that installing it runs the build at install time.
func sdistOnly(files []fileJSON) bool {
	hasSdist := false
	for i := range files {
		switch files[i].PackageType {
		case typeWheel:
			return false
		case typeSdist:
			hasSdist = true
		}
	}
	return hasSdist
}

var _ registry.Source = (*Client)(nil)
