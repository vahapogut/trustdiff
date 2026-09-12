// Package npm is the npm registry client. It reads one full packument per
// package from registry.npmjs.org and weekly download counts from api.npmjs.org
// and maps them onto the registry.Source contract. Publish times, publishers,
// maintainers, install scripts, dependencies, deprecation and provenance
// evidence all come from that single document, which is memoized per client, so
// VersionInfo and Owners cost no request beyond the one Versions made.
//
// Endpoints, verified 2026-09-09 against live responses and the registry
// documentation (https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md
// and https://github.com/npm/registry/blob/main/docs/download-counts.md):
//
//	GET https://registry.npmjs.org/<name>                               full packument, TTL 1 h
//	GET https://api.npmjs.org/downloads/point/last-week/<name>          weekly downloads, TTL 1 h
//	GET https://api.npmjs.org/downloads/point/last-week/<a>,<b>,...     bulk downloads, at most 128 unscoped names, TTL 1 h
//
// A scoped name is sent as @scope%2Fname to the registry and as @scope/name to
// the downloads API, which is how its documentation spells it (both spellings
// were answered on 2026-09-09). The bulk endpoint refuses scoped names with HTTP
// 400 (verified the same day), so BulkDownloads looks them up one by one. A 404
// from either API is registry.ErrNotFound.
//
// Names are sent exactly as given, case included. The registry rejects
// uppercase in new names but legacy mixed-case packages are still served under
// their own spelling and are distinct from their lowercase namesakes: on
// 2026-09-09 registry.npmjs.org/JSONStream was dominictarr's package with 54
// versions and latest 1.3.5, while registry.npmjs.org/jsonstream was an
// unrelated package at 1.0.3. Folding case would evaluate the wrong one.
//
// Two things the plan names are absent on purpose. The abbreviated packument
// (Accept: application/vnd.npm.install-v1+json) has no time and no _npmUser,
// which every check needs, so it would never be requested instead of the full
// one. There is no per-version request either: the registry serves one
// (GET /<name>/<version>, verified 2026-09-09) but it carries nothing the
// packument does not, so the publish times, immutable as they are, ride along
// with the hourly packument instead of being cached forever on their own.
//
// Mapping decisions a reviewer should know:
//
//   - Scripts keeps only preinstall, install and postinstall, the scripts npm runs
//     when it installs the package as a dependency from the registry. prepare is
//     not one of them, because npm runs a dependency's prepare for a git or a
//     local dependency and never for a registry tarball; installScriptNames
//     carries the evidence. A version the registry marks gypfile: true (it ships a
//     binding.gyp) that declares neither install nor preinstall gets the install
//     script npm runs by default for it, node-gyp rebuild, so the implicit native
//     build shows up like a declared one.
//   - Dependencies merges optionalDependencies into dependencies: npm installs
//     optional dependencies by default, so a newly introduced one is as much a
//     signal as a regular one. Requirements are kept verbatim so that a check can
//     resolve them against the version list.
//   - Publisher is _npmUser. For a trusted publishing release _npmUser is the
//     same synthetic account on every package ({"name": "GitHub Actions",
//     "email": "npm-oidc-no-reply@github.com"}) plus a trustedPublisher object
//     that names the configuration; the publisher is then rendered as
//     "<id>-trusted-publisher:<oidcConfigId>" so that the identity TD002
//     compares is the trusted publisher configuration, not the shared account
//     name. See human for the observed shape.
//   - Provenance is attestation when dist.attestations is present (Verified stays
//     false; the runner applies the deps.dev verification), signature when only
//     dist.signatures is present, and none otherwise. The legacy PGP
//     npm-signature field is ignored: the attestation is the evidence the brief
//     names for npm.
//   - npm has no package-level deprecation. VersionList.Deprecated is set when
//     every version is deprecated (the message of dist-tags.latest, or of the
//     newest version when latest is missing), and for a security holding package
//     it is SecurityHoldingNote.
//   - The time map can name versions that no longer exist (unpublished or removed
//     ones, for example event-stream 3.3.6 and flatmap-stream 11.1.1 on
//     2026-09-09). Only versions present in the versions object are listed, in the
//     order the registry returned them.
package npm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
	"github.com/vahapogut/trustdiff/internal/registry"
)

const (
	// DefaultRegistryURL is the public registry; WithRegistryURL overrides it.
	DefaultRegistryURL = "https://registry.npmjs.org"
	// DefaultDownloadsURL is the download counts API; WithDownloadsURL overrides it.
	DefaultDownloadsURL = "https://api.npmjs.org"

	// SecurityHoldingNote is the VersionList.Deprecated text of a security holding
	// package. When npm removes a package for malware it leaves a placeholder
	// whose description reads "security holding package", whose only version is
	// 0.0.1-security and whose repository is github.com/npm/security-holder.
	// Verified 2026-09-09 on flatmap-stream (OSV MAL-2025-20690).
	SecurityHoldingNote = "security holding package: npm removed this package after a malicious publish and left a placeholder"

	// packumentTTL is the freshness of a packument: a new version, a maintainer
	// change or a deprecation shows up within the hour. Everything per version is
	// read from this document, so the same TTL covers it.
	packumentTTL = httpcache.DefaultTTL
	// downloadsTTL is the freshness of a download count; the counts API updates
	// once a day, so an hour loses nothing.
	downloadsTTL = httpcache.DefaultTTL

	// bulkLimit is the most names one bulk downloads request may carry; verified
	// 2026-09-09 against download-counts.md ("limited to at most 128 packages").
	bulkLimit = 128

	// packumentAccept selects the full packument. The abbreviated document served
	// for application/vnd.npm.install-v1+json lacks time and _npmUser. Verified
	// 2026-09-09: application/json returns the same document as */*.
	packumentAccept = "application/json"

	// securityHoldingDescription is the description npm writes into a placeholder,
	// at the top level and in its single version. Verified 2026-09-09 on flatmap-stream.
	securityHoldingDescription = "security holding package"

	// sha1Size is the length of a hex-decoded dist.shasum.
	sha1Size = 20

	// implicitInstallScript is the Scripts["install"] entry of a version with a
	// binding.gyp and no install or preinstall script of its own. npm's scripts
	// documentation: such a package gets a default install command of
	// "node-gyp rebuild". The registry marks those versions with gypfile: true
	// (seen on ref 1.3.5, ffi 2.3.0 and node-expat 2.4.1 on 2026-09-09).
	implicitInstallScript = "node-gyp rebuild (npm default for binding.gyp)"

	// trustedPublisherSuffix joins the provider id and the configuration id of
	// a trusted publishing release into the publisher name.
	trustedPublisherSuffix = "-trusted-publisher:"
)

// installScriptNames are the scripts npm runs when it installs the package as a
// dependency from the registry (brief section 4, TD005 and TD006). Every other
// script (test, build, prepublish and so on) runs only for the package's own
// developers.
//
// prepare is deliberately not one of them, although npm does run it and although a
// great many published packages keep one. It runs when the package is packed, when
// its own checkout is installed, and when a consumer depends on it through git or a
// local folder, and none of those is the registry tarball a lockfile entry names.
// npm says so itself: its approve-scripts page calls them "preinstall, install,
// postinstall, and prepare for non-registry sources", and its hasInstallScript
// getter is !!(hasInstallScript || install || preinstall || postinstall), with no
// prepare in it. Arborist queues prepare with the other three and then drains that
// queue only for link nodes, while ordinary dependencies are built as "deps". Read
// on 2026-09-10: https://docs.npmjs.com/cli/v12/commands/npm-approve-scripts, and
// workspaces/arborist/lib/node.js and .../lib/arborist/rebuild.js of
// https://github.com/npm/cli.
//
// Counting it reported a release that adopted a husky hook as a release that added
// install-time code, and worse: it made the release that added a real postinstall
// afterwards look like one whose predecessor already ran code, so that one was not
// reported at all.
var installScriptNames = []string{"preinstall", "install", "postinstall"}

// Option configures a Client.
type Option func(*Client)

// WithRegistryURL points the client at another registry, for example an
// httptest server. Trailing slashes are removed.
func WithRegistryURL(base string) Option {
	return func(c *Client) { c.registry = strings.TrimRight(base, "/") }
}

// WithDownloadsURL points the client at another download counts API.
func WithDownloadsURL(base string) Option {
	return func(c *Client) { c.downloads = strings.TrimRight(base, "/") }
}

// WithLogger sets the diagnostics logger. The default discards.
func WithLogger(log *slog.Logger) Option {
	return func(c *Client) {
		if log != nil {
			c.log = log
		}
	}
}

// Client is the npm registry client. All requests go through internal/httpcache.
// It is safe for concurrent use.
type Client struct {
	http      *httpcache.Client
	registry  string
	downloads string
	log       *slog.Logger

	// mu guards packuments, the per-client memo of parsed packuments keyed by
	// canonical name. A packument is parsed once per client and never refreshed,
	// which is the lifetime of one run; the disk cache in httpcache handles the
	// hour-long TTL across runs.
	mu         sync.Mutex
	packuments map[string]*packument
}

// New returns a client using the shared HTTP cache, which must not be nil.
func New(h *httpcache.Client, opts ...Option) *Client {
	c := &Client{
		http:       h,
		registry:   DefaultRegistryURL,
		downloads:  DefaultDownloadsURL,
		log:        slog.New(slog.DiscardHandler),
		packuments: map[string]*packument{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Ecosystem implements registry.Source.
func (c *Client) Ecosystem() model.Ecosystem { return model.NPM }

// Versions implements registry.Source from one packument. The returned list is a
// copy the caller may modify.
func (c *Client) Versions(ctx context.Context, name string) (*registry.VersionList, error) {
	name, err := canonicalName(name)
	if err != nil {
		return nil, err
	}
	p, err := c.packument(ctx, name)
	if err != nil {
		return nil, err
	}
	list := &registry.VersionList{
		Ecosystem:   model.NPM,
		Name:        p.name,
		Latest:      p.latest,
		Created:     p.created,
		Modified:    p.modified,
		Deprecated:  p.deprecated,
		Maintainers: slices.Clone(p.maintainers),
		Versions:    make([]model.VersionInfo, len(p.versions)),
	}
	for i := range p.versions {
		list.Versions[i] = cloneVersion(&p.versions[i])
	}
	return list, nil
}

// VersionInfo implements registry.Source from the same packument Versions uses;
// nothing in the full packument needs a second request. An unknown version,
// including one the time map still names after it was unpublished, is
// registry.ErrNotFound.
func (c *Client) VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	if ref.Ecosystem != model.NPM {
		return nil, fmt.Errorf("npm: %s is not an npm package", ref)
	}
	if !ref.HasVersion() {
		return nil, fmt.Errorf("npm: %s: a version is required", ref)
	}
	name, err := canonicalName(ref.Name)
	if err != nil {
		return nil, err
	}
	p, err := c.packument(ctx, name)
	if err != nil {
		return nil, err
	}
	i, ok := p.index[ref.Version]
	if !ok {
		return nil, fmt.Errorf("npm: %s@%s: %w", name, ref.Version, registry.ErrNotFound)
	}
	info := cloneVersion(&p.versions[i])
	return &info, nil
}

// Owners implements registry.Source with the packument's top-level maintainers,
// the accounts currently allowed to publish.
func (c *Client) Owners(ctx context.Context, name string) ([]model.Publisher, error) {
	name, err := canonicalName(name)
	if err != nil {
		return nil, err
	}
	p, err := c.packument(ctx, name)
	if err != nil {
		return nil, err
	}
	return slices.Clone(p.maintainers), nil
}

// Downloads implements registry.Source with the last-week point endpoint. A
// package the counts API does not know is registry.ErrNotFound.
func (c *Client) Downloads(ctx context.Context, name string) (int64, error) {
	name, err := canonicalName(name)
	if err != nil {
		return 0, err
	}
	// The downloads API documents scoped names with a plain slash
	// (/downloads/point/last-month/@slack/client), unlike the registry, and the
	// name is joined unescaped for that reason: canonicalName let through only
	// what a path segment carries as itself.
	u := c.downloads + "/downloads/point/last-week/" + name
	resp, err := c.http.Get(ctx, u, httpcache.Request{TTL: downloadsTTL})
	if err != nil {
		return 0, fmt.Errorf("npm: downloads for %s: %w", name, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return 0, fmt.Errorf("npm: downloads for %s: %w", name, registry.ErrNotFound)
	default:
		return 0, fmt.Errorf("npm: downloads for %s: unexpected status %d", name, resp.StatusCode)
	}
	var doc pointDoc
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return 0, fmt.Errorf("npm: downloads for %s: decoding response: %w", name, err)
	}
	if doc.Downloads == nil {
		return 0, fmt.Errorf("npm: downloads for %s: response has no downloads field", name)
	}
	c.log.Debug("npm downloads", "package", name, "weekly", *doc.Downloads, "from_cache", resp.FromCache)
	return *doc.Downloads, nil
}

// BulkDownloads returns the weekly download count of every name the counts API
// knows, keyed by canonical name, for a caller that warms a whole run at once.
// Unscoped names share bulk requests of at most bulkLimit names each, in the
// order given; scoped names, which the bulk endpoint refuses, and a leftover
// single name, which it would answer in the point shape, go through Downloads.
// A name the API does not know (null in a bulk answer, 404 from the point
// endpoint) is left out rather than failing the call, so a missing key means
// unknown.
//
// Any other failure stops the call and is returned with whatever was read before
// it. One refused request is not an answer about the names it never covered: a
// scan of React's lockfile on 2026-09-12 lost the counts of 1,583 packages because
// api.npmjs.org refused the point request for @babel/plugin-syntax-flow, which is
// one scoped name of several thousand. So the map is what was read and the error
// is what stopped it, and a caller stores each of them for the names it belongs to.
func (c *Client) BulkDownloads(ctx context.Context, names []string) (map[string]int64, error) {
	var bulk, single []string
	seen := make(map[string]bool, len(names))
	for _, raw := range names {
		name, err := canonicalName(raw)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if strings.HasPrefix(name, "@") {
			single = append(single, name)
		} else {
			bulk = append(bulk, name)
		}
	}
	out := make(map[string]int64, len(seen))
	for _, chunk := range chunks(bulk, bulkLimit) {
		if len(chunk) == 1 {
			single = append(single, chunk[0])
			continue
		}
		if err := c.bulkChunk(ctx, chunk, out); err != nil {
			return out, err
		}
	}
	for _, name := range single {
		n, err := c.Downloads(ctx, name)
		if errors.Is(err, registry.ErrNotFound) {
			c.log.Debug("npm downloads unknown", "package", name)
			continue
		}
		if err != nil {
			return out, err
		}
		out[name] = n
	}
	return out, nil
}

// bulkDownloadsError is the error of a failed bulk request with the package names taken
// out of what it prints. It keeps the error it was made from, so errors.Is and
// errors.As see exactly what they saw before: the status code, the offline
// sentinel, a canceled context.
type bulkDownloadsError struct {
	msg string
	err error
}

func (e *bulkDownloadsError) Error() string { return e.msg }
func (e *bulkDownloadsError) Unwrap() error { return e.err }

// withoutTheNames replaces the URL of a failed bulk request, wherever it appears in
// the message, with the endpoint and how many names it carried. The loader stores
// whatever this call returns against every name it asked about, so the whole list
// would otherwise be repeated in the report once per package: the precision pass of
// 2026-09-12 put 1,005 copies of a 3,000 character URL into one report, 2.6 MB of
// it, and made every skip reason in that report unreadable. The status and the
// endpoint are what a reader needs, and the names are in the report already.
//
// The substitution is on the text and not on a typed field, because the errors this
// can come back as are not one type: a status the server sent, a transport failure,
// and an offline cache miss that is neither.
func withoutTheNames(err error, requested, short string) error {
	msg := strings.ReplaceAll(err.Error(), requested, short)
	return &bulkDownloadsError{msg: msg, err: err}
}

// bulkChunk asks the bulk endpoint for one chunk of unscoped names and adds the
// counts it knows to out. Shape verified 2026-09-09: an object keyed by name
// whose values are point objects, or null for a name the API does not know
// ({"isarray":{"downloads":174862265,"package":"isarray","start":"2026-08-31",
// "end":"2026-09-06"},"trustdiff-no-such-package-9f3a1c":null}); a request
// naming only unknown packages still answers 200.
func (c *Client) bulkChunk(ctx context.Context, names []string, out map[string]int64) error {
	// Unscoped names contain only URL-safe characters and the commas must stay
	// literal, so the segment is joined without escaping.
	u := c.downloads + "/downloads/point/last-week/" + strings.Join(names, ",")
	resp, err := c.http.Get(ctx, u, httpcache.Request{TTL: downloadsTTL})
	if err != nil {
		short := fmt.Sprintf("%s/downloads/point/last-week/ (%d names)", c.downloads, len(names))
		return fmt.Errorf("npm: bulk downloads: %w", withoutTheNames(err, u, short))
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("npm: bulk downloads of %d names: unexpected status %d", len(names), resp.StatusCode)
	}
	var doc map[string]*pointDoc
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return fmt.Errorf("npm: bulk downloads: decoding response: %w", err)
	}
	known := 0
	for _, name := range names {
		point := doc[name]
		if point == nil || point.Downloads == nil {
			c.log.Debug("npm downloads unknown", "package", name)
			continue
		}
		out[name] = *point.Downloads
		known++
	}
	c.log.Debug("npm bulk downloads", "asked", len(names), "known", known, "from_cache", resp.FromCache)
	return nil
}

// pointDoc is the point endpoint's answer and the value of one bulk entry.
// Shape verified 2026-09-09:
// {"downloads":174862265,"start":"2026-08-31","end":"2026-09-06","package":"isarray"}.
type pointDoc struct {
	Downloads *int64 `json:"downloads"`
}

// chunks splits names into slices of at most n, keeping their order.
func chunks(names []string, n int) [][]string {
	out := make([][]string, 0, (len(names)+n-1)/n)
	for len(names) > n {
		out = append(out, names[:n])
		names = names[n:]
	}
	if len(names) > 0 {
		out = append(out, names)
	}
	return out
}

// IsSecurityHolding reports whether a version list describes a security holding
// placeholder, recognized by the note Versions puts in Deprecated.
func IsSecurityHolding(list *registry.VersionList) bool {
	return list != nil && strings.HasPrefix(list.Deprecated, SecurityHoldingNote)
}

// canonicalName validates a package name and trims surrounding whitespace. The
// spelling is otherwise kept, case included, because the registry is
// case-sensitive for legacy names (see the package comment); it is the memo and
// cache key as given.
//
// A name npm's own grammar refuses cannot be on the registry, so it is answered as
// not found without a request. That is also what makes it safe to put a name into
// a URL unescaped, which the downloads endpoint needs: what the grammar lets
// through is letters, digits and -_.!~*'() in each half, and a path segment
// carries every one of those as itself.
func canonicalName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if problem := model.NPMNameProblem(name); problem != "" {
		return "", fmt.Errorf("npm: %q is not a valid npm name (%s): %w", name, problem, registry.ErrNotFound)
	}
	return name, nil
}

// encodeName renders a name as one path segment: @scope/name becomes
// @scope%2Fname, which is what the registry expects for scoped packages.
func encodeName(name string) string { return url.PathEscape(name) }

// packument returns the parsed packument for a canonical name, fetching it once
// per client. Errors are not memoized so a transient failure can be retried.
func (c *Client) packument(ctx context.Context, name string) (*packument, error) {
	c.mu.Lock()
	p, ok := c.packuments[name]
	c.mu.Unlock()
	if ok {
		return p, nil
	}

	u := c.registry + "/" + encodeName(name)
	resp, err := c.http.Get(ctx, u, httpcache.Request{Accept: packumentAccept, TTL: packumentTTL})
	if err != nil {
		return nil, fmt.Errorf("npm: packument for %s: %w", name, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("npm: package %s: %w", name, registry.ErrNotFound)
	default:
		return nil, fmt.Errorf("npm: packument for %s: unexpected status %d", name, resp.StatusCode)
	}
	p, err = parsePackument(name, resp.Body, c.log)
	if err != nil {
		return nil, fmt.Errorf("npm: packument for %s: %w", name, err)
	}
	c.log.Debug("npm packument parsed", "package", name, "versions", len(p.versions), "from_cache", resp.FromCache)

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.packuments[name]; ok {
		return existing, nil
	}
	c.packuments[name] = p
	return p, nil
}

// packument is one parsed and mapped document.
type packument struct {
	name        string
	latest      string
	created     time.Time
	modified    time.Time
	deprecated  string
	maintainers []model.Publisher
	// versions is in registry order; index maps a version string to its position.
	versions []model.VersionInfo
	index    map[string]int
}

// packumentDoc holds the top-level fields used from the full packument. All of
// them are generated by the registry (package-metadata.md, "hosted" fields).
type packumentDoc struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	DistTags    map[string]string `json:"dist-tags"`
	// Time maps versions to ISO publish times plus created and modified. Values
	// are kept raw because a fully unpublished package carries an "unpublished"
	// object in the same map.
	Time        map[string]json.RawMessage `json:"time"`
	Maintainers humans                     `json:"maintainers"`
	// Versions is decoded separately to preserve the registry's key order.
	Versions json.RawMessage `json:"versions"`
}

// versionDoc holds the per-version fields used. scripts, dependencies,
// optionalDependencies, deprecated and maintainers come from the publisher's
// package.json without validation, so they use tolerant decoders; _npmUser,
// gypfile and dist are generated by the registry.
type versionDoc struct {
	Description          string      `json:"description"`
	NpmUser              *human      `json:"_npmUser"`
	Maintainers          humans      `json:"maintainers"`
	Scripts              stringMap   `json:"scripts"`
	Dependencies         stringMap   `json:"dependencies"`
	OptionalDependencies stringMap   `json:"optionalDependencies"`
	Deprecated           deprecation `json:"deprecated"`
	// Gypfile is true when the published tarball carries a binding.gyp; the
	// registry sets it (package-metadata.md lists it under the version object).
	// It is decoded tolerantly all the same, since a package.json may carry a
	// key of that name in another shape.
	Gypfile flag    `json:"gypfile"`
	Dist    distDoc `json:"dist"`
}

// distDoc is the registry-generated dist object. Shapes verified 2026-09-09:
// signatures is [{"keyid": "SHA256:...", "sig": "MEUC..."}] and attestations is
// {"url": "https://registry.npmjs.org/-/npm/v1/attestations/<name>@<version>",
// "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}.
type distDoc struct {
	Tarball      string           `json:"tarball"`
	Shasum       string           `json:"shasum"`
	Integrity    string           `json:"integrity"`
	Signatures   []signatureDoc   `json:"signatures"`
	Attestations *attestationsDoc `json:"attestations"`
}

type signatureDoc struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type attestationsDoc struct {
	URL        string `json:"url"`
	Provenance *struct {
		PredicateType string `json:"predicateType"`
	} `json:"provenance"`
}

// human is the registry's person object: {"name": ..., "email": ...}. For a
// trusted publishing release _npmUser also carries a trustedPublisher object.
// The shape is not documented; observed on @sigstore/bundle 4.0.0 and 5.0.0 on
// 2026-09-09 as {"name": "GitHub Actions", "email": "npm-oidc-no-reply@github.com",
// "trustedPublisher": {"id": "github", "oidcConfigId": "oidc:87d8bb4c-..."}},
// with the same oidcConfigId on both versions, so the id is stable per trusted
// publisher configuration and changes when the configuration is replaced.
type human struct {
	Name             string            `json:"name"`
	Email            string            `json:"email"`
	TrustedPublisher *trustedPublisher `json:"trustedPublisher"`
}

// trustedPublisher is _npmUser.trustedPublisher: the provider id and the
// registry's id of the trusted publisher configuration that performed the
// publish. Both are decoded tolerantly because the object is undocumented.
type trustedPublisher struct {
	ID           string `json:"id"`
	OIDCConfigID string `json:"oidcConfigId"`
}

// UnmarshalJSON treats a trustedPublisher of an unexpected shape as absent.
func (p *trustedPublisher) UnmarshalJSON(data []byte) error {
	type plain trustedPublisher
	var decoded plain
	if decodes(data, &decoded) {
		*p = trustedPublisher(decoded)
	} else {
		*p = trustedPublisher{}
	}
	return nil
}

// flag decodes a JSON boolean and treats any other value as false, so a
// package.json that spells a registry-generated flag differently does not fail
// the whole version.
type flag bool

func (f *flag) UnmarshalJSON(data []byte) error {
	var b bool
	*f = flag(decodes(data, &b) && b)
	return nil
}

// decodes reports whether data decodes into v. The tolerant decoders below use
// it to treat a field of an unexpected shape as absent instead of failing the
// whole version: these fields come from the publisher's package.json and the
// registry stores whatever was uploaded.
func decodes(data []byte, v any) bool { return json.Unmarshal(data, v) == nil }

// humans decodes an array of person objects, dropping entries that are not
// objects with a name rather than failing the whole version.
type humans []human

func (h *humans) UnmarshalJSON(data []byte) error {
	*h = nil
	var items []json.RawMessage
	if !decodes(data, &items) {
		return nil
	}
	out := make(humans, 0, len(items))
	for _, item := range items {
		var person human
		if decodes(item, &person) && person.Name != "" {
			out = append(out, person)
		}
	}
	*h = out
	return nil
}

func (h humans) publishers() []model.Publisher {
	if len(h) == 0 {
		return nil
	}
	out := make([]model.Publisher, len(h))
	for i, person := range h {
		out[i] = model.Publisher{Name: person.Name, Email: person.Email}
	}
	return out
}

// stringMap decodes an object of string values, dropping entries of any other
// type. Anything that is not an object is treated as absent.
type stringMap map[string]string

func (m *stringMap) UnmarshalJSON(data []byte) error {
	*m = nil
	var raw map[string]json.RawMessage
	if !decodes(data, &raw) || raw == nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for key, value := range raw {
		var s string
		if decodes(value, &s) {
			out[key] = s
		}
	}
	*m = out
	return nil
}

// deprecation is the deprecated field: documented and observed as the message
// string. A bare true, which a package.json can carry, is rendered as a fixed
// message; anything else means not deprecated.
type deprecation string

func (d *deprecation) UnmarshalJSON(data []byte) error {
	*d = ""
	var s string
	if decodes(data, &s) {
		*d = deprecation(strings.TrimSpace(s))
		return nil
	}
	var b bool
	if decodes(data, &b) && b {
		*d = "deprecated without a message"
	}
	return nil
}

// parsePackument decodes the document and maps every version. A version whose
// object cannot be decoded keeps its ref and publish time and is logged, so one
// odd version never hides the package.
func parsePackument(name string, body []byte, log *slog.Logger) (*packument, error) {
	var doc packumentDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding packument: %w", err)
	}
	order, raw, err := decodeVersions(doc.Versions)
	if err != nil {
		return nil, fmt.Errorf("decoding versions: %w", err)
	}
	times := publishTimes(name, doc.Time, log)

	p := &packument{
		name:        name,
		latest:      doc.DistTags["latest"],
		created:     times["created"],
		modified:    times["modified"],
		maintainers: doc.Maintainers.publishers(),
		versions:    make([]model.VersionInfo, 0, len(order)),
		index:       make(map[string]int, len(order)),
	}
	descriptions := make(map[string]string, len(order))
	allDeprecated := len(order) > 0
	for _, ver := range order {
		var vd versionDoc
		if err := json.Unmarshal(raw[ver], &vd); err != nil {
			log.Warn("npm version document not understood, keeping only its publish time", "package", name, "version", ver, "err", err)
			vd = versionDoc{}
		}
		info := mapVersion(name, ver, &vd, times[ver])
		if info.Deprecated == "" {
			allDeprecated = false
		}
		descriptions[ver] = vd.Description
		p.index[ver] = len(p.versions)
		p.versions = append(p.versions, info)
	}

	switch {
	case isSecurityHolding(doc.Description) || isSecurityHolding(descriptions[p.latest]):
		p.deprecated = SecurityHoldingNote
	case allDeprecated:
		p.deprecated = packageDeprecation(p)
	}
	return p, nil
}

// decodeVersions walks the versions object with a token decoder so the order in
// which the registry listed the versions survives; a plain map would lose it.
func decodeVersions(raw json.RawMessage) ([]string, map[string]json.RawMessage, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, err
	}
	if tok != json.Delim('{') {
		return nil, nil, fmt.Errorf("versions is %v, want an object", tok)
	}
	var order []string
	docs := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, nil, fmt.Errorf("versions key is %v, want a string", tok)
		}
		var doc json.RawMessage
		if err := dec.Decode(&doc); err != nil {
			return nil, nil, fmt.Errorf("version %s: %w", key, err)
		}
		if _, seen := docs[key]; !seen {
			order = append(order, key)
		}
		docs[key] = doc
	}
	return order, docs, nil
}

// publishTimes parses the string entries of the time map. Entries that are not
// strings (the "unpublished" object) or not timestamps are skipped and logged.
func publishTimes(name string, raw map[string]json.RawMessage, log *slog.Logger) map[string]time.Time {
	times := make(map[string]time.Time, len(raw))
	for key, value := range raw {
		var s string
		if !decodes(value, &s) {
			continue
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			log.Debug("npm time entry is not a timestamp", "package", name, "key", key, "value", s)
			continue
		}
		times[key] = t
	}
	return times
}

// mapVersion builds the VersionInfo of one version.
func mapVersion(name, ver string, doc *versionDoc, published time.Time) model.VersionInfo {
	info := model.VersionInfo{
		Ref:             model.PackageRef{Ecosystem: model.NPM, Name: name, Version: ver},
		PublishedAt:     published,
		Maintainers:     doc.Maintainers.publishers(),
		Prerelease:      version.IsPrerelease(model.NPM, ver),
		Deprecated:      string(doc.Deprecated),
		Scripts:         installScripts(doc.Scripts, bool(doc.Gypfile)),
		Dependencies:    dependencies(doc.Dependencies, doc.OptionalDependencies),
		Provenance:      provenance(&doc.Dist),
		Integrity:       integrity(&doc.Dist),
		WeeklyDownloads: -1,
	}
	if doc.NpmUser != nil && doc.NpmUser.Name != "" {
		info.Publisher = &model.Publisher{Name: publisherName(doc.NpmUser), Email: doc.NpmUser.Email}
	}
	return info
}

// publisherName renders _npmUser as the identity TD002 compares. A trusted
// publishing release is "<id>-trusted-publisher:<oidcConfigId>", for example
// github-trusted-publisher:oidc:87d8bb4c-c894-403c-af7e-0d34d7e7327a, because
// the account name is the same "GitHub Actions" on every package published that
// way while the configuration id names the repository and workflow the
// maintainer registered; a publish through a re-pointed configuration then
// reads as a publisher change. A trustedPublisher object that lacks either id
// falls back to the account name.
func publisherName(u *human) string {
	if tp := u.TrustedPublisher; tp != nil && tp.ID != "" && tp.OIDCConfigID != "" {
		return tp.ID + trustedPublisherSuffix + tp.OIDCConfigID
	}
	return u.Name
}

// installScripts keeps the install-time scripts only; nil when there are none.
// With gypfile set and neither install nor preinstall declared, npm runs
// node-gyp rebuild as the install script, which is recorded as such.
func installScripts(scripts stringMap, gypfile bool) map[string]string {
	var out map[string]string
	for _, key := range installScriptNames {
		if cmd, ok := scripts[key]; ok {
			if out == nil {
				out = make(map[string]string, len(installScriptNames))
			}
			out[key] = cmd
		}
	}
	if gypfile {
		_, install := out["install"]
		_, preinstall := out["preinstall"]
		if !install && !preinstall {
			if out == nil {
				out = make(map[string]string, 1)
			}
			out["install"] = implicitInstallScript
		}
	}
	return out
}

// dependencies merges dependencies and optionalDependencies. npm installs an
// optional dependency unless it fails to build, so a new one is as much a
// signal for TD007 as a regular one, and as in npm an entry in
// optionalDependencies wins over one of the same name in dependencies. The
// requirement is kept verbatim: TD007 resolves it against the version list, and
// a marker would break that.
func dependencies(deps, optional stringMap) map[string]string {
	if len(deps) == 0 && len(optional) == 0 {
		return nil
	}
	out := make(map[string]string, len(deps)+len(optional))
	maps.Copy(out, deps)
	maps.Copy(out, optional)
	return out
}

// provenance maps dist to the strongest evidence the packument shows. An
// attestations object counts when it names a URL or a provenance predicate, so
// an empty object does not pass for evidence. Verified is left false on
// purpose: the packument proves that an attestation exists, not that it
// verifies; the runner merges the deps.dev verification.
func provenance(d *distDoc) model.Provenance {
	switch {
	case d.Attestations != nil && (d.Attestations.URL != "" || d.Attestations.Provenance != nil):
		return model.Provenance{Kind: model.ProvenanceAttestation}
	case len(d.Signatures) > 0:
		return model.Provenance{Kind: model.ProvenanceSignature}
	default:
		return model.Provenance{Kind: model.ProvenanceNone}
	}
}

// integrity returns dist.integrity, or renders the SHA-1 shasum of a version
// published before April 2017 as the sha1 SRI string lockfiles use for such
// versions (event-stream 0.9.1 has only a shasum, verified 2026-09-09).
func integrity(d *distDoc) string {
	if d.Integrity != "" {
		return d.Integrity
	}
	sum, err := hex.DecodeString(d.Shasum)
	if err != nil || len(sum) != sha1Size {
		return ""
	}
	return "sha1-" + base64.StdEncoding.EncodeToString(sum)
}

// isSecurityHolding recognizes the placeholder description.
func isSecurityHolding(description string) bool {
	return strings.EqualFold(strings.TrimSpace(description), securityHoldingDescription)
}

// packageDeprecation picks the package-level message once every version is
// deprecated. It is the message of dist-tags.latest, else that of the newest
// version by publish time (the last listed one when times are missing).
func packageDeprecation(p *packument) string {
	if i, ok := p.index[p.latest]; ok {
		return p.versions[i].Deprecated
	}
	newest := -1
	for i := range p.versions {
		if newest < 0 || !p.versions[i].PublishedAt.Before(p.versions[newest].PublishedAt) {
			newest = i
		}
	}
	if newest < 0 {
		return ""
	}
	return p.versions[newest].Deprecated
}

// cloneVersion copies a memoized entry so callers can modify what they get back.
func cloneVersion(v *model.VersionInfo) model.VersionInfo {
	out := *v
	if v.Publisher != nil {
		publisher := *v.Publisher
		out.Publisher = &publisher
	}
	out.Maintainers = slices.Clone(v.Maintainers)
	out.Scripts = maps.Clone(v.Scripts)
	out.Dependencies = maps.Clone(v.Dependencies)
	out.OptionalDependencies = maps.Clone(v.OptionalDependencies)
	out.Unknown = maps.Clone(v.Unknown)
	return out
}

var _ registry.Source = (*Client)(nil)
