package jsr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
	"github.com/vahapogut/trustdiff/internal/registry"
)

const (
	defaultRegistryBase = "https://jsr.io"
	defaultAPIBase      = "https://api.jsr.io"

	// versionsPageLimit is the page size asked of the versions endpoint. The
	// endpoint caps limit at 100 whatever is requested (limit=200 and limit=1000
	// both answered 100 items for @hono/hono on 2026-09-09), so asking for more
	// would only misdescribe what comes back.
	versionsPageLimit = 100
	// maxVersionPages stops the paging loop even if the endpoint kept reporting a
	// total it never reaches. At the page size above it allows 20000 versions,
	// far beyond the largest count seen while this was written (@hono/hono, 146
	// versions on 2026-09-09).
	maxVersionPages = 200

	// downloadsWindow is how much of the downloads endpoint's daily history the
	// weekly figure covers. The endpoint reports 90 days of buckets and the model
	// wants one week, the same figure npm's last-week endpoint gives.
	downloadsWindow = 7 * 24 * time.Hour

	// scopeMinLen and scopeMaxLen, packageMinLen and packageMaxLen are the name
	// lengths api.jsr.io accepts, probed on 2026-09-09: a scope of 1 or 21
	// characters answers HTTP 400 while 2 and 20 answer 200 or 404, and a package
	// name of 1 or 59 characters answers 400 while 2 and 58 answer 404. The
	// character rule is the OpenAPI document's pattern for both,
	// ^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$.
	scopeMinLen   = 2
	scopeMaxLen   = 20
	packageMinLen = 2
	packageMaxLen = 58

	// archivedMessage is what a package archived on JSR reports as its
	// package-level deprecation. JSR records archival as the boolean isArchived
	// with no text beside it, so the client renders a fixed sentence rather than
	// leaving TD011 a signal it cannot explain.
	archivedMessage = "the package is archived on jsr.io"

	// jsrDependencyKind is the Dependency.kind of a dependency on another JSR
	// package. The other value the OpenAPI document allows is "npm".
	jsrDependencyKind = "jsr"
)

// Option configures a Client.
type Option func(*Client)

// WithRegistryBase points the registry API at another root, for example an
// httptest server in tests. The default is https://jsr.io.
func WithRegistryBase(base string) Option {
	return func(c *Client) { c.registry = strings.TrimRight(base, "/") }
}

// WithAPIBase points the management API at another root. The default is
// https://api.jsr.io.
func WithAPIBase(base string) Option {
	return func(c *Client) { c.api = strings.TrimRight(base, "/") }
}

// WithLogger sets the logger for diagnostics. The default discards them.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) {
		if l != nil {
			c.log = l
		}
	}
}

// Client is the JSR client. It is safe for concurrent use.
type Client struct {
	http     *httpcache.Client
	registry string
	api      string
	log      *slog.Logger
}

// New returns a client using the shared HTTP cache.
func New(h *httpcache.Client, opts ...Option) *Client {
	c := &Client{
		http:     h,
		registry: defaultRegistryBase,
		api:      defaultAPIBase,
		log:      slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Ecosystem implements registry.Source.
func (c *Client) Ecosystem() model.Ecosystem { return model.JSR }

// packageMeta is https://jsr.io/@<scope>/<name>/meta.json. Only the fields
// trustdiff reads are declared; every one of them was observed live on
// 2026-09-09 for @std/fs, @luca/flag, @luca/cases and @hono/hono. The
// documented githubRepository field is not declared because nothing in the model
// takes a repository, and because it was absent from all four live answers even
// though api.jsr.io reported a linked repository for three of them.
type packageMeta struct {
	Scope string `json:"scope"`
	Name  string `json:"name"`
	// Latest is the version an unpinned import resolves to; empty when the
	// package has none.
	Latest string `json:"latest"`
	// Versions is keyed by version string. JSON objects have no order and JSR
	// does not write these in one (for @std/fs the first key was 1.0.19 and the
	// second 0.200.0), so the client orders the list itself.
	Versions map[string]metaVersion `json:"versions"`
}

// metaVersion is one entry of meta.json's versions object.
type metaVersion struct {
	// Yanked is the authoritative yank state. The documentation is explicit that
	// this is the only place to read it: the per-version document is immutable
	// and therefore omits it.
	Yanked bool `json:"yanked"`
	// CreatedAt is the publish time, and is a pointer because it is absent from
	// packages whose meta.json predates the field: @std/fs carried it on all 69
	// versions on 2026-09-09 while @luca/flag, last published 2024-01-26,
	// carried none. The documentation does not mention it at all. When it is
	// missing the publish time comes from the management versions list instead.
	CreatedAt *time.Time `json:"createdAt"`
}

// apiPackage is https://api.jsr.io/scopes/<scope>/packages/<name>.
type apiPackage struct {
	Scope     string    `json:"scope"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// LatestVersion is null for a package with no published version.
	LatestVersion *string `json:"latestVersion"`
	// IsArchived means no new version can be published; the existing ones stay
	// downloadable and the package is hidden from search and from the scope page.
	IsArchived bool `json:"isArchived"`
}

// apiVersionsPage is one page of
// https://api.jsr.io/scopes/<scope>/packages/<name>/versions. The envelope and
// its paging are live behavior the OpenAPI document does not describe; see the
// package comment.
type apiVersionsPage struct {
	Items []apiVersion `json:"items"`
	Total int          `json:"total"`
}

// apiVersion is one entry of the versions list.
type apiVersion struct {
	Version string `json:"version"`
	// User is the account that published the version. It is null both for
	// versions published before JSR recorded one and for a user that has since
	// been deleted, which the OpenAPI document says explicitly; @luca/flag's two
	// versions were null on 2026-09-09 and @std/fs's 69 were not.
	User *apiUser `json:"user"`
	// Yanked repeats meta.json's flag. meta.json is preferred as the
	// documentation directs, so this is read only as a fallback.
	Yanked bool `json:"yanked"`
	// UsesNpm reports that the version declares npm dependencies. It is observed
	// and not mapped: the model has no field for it, and the npm dependencies it
	// refers to are listed by the dependencies endpoint with kind "npm".
	UsesNpm bool `json:"usesNpm"`
	// RekorLogID is the Sigstore Rekor transparency log entry of the SLSA
	// provenance statement, and is null for a version published without one.
	RekorLogID *string   `json:"rekorLogId"`
	CreatedAt  time.Time `json:"createdAt"`
}

// apiUser is the public part of a JSR account. There is no login: Name is a
// display name the account holder can change at any time, and the stable
// identifiers are a uuid and a GitHub numeric id, neither of which reads as a
// person in a report.
type apiUser struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	GitHubID *int64 `json:"githubId"`
}

// apiDependency is one entry of the per-version dependencies list. Name is fully
// qualified ("@std/path" for kind "jsr"), Path is the sub-export being imported
// and is empty for the default entrypoint, which is why one package appears once
// per sub-export it is imported from.
type apiDependency struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Constraint string `json:"constraint"`
	Path       string `json:"path"`
}

// apiScopeMember is one entry of https://api.jsr.io/scopes/<scope>/members. The
// endpoint answers without authentication, which is what makes it usable here.
type apiScopeMember struct {
	User    apiUser `json:"user"`
	IsAdmin bool    `json:"isAdmin"`
}

// apiDownloads is https://api.jsr.io/scopes/<scope>/packages/<name>/downloads.
// Only total is declared: recentVersions holds the same daily buckets for a
// handful of recent versions, and the model records downloads per package.
type apiDownloads struct {
	Total []downloadPoint `json:"total"`
}

// downloadPoint is one daily bucket. The list is sparse: a day on which a kind
// had no downloads has no entry at all, which is why @luca/flag's 90 days of
// history came back as 109 points across two kinds on 2026-09-09.
type downloadPoint struct {
	TimeBucket time.Time `json:"timeBucket"`
	// Kind is jsr_meta for a fetch through the JSR registry API and npm_tarball
	// for one through the npm compatibility layer. Both are counted: they are two
	// transports for the same install, not two counts of one.
	Kind  string `json:"kind"`
	Count int64  `json:"count"`
}

// snapshot is what the client knows about a package after the requests that
// answer for the package as a whole. It exists so that Versions and VersionInfo
// map the same facts the same way.
type snapshot struct {
	// name is the registry's own spelling, @<scope>/<name>.
	name string
	meta *packageMeta
	// detail holds the management API's record per version, and is nil when that
	// request failed. detailReason then says why, in the words a check shows.
	detail       map[string]*apiVersion
	detailReason string
	// pkg is the management API's package record, nil when that request failed.
	pkg *apiPackage
}

// Versions implements registry.Source. The version set, the yank state and the
// latest version come from meta.json, which is the registry API JSR documents
// for exactly this; the publishing account, the provenance and the publish time
// of packages whose meta.json predates its createdAt field come from the
// management API's versions list, and the package timestamps and the archived
// flag from its package record.
//
// Only meta.json is required. When a management API request fails the list still
// comes back, because the version set and the yank state are complete without
// it: the versions then carry no publisher and no provenance, and each one names
// the provenance facet in Unknown with the reason, so a check reads "not known"
// rather than "none". A failure of meta.json returns a nil list.
//
// The order is ascending by semantic version, not the order the registry
// returned: meta.json's versions object has no order to preserve.
func (c *Client) Versions(ctx context.Context, name string) (*registry.VersionList, error) {
	snap, err := c.snapshot(ctx, name)
	if err != nil {
		return nil, err
	}
	list := &registry.VersionList{
		Ecosystem: model.JSR,
		Name:      snap.name,
		Latest:    snap.meta.Latest,
		Versions:  make([]model.VersionInfo, 0, len(snap.meta.Versions)),
	}
	if snap.pkg != nil {
		list.Created = snap.pkg.CreatedAt
		list.Modified = snap.pkg.UpdatedAt
		if list.Latest == "" && snap.pkg.LatestVersion != nil {
			list.Latest = *snap.pkg.LatestVersion
		}
		if snap.pkg.IsArchived {
			list.Deprecated = archivedMessage
		}
	}
	// Maintainers stays empty: the scope members cost a request of their own and
	// Owners is the method for them, the same split the crates.io client makes.
	for _, ver := range snap.orderedVersions() {
		list.Versions = append(list.Versions, snap.versionInfo(ver))
	}
	return list, nil
}

// VersionInfo implements registry.Source: the version's entry from meta.json and
// from the management versions list, plus its declared dependencies from the
// dependencies endpoint.
//
// A version meta.json does not list is registry.ErrNotFound, whatever the
// management API says about it, because meta.json is the registry's own answer
// to what exists. When the dependencies request fails the version still comes
// back with a nil error, Dependencies empty and Unknown[model.FacetDependencies]
// carrying the reason, so that only the dependency check is skipped while the
// publish time, the publisher, the yank state and the provenance still reach
// every other check.
func (c *Client) VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	if ref.Ecosystem != model.JSR && ref.Ecosystem != "" {
		return nil, fmt.Errorf("jsr: %s is not a jsr ref", ref)
	}
	if !ref.HasVersion() {
		return nil, fmt.Errorf("jsr: %s: a version is required", ref)
	}
	snap, err := c.snapshot(ctx, ref.Name)
	if err != nil {
		return nil, err
	}
	if _, ok := snap.meta.Versions[ref.Version]; !ok {
		return nil, fmt.Errorf("jsr: %s: %w", ref, registry.ErrNotFound)
	}
	info := snap.versionInfo(ref.Version)

	deps, err := c.dependencies(ctx, snap.name, ref.Version)
	if err != nil {
		c.log.Warn("jsr dependencies not fetched", "ref", info.Ref.String(), "error", err)
		info.SetUnknown(model.FacetDependencies, err.Error())
		return &info, nil
	}
	info.Dependencies = deps
	return &info, nil
}

// Owners implements registry.Source with the members of the package's scope, the
// accounts allowed to publish it. They are named by their display name, the only
// human-readable identity JSR publishes; admins are not distinguished, because
// the model records who may publish and every member may.
func (c *Client) Owners(ctx context.Context, name string) ([]model.Publisher, error) {
	scope, _, err := splitName(name)
	if err != nil {
		return nil, err
	}
	var members []apiScopeMember
	u := c.api + "/scopes/" + url.PathEscape(scope) + "/members"
	if err := c.getJSON(ctx, u, httpcache.DefaultTTL, name, &members); err != nil {
		return nil, err
	}
	owners := make([]model.Publisher, 0, len(members))
	for _, m := range members {
		if m.User.Name == "" {
			continue
		}
		owners = append(owners, model.Publisher{Name: m.User.Name})
	}
	return owners, nil
}

// Downloads implements registry.Source. JSR reports one count per day per kind
// for the last 90 days rather than a weekly total, so the weekly figure is the
// sum of every bucket in the seven days ending at the newest bucket the answer
// holds. Both kinds are counted, because jsr_meta and npm_tarball are two
// transports for the same install rather than two counts of one.
//
// The newest bucket is the day the request is made and is therefore partial,
// which makes the figure a slight underestimate of a full week. A package whose
// answer holds no bucket at all reports registry.ErrUnsupported: no count exists
// to compare with a threshold, and reporting zero would read as a package nobody
// installs.
func (c *Client) Downloads(ctx context.Context, name string) (int64, error) {
	scope, pkg, err := splitName(name)
	if err != nil {
		return 0, err
	}
	var doc apiDownloads
	u := c.api + "/scopes/" + url.PathEscape(scope) + "/packages/" + url.PathEscape(pkg) + "/downloads"
	if err := c.getJSON(ctx, u, httpcache.DefaultTTL, name, &doc); err != nil {
		return 0, err
	}
	if len(doc.Total) == 0 {
		return 0, fmt.Errorf("jsr: %s has no download counts: %w", name, registry.ErrUnsupported)
	}
	var newest time.Time
	for _, p := range doc.Total {
		if p.TimeBucket.After(newest) {
			newest = p.TimeBucket
		}
	}
	from := newest.Add(-downloadsWindow)
	var total int64
	for _, p := range doc.Total {
		if p.Count > 0 && p.TimeBucket.After(from) {
			total += p.Count
		}
	}
	return total, nil
}

// snapshot fetches meta.json, which must succeed, and then the management API's
// versions list and package record, which need not.
func (c *Client) snapshot(ctx context.Context, name string) (*snapshot, error) {
	scope, pkg, err := splitName(name)
	if err != nil {
		return nil, err
	}
	var meta packageMeta
	u := c.registry + "/@" + url.PathEscape(scope) + "/" + url.PathEscape(pkg) + "/meta.json"
	if err := c.getJSON(ctx, u, httpcache.DefaultTTL, name, &meta); err != nil {
		return nil, err
	}
	if meta.Scope == "" || meta.Name == "" {
		return nil, fmt.Errorf("jsr: %s: meta.json names no package", name)
	}
	snap := &snapshot{name: "@" + meta.Scope + "/" + meta.Name, meta: &meta}

	detail, err := c.apiVersions(ctx, scope, pkg, snap.name)
	if err != nil {
		c.log.Warn("jsr version details not fetched", "package", snap.name, "error", err)
		snap.detailReason = err.Error()
	} else {
		snap.detail = detail
	}

	record, err := c.apiPackage(ctx, scope, pkg, snap.name)
	if err != nil {
		c.log.Warn("jsr package record not fetched", "package", snap.name, "error", err)
	} else {
		snap.pkg = record
	}
	return snap, nil
}

// apiPackage fetches the management API's package record.
func (c *Client) apiPackage(ctx context.Context, scope, pkg, what string) (*apiPackage, error) {
	var doc apiPackage
	u := c.api + "/scopes/" + url.PathEscape(scope) + "/packages/" + url.PathEscape(pkg)
	if err := c.getJSON(ctx, u, httpcache.DefaultTTL, what, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// apiVersions walks every page of the management API's versions list and returns
// the entries keyed by version. Paging stops on any of four conditions, so a
// total that never arrives cannot loop forever: an empty page, a page shorter
// than the page size, a collected count that reaches the reported total, and the
// hard cap of maxVersionPages.
func (c *Client) apiVersions(ctx context.Context, scope, pkg, what string) (map[string]*apiVersion, error) {
	base := c.api + "/scopes/" + url.PathEscape(scope) + "/packages/" + url.PathEscape(pkg) + "/versions"
	out := map[string]*apiVersion{}
	for page := 1; page <= maxVersionPages; page++ {
		query := url.Values{
			"page":  []string{strconv.Itoa(page)},
			"limit": []string{strconv.Itoa(versionsPageLimit)},
		}
		var doc apiVersionsPage
		if err := c.getJSON(ctx, base+"?"+query.Encode(), httpcache.DefaultTTL, what, &doc); err != nil {
			return nil, err
		}
		if len(doc.Items) == 0 {
			return out, nil
		}
		for i := range doc.Items {
			entry := &doc.Items[i]
			if entry.Version == "" {
				continue
			}
			out[entry.Version] = entry
		}
		if len(doc.Items) < versionsPageLimit || len(out) >= doc.Total {
			return out, nil
		}
	}
	// Everything collected so far is returned rather than discarded: a partial
	// publisher history is still worth more to the checks than none, and the log
	// line says the answer is short.
	c.log.Warn("jsr versions list longer than the page limit allows", "package", what, "pages", maxVersionPages)
	return out, nil
}

// dependencies returns the version's dependencies on other JSR packages, name to
// constraint. Entries of kind "npm" are left out and counted in a debug line:
// model.VersionInfo.Dependencies has one key space and the dependency check
// resolves every key in the subject's own ecosystem, so an npm package listed
// here would be looked up on JSR and reported as one that does not exist. A
// lockfile records those as npm entries of their own, which is where they belong.
//
// One package appears once per sub-export a version imports from it (@std/fs
// 1.0.24 lists @std/path twelve times), so the first entry for a name wins and a
// later one with a different constraint is logged at debug level.
func (c *Client) dependencies(ctx context.Context, name, ver string) (map[string]string, error) {
	scope, pkg, err := splitName(name)
	if err != nil {
		return nil, err
	}
	u := c.api + "/scopes/" + url.PathEscape(scope) + "/packages/" + url.PathEscape(pkg) +
		"/versions/" + url.PathEscape(ver) + "/dependencies"
	var doc []apiDependency
	// JSR is immutable: a published version's dependencies never change.
	if err := c.getJSON(ctx, u, httpcache.Forever, name+"@"+ver, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(doc))
	var npmCount int
	for _, d := range doc {
		if d.Kind != jsrDependencyKind {
			npmCount++
			continue
		}
		if d.Name == "" {
			continue
		}
		if existing, seen := out[d.Name]; seen {
			if existing != d.Constraint {
				c.log.Debug("jsr dependency listed twice with different constraints",
					"package", name, "version", ver, "dependency", d.Name, "kept", existing, "ignored", d.Constraint)
			}
			continue
		}
		out[d.Name] = d.Constraint
	}
	if npmCount > 0 {
		c.log.Debug("npm dependencies excluded from the jsr dependency map",
			"package", name, "version", ver, "count", npmCount)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// orderedVersions returns every version meta.json lists, ascending by semantic
// version. meta.json's versions object has no meaningful order, so the client
// imposes one; version.Sort keeps versions that do not parse in front and in
// their relative order rather than dropping them.
func (s *snapshot) orderedVersions() []string {
	out := make([]string, 0, len(s.meta.Versions))
	for ver := range s.meta.Versions {
		out = append(out, ver)
	}
	version.Sort(model.JSR, out)
	return out
}

// versionInfo maps one version. The caller has already established that
// meta.json lists it.
func (s *snapshot) versionInfo(ver string) model.VersionInfo {
	entry := s.meta.Versions[ver]
	info := model.VersionInfo{
		Ref:        model.PackageRef{Ecosystem: model.JSR, Name: s.name, Version: ver},
		Prerelease: version.IsPrerelease(model.JSR, ver),
		Yanked:     entry.Yanked,
		Provenance: model.Provenance{Kind: model.ProvenanceNone},
		// JSR publishes a package total per day and, for a few recent versions,
		// their own daily counts; there is no weekly figure per version.
		WeeklyDownloads: -1,
	}
	if entry.CreatedAt != nil {
		info.PublishedAt = *entry.CreatedAt
	}
	// Scripts stays nil and is deliberately not marked unknown: JSR has no
	// install-time script mechanism, so "no install scripts" is a fact about the
	// ecosystem rather than something this client failed to gather.
	detail := s.detail[ver]
	if detail == nil {
		if s.detailReason != "" {
			info.SetUnknown(model.FacetProvenance, s.detailReason)
		}
		return info
	}
	if info.PublishedAt.IsZero() {
		info.PublishedAt = detail.CreatedAt
	}
	if detail.User != nil && detail.User.Name != "" {
		info.Publisher = &model.Publisher{Name: detail.User.Name}
	}
	if detail.RekorLogID != nil && *detail.RekorLogID != "" {
		// JSR builds the SLSA statement itself, from the GitHub Actions OIDC
		// token it validated at publish time, and writes it to the Sigstore Rekor
		// transparency log (https://jsr.io/docs/trust, read 2026-09-09), so the
		// evidence counts as verified by the registry. Identity stays empty: the
		// endpoints carry the log entry id but not the workflow the statement
		// names, and the package's linked GitHub repository is not that workflow,
		// since it can be relinked without republishing anything.
		info.Provenance = model.Provenance{Kind: model.ProvenanceAttestation, Verified: true}
	}
	return info
}

// getJSON performs one cached GET and decodes a 200 body. A 404 is
// registry.ErrNotFound; the bodies differ by host and neither is needed beyond
// the status (jsr.io answers the plain text "404 - Not Found", api.jsr.io a JSON
// object such as {"code":"packageNotFound","message":...}, both verified
// 2026-09-09).
func (c *Client) getJSON(ctx context.Context, u string, ttl time.Duration, what string, out any) error {
	// The registry API documentation requires an Accept header that does not ask
	// for text/html, or the host may answer with a rendered HTML page instead of
	// the data.
	resp, err := c.http.Get(ctx, u, httpcache.Request{Accept: "application/json", TTL: ttl})
	if err != nil {
		return fmt.Errorf("jsr: %s: %w", what, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("jsr: %s: %w", what, registry.ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jsr: %s: unexpected status %d from %s", what, resp.StatusCode, u)
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("jsr: %s: decoding %s: %w", what, u, err)
	}
	return nil
}

// splitName splits a JSR package name into its scope and its package part. Every
// JSR name is scoped, so @luca/flag is the only shape there is; the leading "@"
// is required because that is how the name is written everywhere, in an import
// specifier, on the package page and in a trustdiff ref.
//
// A name that cannot be a JSR name is reported as not found rather than as a bad
// request, since no request could change that answer, which is the rule the
// crates.io client follows for crate names.
func splitName(name string) (scope, pkg string, err error) {
	rest, ok := strings.CutPrefix(name, "@")
	if !ok {
		return "", "", fmt.Errorf("jsr: %q is not a jsr package name, which is always @scope/name: %w", name, registry.ErrNotFound)
	}
	scope, pkg, ok = strings.Cut(rest, "/")
	if !ok {
		return "", "", fmt.Errorf("jsr: %q is not a jsr package name, which is always @scope/name: %w", name, registry.ErrNotFound)
	}
	if err := checkNamePart("scope", scope, scopeMinLen, scopeMaxLen); err != nil {
		return "", "", err
	}
	if err := checkNamePart("package name", pkg, packageMinLen, packageMaxLen); err != nil {
		return "", "", err
	}
	return scope, pkg, nil
}

// checkNamePart rejects a scope or package name that JSR could not have
// registered: lowercase ASCII letters and digits with single dashes between
// them, starting with a letter and ending with a letter or digit, within the
// length the API accepts.
func checkNamePart(kind, s string, minLen, maxLen int) error {
	invalid := fmt.Errorf("jsr: %q is not a valid jsr %s: %w", s, kind, registry.ErrNotFound)
	if len(s) < minLen || len(s) > maxLen {
		return invalid
	}
	if s[0] < 'a' || s[0] > 'z' {
		return invalid
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
		case ch == '-':
			// A dash must separate two characters, so it may not end the name
			// and may not follow another dash.
			if i+1 >= len(s) || s[i-1] == '-' {
				return invalid
			}
		default:
			return invalid
		}
	}
	return nil
}

var _ registry.Source = (*Client)(nil)
