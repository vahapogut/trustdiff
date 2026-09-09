// Package crates is the crates.io client. It implements registry.Source on top
// of the crates.io API and the static archive host, and it is the only code that
// knows their HTTP shapes.
//
// Endpoints, verified 2026-09-09 against live responses and the OpenAPI document
// at https://crates.io/api/openapi.json:
//
//	GET https://crates.io/api/v1/crates/<name>                        crate and every version
//	GET https://crates.io/api/v1/crates/<name>/owners                 current owners
//	GET https://crates.io/api/v1/crates/<name>/<version>/dependencies declared dependencies
//	GET https://static.crates.io/crates/<name>/<name>-<version>.crate the gzip tar archive
//
// crates.io asks API users for an identifying User-Agent and at most one request
// per second (RFC 3463). Both are enforced by the shared internal/httpcache
// client, which sends the trustdiff agent string and rate limits the host
// crates.io to one request per second; nothing here times or throttles on its
// own. The static host is not rate limited by crates.io and serves immutable
// files, so archives are cached forever.
//
// Every request goes through internal/httpcache: crate and owner documents are
// cached for the default hour, per-version dependencies and archives forever.
package crates

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
	"github.com/vahapogut/trustdiff/internal/registry"
)

const (
	defaultAPIBase    = "https://crates.io/api/v1"
	defaultStaticBase = "https://static.crates.io/crates"

	// recentDownloadsWeeks converts crate.recent_downloads, which the OpenAPI
	// document describes as "the total number of downloads for this crate in the
	// last 90 days" (verified 2026-09-09), into a weekly figure. 90 days are
	// 12.86 weeks; dividing by 13 rounds the estimate down rather than up.
	recentDownloadsWeeks = 13
)

// Option configures a Client.
type Option func(*Client)

// WithAPIBase points the client at another API root, for example an httptest
// server in tests. The default is https://crates.io/api/v1.
func WithAPIBase(base string) Option {
	return func(c *Client) { c.api = strings.TrimRight(base, "/") }
}

// WithStaticBase points the archive downloads at another root. The default is
// https://static.crates.io/crates.
func WithStaticBase(base string) Option {
	return func(c *Client) { c.static = strings.TrimRight(base, "/") }
}

// WithLogger sets the logger for diagnostics. The default discards them.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) {
		if l != nil {
			c.log = l
		}
	}
}

// Client is the crates.io client. It is safe for concurrent use.
type Client struct {
	http   *httpcache.Client
	api    string
	static string
	log    *slog.Logger
	// maxArchive caps the archive size that is inspected; MaxArchiveBytes outside tests.
	maxArchive int64
}

// New returns a client using the shared HTTP cache.
func New(h *httpcache.Client, opts ...Option) *Client {
	c := &Client{
		http:       h,
		api:        defaultAPIBase,
		static:     defaultStaticBase,
		log:        slog.New(slog.DiscardHandler),
		maxArchive: MaxArchiveBytes,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Ecosystem implements registry.Source.
func (c *Client) Ecosystem() model.Ecosystem { return model.Cargo }

// crateResponse is the crate document. Only the fields trustdiff reads are
// declared; every one of them was observed in the live response for serde and
// rand_core on 2026-09-09 and is described in the OpenAPI document.
type crateResponse struct {
	Crate struct {
		// Name is the registered spelling. Lookups are case-insensitive and treat
		// "-" and "_" alike, so it may differ from what the caller asked for; the
		// archive host and the archive entries use this spelling.
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		// RecentDownloads is the 90-day download total; null for a crate without
		// download data (the OpenAPI document declares it nullable).
		RecentDownloads *int64 `json:"recent_downloads"`
		// MaxStableVersion is the highest non-prerelease version; null when every
		// version is a prerelease. MaxVersion is the highest version of any kind.
		// Both are marked deprecated in the OpenAPI document but still served.
		MaxStableVersion *string `json:"max_stable_version"`
		MaxVersion       string  `json:"max_version"`
		// TrustpubOnly is true when the crate accepts trusted publishing only.
		TrustpubOnly bool `json:"trustpub_only"`
	} `json:"crate"`
	Versions []crateVersion `json:"versions"`
}

// crateVersion is one entry of versions[].
type crateVersion struct {
	Num       string    `json:"num"`
	CreatedAt time.Time `json:"created_at"`
	Yanked    bool      `json:"yanked"`
	// YankMessage is the message given at yank time; null when there is none.
	YankMessage *string `json:"yank_message"`
	// PublishedBy is null for versions published before crates.io recorded the
	// publisher (serde 1.0.88 and older on 2026-09-09) and, observed on rand_core
	// 0.10.0 and 0.10.1, for versions published through trusted publishing, where
	// no user account performed the publish.
	PublishedBy *struct {
		Login string `json:"login"`
		Name  string `json:"name"`
	} `json:"published_by"`
	// Checksum is the SHA-256 of the .crate file as lowercase hex.
	Checksum string `json:"checksum"`
	// CrateSize is the size of the .crate file in bytes.
	CrateSize int64 `json:"crate_size"`
	// TrustpubData is present only for versions published through trusted
	// publishing. The OpenAPI document marks it unstable and says its structure
	// depends on the provider; the fields below are the ones observed live on
	// rand 0.8.8 and rand_core 0.10.1 (provider "github") on 2026-09-09. There is
	// no verification flag inside it: crates.io only records the object after it
	// validated the provider's OIDC token itself.
	TrustpubData *trustpubData `json:"trustpub_data"`
	// AuditActions lists publish and yank actions with the acting user and time.
	// Observed but not mapped: the model has no place for a per-version audit log.
	AuditActions []struct {
		Action string    `json:"action"`
		Time   time.Time `json:"time"`
		User   struct {
			Login string `json:"login"`
		} `json:"user"`
	} `json:"audit_actions"`
}

// trustpubData is versions[].trustpub_data as observed for provider "github".
type trustpubData struct {
	Provider   string `json:"provider"`
	Repository string `json:"repository"`
	RunID      string `json:"run_id"`
	SHA        string `json:"sha"`
}

// ownersResponse is the owners document: users[] holds both users (kind "user",
// login is the GitHub login) and teams (kind "team", login like
// "github:serde-rs:publish"). Observed on serde on 2026-09-09.
type ownersResponse struct {
	Users []struct {
		Login string `json:"login"`
		Kind  string `json:"kind"`
		Name  string `json:"name"`
	} `json:"users"`
}

// dependenciesResponse is the per-version dependency list. kind is normal, dev or
// build (OpenAPI document and serde 1.0.229, 2026-09-09); target carries a cfg
// expression or null; a crate may appear more than once with different targets.
type dependenciesResponse struct {
	Dependencies []struct {
		CrateID  string  `json:"crate_id"`
		Req      string  `json:"req"`
		Kind     string  `json:"kind"`
		Optional bool    `json:"optional"`
		Target   *string `json:"target"`
	} `json:"dependencies"`
}

// Versions implements registry.Source from the crate document alone: no extra
// request per version. Latest is max_stable_version, Created and Modified the
// crate timestamps. Each version carries its publish time, yank state (with the
// yank message as Deprecated), prerelease flag, publisher login, checksum and
// provenance. Maintainers stays empty because owners cost a second request; use
// Owners. Refs keep the name the caller passed; see crateResponse.Crate.Name.
func (c *Client) Versions(ctx context.Context, name string) (*registry.VersionList, error) {
	doc, err := c.crate(ctx, name)
	if err != nil {
		return nil, err
	}
	list := &registry.VersionList{
		Ecosystem: model.Cargo,
		Name:      name,
		Created:   doc.Crate.CreatedAt,
		Modified:  doc.Crate.UpdatedAt,
		Versions:  make([]model.VersionInfo, 0, len(doc.Versions)),
	}
	if doc.Crate.MaxStableVersion != nil {
		list.Latest = *doc.Crate.MaxStableVersion
	}
	for i := range doc.Versions {
		list.Versions = append(list.Versions, versionInfo(name, &doc.Versions[i]))
	}
	return list, nil
}

// versionInfo maps one versions[] entry. WeeklyDownloads is -1: crates.io has a
// lifetime total per version but no weekly figure.
func versionInfo(name string, v *crateVersion) model.VersionInfo {
	info := model.VersionInfo{
		Ref:             model.PackageRef{Ecosystem: model.Cargo, Name: name, Version: v.Num},
		PublishedAt:     v.CreatedAt,
		Prerelease:      version.IsPrerelease(model.Cargo, v.Num),
		Yanked:          v.Yanked,
		Integrity:       v.Checksum,
		Provenance:      model.Provenance{Kind: model.ProvenanceNone},
		WeeklyDownloads: -1,
	}
	if v.PublishedBy != nil && v.PublishedBy.Login != "" {
		info.Publisher = &model.Publisher{Name: v.PublishedBy.Login}
	}
	if v.Yanked && v.YankMessage != nil && *v.YankMessage != "" {
		info.Deprecated = *v.YankMessage
	}
	if v.TrustpubData != nil {
		// The registry validated the provider's token before recording the
		// publish, so the evidence counts as verified by the registry. Identity
		// is <provider>:<repository>, for example github:rust-random/rand_core.
		info.Provenance = model.Provenance{
			Kind:     model.ProvenanceTrustedPublisher,
			Verified: true,
			Identity: v.TrustpubData.Provider + ":" + v.TrustpubData.Repository,
		}
	}
	return info
}

// Owners implements registry.Source from the owners document. Teams are
// included with their login (github:<org>:<team>) as the name.
func (c *Client) Owners(ctx context.Context, name string) ([]model.Publisher, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	var doc ownersResponse
	if err := c.getJSON(ctx, c.api+"/crates/"+url.PathEscape(name)+"/owners", httpcache.DefaultTTL, name, &doc); err != nil {
		return nil, err
	}
	owners := make([]model.Publisher, 0, len(doc.Users))
	for _, u := range doc.Users {
		if u.Login == "" {
			continue
		}
		owners = append(owners, model.Publisher{Name: u.Login})
	}
	return owners, nil
}

// Downloads implements registry.Source. crates.io publishes a 90-day total
// (crate.recent_downloads), not a weekly count, so the result is that total
// divided by 13, a slight underestimate of one week. A crate whose
// recent_downloads is null reports registry.ErrUnsupported.
func (c *Client) Downloads(ctx context.Context, name string) (int64, error) {
	doc, err := c.crate(ctx, name)
	if err != nil {
		return 0, err
	}
	if doc.Crate.RecentDownloads == nil {
		return 0, fmt.Errorf("crates: %s has no recent download count: %w", name, registry.ErrUnsupported)
	}
	return *doc.Crate.RecentDownloads / recentDownloadsWeeks, nil
}

// VersionInfo implements registry.Source: the version's entry from the crate
// document, its normal-kind dependencies from the dependencies endpoint, and
// Scripts from an inspection of the .crate archive (build script and
// procedural macro, see Inspect).
//
// When the archive cannot be inspected, VersionInfo still returns the version
// with Scripts empty, together with an error wrapping ErrNotInspected and the
// cause (ErrArchiveTooLarge, ErrChecksumMismatch, httpcache.ErrOffline, an
// unavailable or corrupt archive). Callers that only need the metadata keep the
// value and report the install-script check as skipped with the error text.
// Every other error returns a nil version.
func (c *Client) VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	if ref.Ecosystem != model.Cargo && ref.Ecosystem != "" {
		return nil, fmt.Errorf("crates: %s is not a crates.io ref", ref)
	}
	if ref.Version == "" {
		return nil, fmt.Errorf("crates: %s: a version is required", ref)
	}
	doc, err := c.crate(ctx, ref.Name)
	if err != nil {
		return nil, err
	}
	var entry *crateVersion
	for i := range doc.Versions {
		if doc.Versions[i].Num == ref.Version {
			entry = &doc.Versions[i]
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("crates: %s: %w", ref, registry.ErrNotFound)
	}
	info := versionInfo(ref.Name, entry)

	deps, err := c.dependencies(ctx, doc.Crate.Name, ref)
	if err != nil {
		return nil, err
	}
	info.Dependencies = deps

	scripts, err := c.inspect(ctx, doc.Crate.Name, ref.Version, entry.Checksum, entry.CrateSize)
	if err != nil {
		c.log.Warn("crate archive not inspected", "ref", ref.String(), "error", err)
		return &info, fmt.Errorf("crates: %s: %w", ref, err)
	}
	info.Scripts = scripts
	return &info, nil
}

// dependencies returns the normal-kind dependencies of a version as name to
// requirement. Build-kind and dev-kind entries are excluded: neither ends up in
// a dependent's build, which is what TD007 reasons about; their counts are
// logged at debug level. When a crate is listed more than once (serde 1.0.219
// lists serde_derive with and without a cfg target), the entry without a target
// wins, then a non-optional one, then the registry's order.
func (c *Client) dependencies(ctx context.Context, crateName string, ref model.PackageRef) (map[string]string, error) {
	u := c.api + "/crates/" + url.PathEscape(crateName) + "/" + url.PathEscape(ref.Version) + "/dependencies"
	var doc dependenciesResponse
	// A version's dependency list never changes once published.
	if err := c.getJSON(ctx, u, httpcache.Forever, ref.String(), &doc); err != nil {
		return nil, err
	}
	type pick struct {
		req           string
		targeted, opt bool
	}
	chosen := map[string]pick{}
	var build, dev int
	for _, d := range doc.Dependencies {
		switch d.Kind {
		case "normal":
		case "build":
			build++
			continue
		case "dev":
			dev++
			continue
		default:
			c.log.Debug("unknown dependency kind", "ref", ref.String(), "crate", d.CrateID, "kind", d.Kind)
			continue
		}
		candidate := pick{req: d.Req, targeted: d.Target != nil && *d.Target != "", opt: d.Optional}
		current, seen := chosen[d.CrateID]
		if !seen || better(candidate.targeted, candidate.opt, current.targeted, current.opt) {
			chosen[d.CrateID] = candidate
		}
	}
	if build+dev > 0 {
		c.log.Debug("dependencies excluded by kind", "ref", ref.String(), "build", build, "dev", dev)
	}
	if len(chosen) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(chosen))
	for name, p := range chosen {
		out[name] = p.req
	}
	return out, nil
}

// better reports whether a candidate dependency entry should replace the one
// chosen so far: untargeted beats targeted, then non-optional beats optional.
func better(candTargeted, candOpt, curTargeted, curOpt bool) bool {
	if candTargeted != curTargeted {
		return !candTargeted
	}
	return !candOpt && curOpt
}

// crate fetches the crate document.
func (c *Client) crate(ctx context.Context, name string) (*crateResponse, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	var doc crateResponse
	if err := c.getJSON(ctx, c.api+"/crates/"+url.PathEscape(name), httpcache.DefaultTTL, name, &doc); err != nil {
		return nil, err
	}
	if doc.Crate.Name == "" {
		return nil, fmt.Errorf("crates: %s: response has no crate object", name)
	}
	if doc.Crate.Name != name {
		c.log.Debug("crate name differs from the requested spelling", "requested", name, "registered", doc.Crate.Name)
	}
	return &doc, nil
}

// getJSON performs one cached GET and decodes a 200 body. A 404 is
// registry.ErrNotFound; the registry's body for it is {"errors":[{"detail":...}]}
// (verified 2026-09-09) and is not needed beyond the status.
func (c *Client) getJSON(ctx context.Context, u string, ttl time.Duration, what string, out any) error {
	resp, err := c.http.Get(ctx, u, httpcache.Request{Accept: "application/json", TTL: ttl})
	if err != nil {
		return fmt.Errorf("crates: %s: %w", what, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("crates: %s: %w", what, registry.ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("crates: %s: unexpected status %d from %s", what, resp.StatusCode, u)
	}
	if err := json.Unmarshal(resp.Body, out); err != nil {
		return fmt.Errorf("crates: %s: decoding %s: %w", what, u, err)
	}
	return nil
}

// checkName rejects anything that cannot be a crate name before it reaches a
// URL: crates.io names are ASCII letters, digits, "-" and "_", at most 64 bytes
// and starting with a letter or digit. An impossible name is reported as not
// found, since no request could change that answer.
func checkName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("crates: %q is not a valid crate name: %w", name, registry.ErrNotFound)
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		alnum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if alnum || (i > 0 && (ch == '-' || ch == '_')) {
			continue
		}
		return fmt.Errorf("crates: %q is not a valid crate name: %w", name, registry.ErrNotFound)
	}
	return nil
}

var _ registry.Source = (*Client)(nil)
