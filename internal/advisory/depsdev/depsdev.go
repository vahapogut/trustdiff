// Package depsdev talks to the deps.dev v3alpha API (Google Open Source Insights).
// It is an accelerator and a cross-check, never the only source: version facts
// (publish time, deprecation, verified attestations and SLSA provenance, cooldown),
// findings (MALICIOUS, DEPRECATED, COOLDOWN, LOW_USAGE, VULNERABLE) and similarly
// named packages. deps.dev has no Deno or JSR system; those refs report unsupported.
//
// Endpoints, verified 2026-09-09 against https://docs.deps.dev/api/v3alpha/ and
// against live calls the same day:
//
//	POST https://api.deps.dev/v3alpha/versionbatch   (up to 5000 requests[]{versionKey})
//	POST https://api.deps.dev/v3alpha/findingsbatch  (up to 5000 requests[]{versionKey or packageKey})
//	GET  https://api.deps.dev/v3alpha/systems/<SYSTEM>/packages/<name>:similarlyNamedPackages
//
// Both batch endpoints answer responses[] in request order, one response per
// request, each carrying the echoed request, and may paginate through
// nextPageToken and pageToken. A version deps.dev has never seen is a 200
// whose response carries only the echoed request. deps.dev canonicalizes
// names on its side: PyPI names to the PEP 503 form, so Requests and requests
// are one version, while npm names are matched case-sensitively, so JSONStream
// and jsonstream are two packages (verified 2026-09-09, both recorded in
// testdata). For a request that collapsed onto an earlier one it echoes that
// earlier request's uncanonicalized spelling ([Requests, requests] got two
// responses in order, both echoing Requests), so the echo cannot tell such
// requests apart. Refs are therefore sent exactly as the caller spells them,
// and answers are matched by position whenever a chunk got one response per
// request; the echo places responses only when the counts differ, and a
// response that cannot be placed, or a ref left without one, is an error
// rather than a "not found". A scoped npm name in a path needs its slash
// percent-encoded; an unencoded one is a 404.
//
// Batch answers are cached for six hours and similarly named packages for a
// day, all through internal/httpcache.
package depsdev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
)

const (
	// DefaultBaseURL is the deps.dev v3alpha API root.
	DefaultBaseURL = "https://api.deps.dev/v3alpha"
	// BatchSize is the most requests one versionbatch or findingsbatch call
	// carries. deps.dev accepts up to 5000 (verified 2026-09-09).
	BatchSize = 5000

	// batchTTL is the cache lifetime of a batch answer, the same six hours the
	// plan gives OSV results.
	batchTTL = 6 * time.Hour
	// similarTTL is the cache lifetime of a similarly named packages answer.
	similarTTL = 24 * time.Hour
	// maxPages bounds how many pages one chunk follows, so a server that keeps
	// returning a page token cannot spin the client forever.
	maxPages = 100
	// acceptJSON is sent with every request. deps.dev answers JSON regardless;
	// the header is part of the httpcache key.
	acceptJSON = "application/json"
)

// ErrUnsupported is returned for ecosystems deps.dev does not index (Deno, JSR).
var ErrUnsupported = errors.New("ecosystem not indexed by deps.dev")

// VersionFacts is what deps.dev knows about one package version.
type VersionFacts struct {
	// Found is false when deps.dev has never seen the version.
	Found       bool      `json:"found"`
	PublishedAt time.Time `json:"published_at,omitempty"`
	// IsDeprecated mirrors the registry deprecation flag as deps.dev sees it.
	IsDeprecated bool `json:"is_deprecated"`
	// AdvisoryKeys lists the advisory ids deps.dev links to the version.
	AdvisoryKeys []string `json:"advisory_keys,omitempty"`
	// AttestationVerified is true when deps.dev verified a build attestation
	// (npm provenance or PyPI PEP 740); SLSAVerified when it verified SLSA provenance.
	AttestationVerified bool `json:"attestation_verified"`
	SLSAVerified        bool `json:"slsa_verified"`
	// SourceRepositories are the repositories the verified attestations name,
	// distinct and in the order deps.dev returned them. It is what tells a
	// migration to trusted publishing from a takeover: both change the publishing
	// identity, and only one of them keeps building the package from the
	// repository it was always built from.
	SourceRepositories []string `json:"source_repositories,omitempty"`
	// CooldownEnd is the end of the deps.dev cooldown window when one is reported.
	CooldownEnd time.Time `json:"cooldown_end,omitempty"`
}

// addSource records a repository a verified attestation names, once. An
// unverified attestation is not recorded at all: what it claims about its source
// is exactly what an attacker would claim.
func (f *VersionFacts) addSource(repo string) {
	if repo == "" {
		return
	}
	for _, have := range f.SourceRepositories {
		if strings.EqualFold(have, repo) {
			return
		}
	}
	f.SourceRepositories = append(f.SourceRepositories, repo)
}

// Finding is one deps.dev finding for a version.
type Finding struct {
	// Type is one of NOT_FOUND, MALICIOUS, DEPRECATED, COOLDOWN, LOW_USAGE, VULNERABLE, REMEDIATION.
	Type string `json:"type"`
	// Risk is the RISK_* level deps.dev assigns.
	Risk string `json:"risk,omitempty"`
	// Detail carries the human text deps.dev returns with the finding: the
	// deprecation reason, the end of the cooldown window, or the higher-usage
	// alternatives of a LOW_USAGE finding, rendered as one line. It is empty
	// when the finding came without context (verified 2026-09-09: a finding is
	// {type, risk} plus at most one of deprecatedContext{reason},
	// cooldownContext{end} and lowUsageContext{alternativePackages[]}).
	Detail string `json:"detail,omitempty"`
}

// Similar is a package whose name resembles the queried one.
type Similar struct {
	Name string `json:"name"`
	// Popularity is reserved for a ranking signal. The v3alpha response carries
	// none (verified 2026-09-09: packages[] holds only packageKey{system, name}),
	// so this client leaves it zero and the checks rank neighbors themselves.
	Popularity int64 `json:"popularity,omitempty"`
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL points the client at another API root, for example an httptest
// server. Trailing slashes are removed.
func WithBaseURL(base string) Option {
	return func(c *Client) { c.base = strings.TrimRight(base, "/") }
}

// WithLogger sets the diagnostics logger. The default discards.
func WithLogger(log *slog.Logger) Option {
	return func(c *Client) {
		if log != nil {
			c.log = log
		}
	}
}

// Client is the deps.dev API client. All requests go through internal/httpcache.
// It is safe for concurrent use.
type Client struct {
	http *httpcache.Client
	base string
	log  *slog.Logger
	// batchSize is BatchSize outside tests, which lower it to exercise chunking.
	batchSize int
}

// New returns a client using the shared HTTP cache, which must not be nil.
func New(h *httpcache.Client, opts ...Option) *Client {
	c := &Client{
		http:      h,
		base:      DefaultBaseURL,
		log:       slog.New(slog.DiscardHandler),
		batchSize: BatchSize,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Versions returns version facts for every ref deps.dev indexes, through
// versionbatch in chunks of BatchSize. A ref deps.dev has never seen, and a ref
// without a version, is present with Found false; Found false is never the
// result of a missing or misplaced response, which is an error instead (see
// the package comment). Refs of ecosystems deps.dev does not index are absent;
// ErrUnsupported is returned only when every ref was one of them. A cold cache
// in offline mode is httpcache.ErrOffline, wrapped.
func (c *Client) Versions(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef]VersionFacts, error) {
	plan, versionless, err := planBatch(refs, false)
	if err != nil {
		return nil, fmt.Errorf("depsdev: versions: %w", err)
	}
	out := make(map[model.PackageRef]VersionFacts, len(plan.refs)+len(versionless))
	for _, ref := range versionless {
		out[ref] = VersionFacts{}
	}
	for _, ref := range plan.refs {
		out[ref] = VersionFacts{}
	}
	for _, ch := range plan.chunks(c.batchSize) {
		responses, err := c.postBatch(ctx, "versionbatch", ch.items())
		if err != nil {
			return nil, err
		}
		at := ch.attribution("versionbatch", len(responses))
		for i, raw := range responses {
			var vr versionResponse
			if err := json.Unmarshal(raw, &vr); err != nil {
				return nil, fmt.Errorf("depsdev: decoding versionbatch response %d: %w", i, err)
			}
			ref, err := c.resolve(at, i, vr.Request)
			if err != nil {
				return nil, err
			}
			if vr.Version == nil {
				// An unknown version: only the echoed request came back, and
				// the entry keeps Found false.
				continue
			}
			out[ref] = c.facts(ref, vr.Version)
		}
		if err := at.complete(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Findings returns the deps.dev findings for every ref, through findingsbatch
// in chunks of BatchSize: the requested version's findings followed by the
// package-scoped ones it did not already repeat. A ref without a version is
// asked as a package and gets the package-scoped findings. Refs with no
// findings are absent from the map; refs of ecosystems deps.dev does not index
// are skipped, and ErrUnsupported is returned only when every ref was one of
// them. A missing or misplaced response is an error, as in Versions. A cold
// cache in offline mode is httpcache.ErrOffline, wrapped.
func (c *Client) Findings(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef][]Finding, error) {
	plan, _, err := planBatch(refs, true)
	if err != nil {
		return nil, fmt.Errorf("depsdev: findings: %w", err)
	}
	out := make(map[model.PackageRef][]Finding, len(plan.refs))
	for _, ch := range plan.chunks(c.batchSize) {
		responses, err := c.postBatch(ctx, "findingsbatch", ch.items())
		if err != nil {
			return nil, err
		}
		at := ch.attribution("findingsbatch", len(responses))
		for i, raw := range responses {
			var fr findingsResponse
			if err := json.Unmarshal(raw, &fr); err != nil {
				return nil, fmt.Errorf("depsdev: decoding findingsbatch response %d: %w", i, err)
			}
			ref, err := c.resolve(at, i, fr.Request)
			if err != nil {
				return nil, err
			}
			if findings := c.findingsOf(ref, fr.Findings); len(findings) > 0 {
				out[ref] = findings
			}
		}
		if err := at.complete(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SimilarNames returns packages with names similar to name in the ecosystem.
// A package deps.dev has never indexed has no neighbors and yields an empty
// list, not an error (the endpoint answers a plain-text 404 "package not found",
// observed 2026-09-09). A cold cache in offline mode is httpcache.ErrOffline,
// wrapped.
func (c *Client) SimilarNames(ctx context.Context, eco model.Ecosystem, name string) ([]Similar, error) {
	system := System(eco)
	if system == "" {
		return nil, fmt.Errorf("depsdev: similar names for %s: %w", eco, ErrUnsupported)
	}
	if name == "" {
		return nil, errors.New("depsdev: similar names: empty package name")
	}
	// url.PathEscape keeps "@" and encodes "/", which is the form deps.dev
	// accepts for a scoped npm name (verified 2026-09-09 with @types/node).
	target := c.base + "/systems/" + system + "/packages/" + url.PathEscape(name) + ":similarlyNamedPackages"
	resp, err := c.http.Get(ctx, target, httpcache.Request{Accept: acceptJSON, TTL: similarTTL})
	if err != nil {
		return nil, fmt.Errorf("depsdev: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return []Similar{}, nil
	default:
		return nil, fmt.Errorf("depsdev: GET %s: unexpected status %d", target, resp.StatusCode)
	}
	var doc similarDoc
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return nil, fmt.Errorf("depsdev: decoding similarly named packages for %s: %w", name, err)
	}
	out := make([]Similar, 0, len(doc.Packages))
	for _, p := range doc.Packages {
		if p.PackageKey.Name != "" {
			out = append(out, Similar{Name: p.PackageKey.Name})
		}
	}
	return out, nil
}

// System maps an ecosystem to the deps.dev system name, or "" when unsupported.
func System(eco model.Ecosystem) string {
	switch eco {
	case model.NPM:
		return "NPM"
	case model.PyPI:
		return "PYPI"
	case model.Cargo:
		return "CARGO"
	default:
		return ""
	}
}

// postBatch sends one chunk of requests to endpoint, follows page tokens, and
// returns the raw responses of every page in order. Each page is its own POST
// with its own cache entry, since the page token is part of the body.
func (c *Client) postBatch(ctx context.Context, endpoint string, items []batchItem) ([]json.RawMessage, error) {
	target := c.base + "/" + endpoint
	var all []json.RawMessage
	token := ""
	for page := 1; ; page++ {
		if page > maxPages {
			return nil, fmt.Errorf("depsdev: POST %s: more than %d pages for one batch", target, maxPages)
		}
		body, err := json.Marshal(batchRequest{Requests: items, PageToken: token})
		if err != nil {
			return nil, fmt.Errorf("depsdev: encoding %s request: %w", endpoint, err)
		}
		resp, err := c.http.Post(ctx, target, body, httpcache.Request{Accept: acceptJSON, TTL: batchTTL})
		if err != nil {
			return nil, fmt.Errorf("depsdev: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("depsdev: POST %s: unexpected status %d", target, resp.StatusCode)
		}
		var doc batchPage
		if err := json.Unmarshal(resp.Body, &doc); err != nil {
			return nil, fmt.Errorf("depsdev: decoding %s response: %w", endpoint, err)
		}
		c.log.Debug("deps.dev batch page", "endpoint", endpoint, "requests", len(items), "page", page, "responses", len(doc.Responses), "from_cache", resp.FromCache)
		all = append(all, doc.Responses...)
		if doc.NextPageToken == "" {
			return all, nil
		}
		token = doc.NextPageToken
	}
}

// facts converts one version document. Any verified attestation or SLSA
// provenance sets the corresponding flag; the lists are not otherwise kept.
func (c *Client) facts(ref model.PackageRef, v *versionDoc) VersionFacts {
	f := VersionFacts{
		Found:        true,
		PublishedAt:  c.parseTime(ref, "publishedAt", v.PublishedAt),
		IsDeprecated: v.IsDeprecated,
	}
	for _, a := range v.AdvisoryKeys {
		if a.ID != "" {
			f.AdvisoryKeys = append(f.AdvisoryKeys, a.ID)
		}
	}
	for _, a := range v.Attestations {
		if a.Verified {
			f.AttestationVerified = true
			f.addSource(a.SourceRepository)
		}
	}
	for _, p := range v.SLSAProvenances {
		if p.Verified {
			f.SLSAVerified = true
			f.addSource(p.SourceRepository)
		}
	}
	if v.Cooldown != nil {
		f.CooldownEnd = c.parseTime(ref, "cooldown.end", v.Cooldown.End)
	}
	return f
}

// findingKind is what makes two findings the same one: a package-scoped
// finding repeats the type and risk of the version-scoped one, but not always
// its context (request 2.88.2 carries the deprecation reason only on the
// version, observed 2026-09-09).
type findingKind struct {
	typ, risk string
}

// findingsOf flattens one findings document: the requested version's findings
// first, then the package-scoped ones of a kind not already listed. deps.dev
// usually repeats package findings inside each version, but not for a version
// it has never seen (flatmap-stream 0.1.1 is NOT_FOUND while the package is
// MALICIOUS, observed 2026-09-09), and the checks want both. A package request
// has no requested version and yields the package-scoped findings alone.
func (c *Client) findingsOf(ref model.PackageRef, doc *findingsDoc) []Finding {
	if doc == nil {
		return nil
	}
	var out []Finding
	seen := map[findingKind]bool{}
	add := func(docs []findingDoc) {
		for _, d := range docs {
			f := c.finding(ref, d)
			kind := findingKind{typ: f.Type, risk: f.Risk}
			if f.Type == "" || seen[kind] {
				continue
			}
			seen[kind] = true
			out = append(out, f)
		}
	}
	if doc.RequestedVersion != nil {
		add(doc.RequestedVersion.Findings)
	}
	add(doc.PackageFindings)
	return out
}

// finding converts one finding, rendering whichever context deps.dev attached
// as the Detail line.
func (c *Client) finding(ref model.PackageRef, d findingDoc) Finding {
	f := Finding{Type: d.Type, Risk: d.Risk}
	switch {
	case d.DeprecatedContext != nil && d.DeprecatedContext.Reason != "":
		f.Detail = d.DeprecatedContext.Reason
	case d.CooldownContext != nil && d.CooldownContext.End != "":
		if end := c.parseTime(ref, "cooldownContext.end", d.CooldownContext.End); !end.IsZero() {
			f.Detail = "in cooldown until " + end.UTC().Format(time.RFC3339)
		}
	case d.LowUsageContext != nil && len(d.LowUsageContext.AlternativePackages) > 0:
		f.Detail = "packages with similar names and higher usage: " + strings.Join(d.LowUsageContext.AlternativePackages, ", ")
	}
	return f
}

// parseTime reads an RFC 3339 timestamp. An empty value is the zero time; an
// unparsable one is logged and treated the same, since one odd timestamp must
// not fail a whole batch.
func (c *Client) parseTime(ref model.PackageRef, field, value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		c.log.Warn("deps.dev timestamp not parsed", "ref", ref.String(), "field", field, "value", value, "error", err)
		return time.Time{}
	}
	return t
}

// batchPlan is the set of refs one batch answers: deduplicated, in input order,
// with the request sent for each and the way back from an echoed key to a ref.
type batchPlan struct {
	refs  []model.PackageRef
	items []batchItem
	byKey map[string]int
}

// planBatch keeps the refs deps.dev can answer and drops the rest. A ref of an
// ecosystem deps.dev does not index is skipped; when refs is not empty and every
// ref was one of them the error is ErrUnsupported. A ref without a version
// becomes a packageKey request when allowPackageKey is set and is otherwise
// returned in versionless, for the caller to answer without a request.
func planBatch(refs []model.PackageRef, allowPackageKey bool) (plan *batchPlan, versionless []model.PackageRef, err error) {
	plan = &batchPlan{byKey: map[string]int{}}
	seen := make(map[model.PackageRef]bool, len(refs))
	supported := 0
	for _, ref := range refs {
		system := System(ref.Ecosystem)
		if system == "" {
			continue
		}
		supported++
		if seen[ref] {
			continue
		}
		seen[ref] = true
		var item batchItem
		switch {
		case ref.Version != "":
			item.VersionKey = &versionKey{System: system, Name: ref.Name, Version: ref.Version}
		case allowPackageKey:
			item.PackageKey = &packageKey{System: system, Name: ref.Name}
		default:
			versionless = append(versionless, ref)
			continue
		}
		plan.byKey[item.key()] = len(plan.refs)
		plan.refs = append(plan.refs, ref)
		plan.items = append(plan.items, item)
	}
	if len(refs) > 0 && supported == 0 {
		return nil, nil, ErrUnsupported
	}
	return plan, versionless, nil
}

// chunks splits the plan into consecutive slices of at most size refs.
func (p *batchPlan) chunks(size int) []chunk {
	if size <= 0 {
		size = BatchSize
	}
	out := make([]chunk, 0, (len(p.refs)+size-1)/size)
	for start := 0; start < len(p.refs); start += size {
		out = append(out, chunk{plan: p, start: start, end: min(start+size, len(p.refs))})
	}
	return out
}

// chunk is one batch call's worth of a plan.
type chunk struct {
	plan       *batchPlan
	start, end int
}

func (ch chunk) items() []batchItem { return ch.plan.items[ch.start:ch.end] }

// attribution is the way back from one chunk's responses to its refs, and the
// record of which refs got one. endpoint names the call in errors; total is
// the number of responses the chunk got across all pages.
type attribution struct {
	ch       chunk
	endpoint string
	total    int
	answered []bool
}

func (ch chunk) attribution(endpoint string, total int) *attribution {
	return &attribution{ch: ch, endpoint: endpoint, total: total, answered: make([]bool, ch.end-ch.start)}
}

// resolve maps the response at pos back to its ref and marks the ref answered.
// deps.dev answers in request order, and the echoed request of a request that
// collapsed onto an earlier one repeats that earlier spelling (see the package
// comment), so when the chunk got exactly one response per request the
// position decides and an echo naming another ref of the chunk is only logged.
// When the counts differ the echo is the only way back, and a response it
// cannot place is an error rather than a guess.
func (c *Client) resolve(at *attribution, pos int, echo batchItem) (model.PackageRef, error) {
	ch := at.ch
	n := ch.end - ch.start
	i, keyed := ch.plan.byKey[echo.key()]
	keyed = keyed && i >= ch.start && i < ch.end
	var local int
	switch {
	case at.total == n:
		local = pos
		if keyed && i != ch.start+pos {
			c.log.Warn("deps.dev response echoes another request of the batch, kept by position", "endpoint", at.endpoint, "position", pos, "sent", ch.plan.items[ch.start+pos], "echoed", echo)
		}
	case keyed:
		local = i - ch.start
	default:
		return model.PackageRef{}, fmt.Errorf("depsdev: %s of %d requests: %d responses, response %d (%s) names no request", at.endpoint, n, at.total, pos, echo)
	}
	at.answered[local] = true
	return ch.plan.refs[ch.start+local], nil
}

// complete returns an error when a ref of the chunk got no response, naming
// the first one left out, so a short answer is never read as "not found".
func (at *attribution) complete() error {
	for i, ok := range at.answered {
		if !ok {
			return fmt.Errorf("depsdev: %s of %d requests: %d responses, none for %s", at.endpoint, len(at.answered), at.total, at.ch.plan.refs[at.ch.start+i])
		}
	}
	return nil
}

// Wire types, verified 2026-09-09 against https://docs.deps.dev/api/v3alpha/
// and live responses. Only the fields this client reads are declared; JSON
// decoding ignores the rest (purl, licenses, links, registries, relatedProjects,
// upstreamIdentifiers, projectStatus, recommendedVersions, defaultVersion).

// versionKey identifies one package version: requests[].versionKey in both
// batch requests, and version.versionKey in a versionbatch answer.
type versionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// packageKey identifies one package: requests[].packageKey in findingsbatch and
// the packageKey of every similarly named package.
type packageKey struct {
	System string `json:"system"`
	Name   string `json:"name"`
}

// batchRequest is the body of versionbatch and findingsbatch: requests[] and,
// for a follow-up page, the pageToken of the previous answer.
type batchRequest struct {
	Requests  []batchItem `json:"requests"`
	PageToken string      `json:"pageToken,omitempty"`
}

// batchItem is one requests[] entry and the echoed responses[].request. A
// versionbatch item carries a versionKey; a findingsbatch item carries either.
type batchItem struct {
	VersionKey *versionKey `json:"versionKey,omitempty"`
	PackageKey *packageKey `json:"packageKey,omitempty"`
}

// key renders the item for matching an echoed request to what was sent.
func (it batchItem) key() string {
	switch {
	case it.VersionKey != nil:
		return "v\x00" + it.VersionKey.System + "\x00" + it.VersionKey.Name + "\x00" + it.VersionKey.Version
	case it.PackageKey != nil:
		return "p\x00" + it.PackageKey.System + "\x00" + it.PackageKey.Name
	default:
		return ""
	}
}

// String renders the item for logs and errors: SYSTEM/name@version for a
// version key, SYSTEM/name for a package key, "(none)" for an empty echo.
func (it batchItem) String() string {
	switch {
	case it.VersionKey != nil:
		return it.VersionKey.System + "/" + it.VersionKey.Name + "@" + it.VersionKey.Version
	case it.PackageKey != nil:
		return it.PackageKey.System + "/" + it.PackageKey.Name
	default:
		return "(none)"
	}
}

// batchPage is the envelope both batch endpoints return: responses[] for this
// page and nextPageToken, empty on the last page.
type batchPage struct {
	Responses     []json.RawMessage `json:"responses"`
	NextPageToken string            `json:"nextPageToken"`
}

// versionResponse is one versionbatch responses[] entry. version is absent
// when deps.dev does not know the version.
type versionResponse struct {
	Request batchItem   `json:"request"`
	Version *versionDoc `json:"version,omitempty"`
}

// versionDoc is responses[].version.
type versionDoc struct {
	VersionKey   versionKey `json:"versionKey"`
	PublishedAt  string     `json:"publishedAt"`
	IsDeprecated bool       `json:"isDeprecated"`
	// AdvisoryKeys are the OSV ids of advisories affecting the version directly.
	AdvisoryKeys []advisoryKey `json:"advisoryKeys"`
	// SLSAProvenances is populated for npm only; Attestations covers every
	// system (npm SLSA provenance, PyPI publish attestations).
	SLSAProvenances []attestationDoc `json:"slsaProvenances"`
	Attestations    []attestationDoc `json:"attestations"`
	Cooldown        *cooldownDoc     `json:"cooldown"`
}

// advisoryKey is one advisoryKeys[] entry.
type advisoryKey struct {
	ID string `json:"id"`
}

// attestationDoc is one attestations[] or slsaProvenances[] entry. Both carry
// verified, sourceRepository, commit and url; attestations[] also carries type.
type attestationDoc struct {
	Type             string `json:"type"`
	URL              string `json:"url"`
	Verified         bool   `json:"verified"`
	SourceRepository string `json:"sourceRepository"`
	Commit           string `json:"commit"`
}

// cooldownDoc is version.cooldown: end and a description that was empty in
// every live answer seen.
type cooldownDoc struct {
	End         string `json:"end"`
	Description string `json:"description"`
}

// findingsResponse is one findingsbatch responses[] entry.
type findingsResponse struct {
	Request  batchItem    `json:"request"`
	Findings *findingsDoc `json:"findings,omitempty"`
}

// findingsDoc is responses[].findings. requestedVersion is present for a
// versionKey request (with a NOT_FOUND finding for an unknown version) and
// absent for a packageKey request; packageFindings apply to every version.
type findingsDoc struct {
	RequestedVersion *versionFindingsDoc `json:"requestedVersion,omitempty"`
	PackageFindings  []findingDoc        `json:"packageFindings"`
}

// versionFindingsDoc is findings.requestedVersion.
type versionFindingsDoc struct {
	VersionKey versionKey   `json:"versionKey"`
	Findings   []findingDoc `json:"findings"`
}

// findingDoc is one finding: type, risk and at most one context object.
type findingDoc struct {
	Type              string             `json:"type"`
	Risk              string             `json:"risk"`
	DeprecatedContext *deprecatedContext `json:"deprecatedContext,omitempty"`
	CooldownContext   *cooldownContext   `json:"cooldownContext,omitempty"`
	LowUsageContext   *lowUsageContext   `json:"lowUsageContext,omitempty"`
}

type deprecatedContext struct {
	Reason string `json:"reason"`
}

type cooldownContext struct {
	End string `json:"end"`
}

type lowUsageContext struct {
	AlternativePackages []string `json:"alternativePackages"`
}

// similarDoc is the similarlyNamedPackages answer: the canonical packageKey of
// the queried package and packages[], each with only a packageKey.
type similarDoc struct {
	PackageKey packageKey `json:"packageKey"`
	Packages   []struct {
		PackageKey packageKey `json:"packageKey"`
	} `json:"packages"`
}
