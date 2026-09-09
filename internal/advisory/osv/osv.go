// Package osv queries OSV.dev for vulnerability and malicious-package advisories.
//
// Endpoints, verified 2026-09-09 against https://google.github.io/osv.dev/api/
// and live calls:
//
//	POST https://api.osv.dev/v1/querybatch  advisory ids and modified per query, TTL 6 h
//	GET  https://api.osv.dev/v1/vulns/<id>  one advisory record in the OSV schema, TTL 6 h
//
// querybatch takes {"queries":[{"package":{"name","ecosystem"},"version"}]} and
// answers {"results":[{"vulns":[{"id","modified"}]}]} with one result per query,
// in query order (the documentation guarantees the ordering; a query without
// hits comes back as an empty object). A query without version returns every
// advisory of the package. At most 1000 queries go in one request: a batch of
// 1001 is answered with 400 "too many queries", which is the limit OSV's own Go
// binding hard-codes as MaxQueriesPerQueryBatchRequest. A result carries
// next_page_token when one query has more than about 1000 advisories or the
// batch more than about 3000; the client repeats the request with page_token
// for those queries until none remains. An ecosystem name OSV does not know
// fails the whole batch with 400 "invalid ecosystem", so refs of ecosystems
// OSV lacks (Deno, JSR) are never sent.
//
// Ecosystem names on the wire are npm, PyPI and crates.io (PyPI names are
// matched case-insensitively: Pillow and pillow answered the same). Advisory
// ids that start with MAL- come from ossf/malicious-packages, the MAL prefix of
// the OSV schema's id table, and mark a malicious version.
//
// A record's severity[] entries are typed CVSS_V2, CVSS_V3 (a v3.0 or v3.1
// vector string) or CVSS_V4 (OSV schema, severity[].type). The advisory
// severity is derived in this order:
//
//  1. database_specific.severity when present and recognized (GHSA records
//     carry LOW, MODERATE, HIGH or CRITICAL). Score is still the base score of
//     the record's CVSS_V3 vector when it has one, and 0 otherwise.
//  2. Otherwise the base score computed from the first usable CVSS_V3 vector
//     with the equations of the CVSS v3.1 specification (see cvss.go), bucketed
//     with advisory.SeverityFromScore.
//  3. Otherwise SeverityUnknown with Score 0: a record with only a CVSS_V4
//     entry (no v4 calculator in v0.1, see docs/checks.md#td010), and records
//     without severity at all such as RUSTSEC and MAL- ones. Unknown counts as
//     medium against a policy threshold.
//
// Summary is the record's summary, or the first line of details when the
// record has none (some PYSEC records), cut at summaryMaxRunes.
package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
)

const (
	// DefaultBaseURL is the public API; WithBaseURL overrides it.
	DefaultBaseURL = "https://api.osv.dev/v1"
	// TTL is how long querybatch and vulns answers are served from the cache
	// (brief section 11: OSV results 6 h).
	TTL = 6 * time.Hour
	// MaxQueriesPerBatch is the most queries one querybatch request may carry.
	MaxQueriesPerBatch = 1000
	// MaliciousPrefix marks advisories imported from ossf/malicious-packages.
	MaliciousPrefix = "MAL-"

	// advisoryPageURL is the human page for an advisory id. Verified 2026-09-09:
	// https://osv.dev/vulnerability/MAL-2025-20690 renders the record.
	advisoryPageURL = "https://osv.dev/vulnerability/"
	// acceptJSON is sent with every request; both endpoints answered
	// application/json to it on 2026-09-09.
	acceptJSON = "application/json"
	// maxPages bounds the pagination loop of one batch so a server that keeps
	// returning tokens cannot make Advisories run forever.
	maxPages = 50
	// summaryMaxRunes bounds a summary derived from details.
	summaryMaxRunes = 200
)

// ErrUnsupported is returned (wrapped) when none of the refs belongs to an
// ecosystem OSV indexes (Deno and JSR have no OSV ecosystem). When only some
// refs are unsupported they are left out of the answer without an error.
var ErrUnsupported = errors.New("ecosystem not indexed by OSV")

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

// Client is the OSV.dev client. All requests go through internal/httpcache. It
// holds no state of its own and is safe for concurrent use.
type Client struct {
	http *httpcache.Client
	base string
	log  *slog.Logger
}

// New returns a client using the shared HTTP cache, which must not be nil.
func New(h *httpcache.Client, opts ...Option) *Client {
	c := &Client{http: h, base: DefaultBaseURL, log: slog.New(slog.DiscardHandler)}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Wire shapes, verified 2026-09-09 against live responses. Field order in the
// request matters only for the cache key, which hashes the body.
type (
	batchRequest struct {
		Queries []batchQuery `json:"queries"`
	}
	batchQuery struct {
		Package   batchPackage `json:"package"`
		Version   string       `json:"version,omitempty"`
		PageToken string       `json:"page_token,omitempty"`
	}
	batchPackage struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	batchResponse struct {
		Results []batchResult `json:"results"`
	}
	batchResult struct {
		Vulns         []batchVuln `json:"vulns"`
		NextPageToken string      `json:"next_page_token"`
	}
	batchVuln struct {
		ID       string `json:"id"`
		Modified string `json:"modified"`
	}

	// vulnRecord is the part of an OSV record the client reads. database_specific
	// is kept raw because its shape belongs to the source database: GHSA puts a
	// severity label there, MAL records a malicious-packages-origins list,
	// RUSTSEC a license.
	vulnRecord struct {
		ID               string                     `json:"id"`
		Aliases          []string                   `json:"aliases"`
		Summary          string                     `json:"summary"`
		Details          string                     `json:"details"`
		Published        string                     `json:"published"`
		Modified         string                     `json:"modified"`
		Severity         []vulnSeverity             `json:"severity"`
		DatabaseSpecific map[string]json.RawMessage `json:"database_specific"`
	}
	vulnSeverity struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}
)

// Advisories implements advisory.Source: one querybatch (in chunks of
// MaxQueriesPerBatch, following page tokens) for every distinct supported ref,
// then one vulns request per distinct advisory id, however many refs share it.
// Refs whose ecosystem OSV lacks are left out; ErrUnsupported is returned only
// when every ref was unsupported. A ref without a version is answered with
// every advisory of the package.
func (c *Client) Advisories(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef][]advisory.Advisory, error) {
	out := make(map[model.PackageRef][]advisory.Advisory)
	if len(refs) == 0 {
		return out, nil
	}
	distinct, unsupported := planQueries(refs)
	if len(distinct) == 0 {
		return nil, fmt.Errorf("osv: %w: %s", ErrUnsupported, strings.Join(unsupported, ", "))
	}
	if len(unsupported) > 0 {
		c.log.Debug("osv skipping ecosystems it does not index", "ecosystems", unsupported)
	}

	hits := make(map[model.PackageRef][]batchVuln, len(distinct))
	for chunk := range slices.Chunk(distinct, MaxQueriesPerBatch) {
		if err := c.queryChunk(ctx, chunk, hits); err != nil {
			return nil, err
		}
	}

	// One details request per distinct id, in a stable order so a run is
	// reproducible and the cache is filled the same way every time.
	listed := make(map[string]batchVuln)
	for _, vulns := range hits {
		for _, v := range vulns {
			if _, ok := listed[v.ID]; !ok {
				listed[v.ID] = v
			}
		}
	}
	ids := slices.Sorted(maps.Keys(listed))
	details := make(map[string]*advisory.Advisory, len(ids))
	for _, id := range ids {
		a, err := c.detail(ctx, id, listed[id])
		if err != nil {
			return nil, err
		}
		details[id] = a
	}
	c.log.Debug("osv advisories assembled", "refs", len(distinct), "advisories", len(ids))

	for _, ref := range distinct {
		vulns := hits[ref]
		if len(vulns) == 0 {
			continue
		}
		list := make([]advisory.Advisory, 0, len(vulns))
		for _, v := range vulns {
			a := *details[v.ID]
			a.Aliases = slices.Clone(a.Aliases)
			list = append(list, a)
		}
		out[ref] = list
	}
	return out, nil
}

// planQueries returns the distinct refs OSV can answer, in first-seen order,
// and the names of the ecosystems that had to be left out.
func planQueries(refs []model.PackageRef) (distinct []model.PackageRef, unsupported []string) {
	seen := make(map[model.PackageRef]struct{}, len(refs))
	for _, ref := range refs {
		if Ecosystem(ref.Ecosystem) == "" {
			name := ref.Ecosystem.String()
			if !slices.Contains(unsupported, name) {
				unsupported = append(unsupported, name)
			}
			continue
		}
		if _, dup := seen[ref]; dup {
			continue
		}
		seen[ref] = struct{}{}
		distinct = append(distinct, ref)
	}
	return distinct, unsupported
}

// queryChunk posts one chunk of at most MaxQueriesPerBatch refs and appends
// every listed advisory to hits, repeating the request with page tokens for
// the queries whose results were paginated.
func (c *Client) queryChunk(ctx context.Context, chunk []model.PackageRef, hits map[model.PackageRef][]batchVuln) error {
	pending := make([]int, len(chunk))
	for i := range chunk {
		pending[i] = i
	}
	tokens := make([]string, len(chunk))
	for page := 0; len(pending) > 0; page++ {
		if page >= maxPages {
			return fmt.Errorf("osv: querybatch: more than %d pages for one batch of %d queries", maxPages, len(chunk))
		}
		req := batchRequest{Queries: make([]batchQuery, 0, len(pending))}
		for _, i := range pending {
			ref := chunk[i]
			req.Queries = append(req.Queries, batchQuery{
				Package:   batchPackage{Name: ref.Name, Ecosystem: Ecosystem(ref.Ecosystem)},
				Version:   ref.Version,
				PageToken: tokens[i],
			})
		}
		body, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("osv: querybatch: encoding %d queries: %w", len(req.Queries), err)
		}
		resp, err := c.http.Post(ctx, c.base+"/querybatch", body, httpcache.Request{Accept: acceptJSON, TTL: TTL})
		if err != nil {
			return fmt.Errorf("osv: querybatch of %d queries: %w", len(req.Queries), err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("osv: querybatch of %d queries: unexpected status %d", len(req.Queries), resp.StatusCode)
		}
		var parsed batchResponse
		if err := json.Unmarshal(resp.Body, &parsed); err != nil {
			return fmt.Errorf("osv: querybatch of %d queries: decoding response: %w", len(req.Queries), err)
		}
		if len(parsed.Results) != len(req.Queries) {
			return fmt.Errorf("osv: querybatch of %d queries: %d results in the response", len(req.Queries), len(parsed.Results))
		}
		c.log.Debug("osv querybatch", "queries", len(req.Queries), "page", page+1, "from_cache", resp.FromCache)

		var next []int
		for k, i := range pending {
			res := parsed.Results[k]
			hits[chunk[i]] = append(hits[chunk[i]], res.Vulns...)
			if res.NextPageToken != "" {
				tokens[i] = res.NextPageToken
				next = append(next, i)
			}
		}
		pending = next
	}
	return nil
}

// detail fetches one advisory record. An id the batch listed but the vulns
// endpoint does not know (a record withdrawn between the two requests) is
// reported and answered from the batch entry alone, so a malicious-package
// listing is never silently dropped.
func (c *Client) detail(ctx context.Context, id string, listed batchVuln) (*advisory.Advisory, error) {
	u := c.base + "/vulns/" + url.PathEscape(id)
	resp, err := c.http.Get(ctx, u, httpcache.Request{Accept: acceptJSON, TTL: TTL})
	if err != nil {
		return nil, fmt.Errorf("osv: advisory %s: %w", id, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		c.log.Warn("advisory listed by querybatch but not found", "id", id)
		a := c.toAdvisory(id, &vulnRecord{Modified: listed.Modified})
		return &a, nil
	default:
		return nil, fmt.Errorf("osv: advisory %s: unexpected status %d", id, resp.StatusCode)
	}
	var rec vulnRecord
	if err := json.Unmarshal(resp.Body, &rec); err != nil {
		return nil, fmt.Errorf("osv: advisory %s: decoding response: %w", id, err)
	}
	if rec.Modified == "" {
		rec.Modified = listed.Modified
	}
	a := c.toAdvisory(id, &rec)
	c.log.Debug("osv advisory", "id", id, "severity", a.Severity, "score", a.Score, "malicious", a.Malicious, "from_cache", resp.FromCache)
	return &a, nil
}

// toAdvisory maps one record onto advisory.Advisory; id is the id the batch
// listed, which is also the record's id.
func (c *Client) toAdvisory(id string, rec *vulnRecord) advisory.Advisory {
	a := advisory.Advisory{
		ID:        id,
		Aliases:   slices.Clone(rec.Aliases),
		Summary:   summaryOf(rec),
		Malicious: strings.HasPrefix(id, MaliciousPrefix),
		Published: c.parseTime(id, "published", rec.Published),
		Modified:  c.parseTime(id, "modified", rec.Modified),
		URL:       advisoryPageURL + id,
	}
	a.Severity, a.Score = c.severity(id, rec)
	return a
}

// severity applies the order documented in the package comment: the database
// label, then the computed CVSS v3 base score, then unknown.
func (c *Client) severity(id string, rec *vulnRecord) (advisory.Severity, float64) {
	score, hasScore := c.cvss3Score(id, rec.Severity)
	if label := rec.databaseSeverity(); label != "" {
		if sev, err := advisory.ParseSeverity(label); err == nil && sev != advisory.SeverityUnknown {
			return sev, score
		}
		c.log.Debug("unrecognized database_specific.severity", "id", id, "severity", label)
	}
	if hasScore {
		return advisory.SeverityFromScore(score), score
	}
	return advisory.SeverityUnknown, 0
}

// cvss3Score computes the base score of the first CVSS_V3 entry whose vector
// parses. An entry that does not is reported and skipped, so one malformed
// vector cannot hide a usable one.
func (c *Client) cvss3Score(id string, entries []vulnSeverity) (float64, bool) {
	for _, e := range entries {
		if e.Type != "CVSS_V3" {
			continue
		}
		score, err := cvss3BaseScore(e.Score)
		if err != nil {
			c.log.Warn("unusable CVSS_V3 vector", "id", id, "vector", e.Score, "error", err)
			continue
		}
		return score, true
	}
	return 0, false
}

// databaseSeverity returns database_specific.severity when it is a string.
func (rec *vulnRecord) databaseSeverity() string {
	raw, ok := rec.DatabaseSpecific["severity"]
	if !ok {
		return ""
	}
	var label string
	if err := json.Unmarshal(raw, &label); err != nil {
		return ""
	}
	return strings.TrimSpace(label)
}

// summaryOf returns the record's summary, or the first line of its details
// bounded to summaryMaxRunes when it has none.
func summaryOf(rec *vulnRecord) string {
	if s := strings.TrimSpace(rec.Summary); s != "" {
		return s
	}
	for line := range strings.SplitSeq(rec.Details, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if runes := []rune(line); len(runes) > summaryMaxRunes {
			return string(runes[:summaryMaxRunes])
		}
		return line
	}
	return ""
}

// parseTime reads an RFC 3339 timestamp (OSV writes UTC with a Z suffix and
// sometimes fractional seconds). Empty or unparsable values yield the zero time.
func (c *Client) parseTime(id, field, value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		c.log.Debug("unparsable timestamp", "id", id, "field", field, "value", value, "error", err)
		return time.Time{}
	}
	return t
}

// Ecosystem maps an ecosystem to the OSV ecosystem name, or "" when OSV has none.
func Ecosystem(eco model.Ecosystem) string {
	switch eco {
	case model.NPM:
		return "npm"
	case model.PyPI:
		return "PyPI"
	case model.Cargo:
		return "crates.io"
	default:
		return ""
	}
}

var _ advisory.Source = (*Client)(nil)
