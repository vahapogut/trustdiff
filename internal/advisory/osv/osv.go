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
// OSV lacks (Deno, JSR) are never sent: they are absent from the answer, and
// only a call made of nothing else is an ErrUnsupported error. A caller that
// mixes ecosystems must therefore test Ecosystem per ref before it reads an
// absent ref as "no advisories".
//
// Ecosystem names on the wire are npm, PyPI and crates.io. Package names are
// sent exactly as the ref spells them: npm matches legacy mixed-case names
// such as JSONStream case-sensitively (jsonstream is another package), while
// PyPI names are matched case-insensitively (Pillow and pillow answered the
// same). Advisory ids that start with MAL- come from ossf/malicious-packages,
// the MAL prefix of the OSV schema's id table, and mark a malicious version.
//
// A record's severity[] entries are typed CVSS_V2, CVSS_V3 (a v3.0 or v3.1
// vector string) or CVSS_V4 (OSV schema, severity[].type). The advisory
// severity is derived in this order, and SeveritySource records which step
// decided:
//
//  1. database_specific.severity when present and recognized (GHSA records
//     carry LOW, MODERATE, HIGH or CRITICAL). Score is still the base score of
//     the record's CVSS_V3 vector when it has one, and 0 otherwise. GitHub
//     rates a record on its newest vector, so the label may reflect a CVSS v4
//     assessment and disagree with the v3 score (GHSA-qw6h-vgh9-j6wx is LOW
//     with a v3 score of 5.0); SeveritySource is "database_specific".
//  2. Otherwise the base score computed from the first usable CVSS_V3 vector
//     with the equations of the CVSS v3.1 specification (see cvss.go), bucketed
//     with advisory.SeverityFromScore: a vector that scores 0.0 (no impact) is
//     SeverityNone, a published rating, not an unknown one. SeveritySource is
//     "cvss_v3".
//  3. Otherwise SeverityUnknown with Score 0 and no SeveritySource: a record
//     with only a CVSS_V4 entry (no v4 calculator in v0.1, see
//     docs/checks.md#td010), and records without severity at all such as
//     RUSTSEC and MAL- ones. Unknown counts as medium against a policy
//     threshold.
//
// Summary is the record's summary, or the first line of details when the
// record has none (some PYSEC records), cut at summaryMaxRunes.
//
// Failures stay local to what they touched. A querybatch chunk that fails
// loses only its own refs, a details request that fails loses only the refs
// that list that id, and the call returns the refs it did answer together with
// an *advisory.PartialError naming the rest. A MAL- id whose details request
// fails for any reason is answered from the batch entry, since the malicious
// flag is the whole signal and must survive a flaky record. An id the batch
// listed but the vulns endpoint does not know (404, a record withdrawn between
// the two requests) is dropped, never reported as an advisory of unknown
// severity, and an entry without an id is skipped. A record that arrives with a
// withdrawn timestamp is dropped as well: OSV filters withdrawn records out of
// the query API today, so it does not happen, but the offline index drops them
// and the two paths are not written to disagree about the same advisory. After
// maxDetailFailures failed details requests in one call the remaining ids are not
// requested: an outage is reported once, not once per advisory.
//
// The offline path answers the same refs from internal/advisory/osvindex through
// the same rules: the index stores the severity inputs and the timestamps
// verbatim, in UTC and in the record's own order, and the advisory is assembled
// here, so an offline run and an online run describe an advisory identically.
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
	"github.com/vahapogut/trustdiff/internal/advisory/osvindex"
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
	// maxDetailFailures is how many details requests may fail in one call
	// before the rest are given up without a request, each with retries of its
	// own already spent. Three tells an outage from one bad record.
	maxDetailFailures = 3
	// summaryMaxRunes bounds a summary derived from details.
	summaryMaxRunes = 200
)

// ErrUnsupported is returned (wrapped) when none of the refs belongs to an
// ecosystem OSV indexes (Deno and JSR have no OSV ecosystem). When only some
// refs are unsupported they are left out of the answer without an error, so a
// caller must check Ecosystem per ref before it treats an absent ref as
// answered.
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

// WithIndex makes the client answer from the offline advisory index instead of
// the API. A nil reader with a non-nil error means there is no index, and every
// call then fails with that error, whose message begins with "offline", so the
// checks report themselves as skipped with that reason. The pair is what
// osvindex.Open returns, so a caller passes it straight through.
func WithIndex(idx *osvindex.Reader, err error) Option {
	return func(c *Client) { c.index, c.indexErr = idx, err }
}

// Client is the OSV.dev client. All requests go through internal/httpcache. It
// holds no state of its own and is safe for concurrent use.
type Client struct {
	http *httpcache.Client
	base string
	log  *slog.Logger
	// index answers instead of the API when the caller opened one, which is what
	// --offline does. indexErr is what to say when the caller looked for an index
	// and there is none: it reaches the checks as the reason a check was skipped.
	index    *osvindex.Reader
	indexErr error
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
		Withdrawn        string                     `json:"withdrawn"`
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
//
// A failed chunk or details request loses only the refs it concerns (see the
// package comment): the answered refs come back with an *advisory.PartialError
// naming the lost ones, and only when no ref could be answered is the cause
// returned alone. A canceled context ends the call at once.
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
	// The index is asked after the ecosystems have been filtered, so a Deno or JSR
	// ref still gets ErrUnsupported and not a complaint about a missing index.
	if c.indexErr != nil {
		return nil, fmt.Errorf("osv: %w", c.indexErr)
	}
	if c.index != nil {
		return c.advisoriesFromIndex(distinct)
	}

	lost := &advisory.PartialError{Source: "osv", Refs: map[model.PackageRef]error{}}
	lose := func(ref model.PackageRef, err error) {
		if lost.Cause == nil {
			lost.Cause = err
		}
		lost.Refs[ref] = err
	}

	hits := make(map[model.PackageRef][]batchVuln, len(distinct))
	for chunk := range slices.Chunk(distinct, MaxQueriesPerBatch) {
		err := c.queryChunk(ctx, chunk, hits)
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return nil, err
		}
		c.log.Warn("osv querybatch chunk failed", "queries", len(chunk), "error", err)
		for _, ref := range chunk {
			// A page may already have been recorded before a later one failed.
			delete(hits, ref)
			lose(ref, err)
		}
	}

	details, failedIDs, err := c.details(ctx, hits)
	if err != nil {
		return nil, err
	}

	for _, ref := range distinct {
		if _, gone := lost.Refs[ref]; gone {
			continue
		}
		vulns := hits[ref]
		list := make([]advisory.Advisory, 0, len(vulns))
		for _, v := range vulns {
			if idErr, failed := failedIDs[v.ID]; failed {
				lose(ref, idErr)
				list = nil
				break
			}
			d, ok := details[v.ID]
			if !ok {
				// Dropped: an empty id, or a record the vulns endpoint no
				// longer serves.
				continue
			}
			a := *d
			a.Aliases = slices.Clone(a.Aliases)
			list = append(list, a)
		}
		if len(list) > 0 {
			out[ref] = list
		}
	}
	c.log.Debug("osv advisories assembled", "refs", len(distinct), "answered", len(distinct)-len(lost.Refs), "advisories", len(details))

	switch {
	case len(lost.Refs) == 0:
		return out, nil
	case len(lost.Refs) == len(distinct):
		return nil, lost.Cause
	default:
		return out, lost
	}
}

// details fetches the record of every distinct id the batch listed, in sorted
// order so a run is reproducible and the cache is filled the same way every
// time. It returns the records by id, the ids whose request failed with the
// error that failed each, and an error only when the context ended. An id that
// was dropped (empty, or a withdrawn non-MAL record) is in neither map. Once
// maxDetailFailures requests have failed the remaining ids are not requested:
// MAL- ids fall back to their batch entry, the others fail with the last error.
func (c *Client) details(ctx context.Context, hits map[model.PackageRef][]batchVuln) (map[string]*advisory.Advisory, map[string]error, error) {
	listed := make(map[string]batchVuln)
	empty := 0
	for _, vulns := range hits {
		for _, v := range vulns {
			if v.ID == "" {
				empty++
				continue
			}
			if _, ok := listed[v.ID]; !ok {
				listed[v.ID] = v
			}
		}
	}
	if empty > 0 {
		c.log.Warn("osv querybatch listed entries without an id, skipped", "entries", empty)
	}
	ids := slices.Sorted(maps.Keys(listed))
	details := make(map[string]*advisory.Advisory, len(ids))
	failed := make(map[string]error)
	var lastErr error
	for _, id := range ids {
		var a *advisory.Advisory
		var err error
		switch {
		case len(failed) < maxDetailFailures:
			a, err = c.detail(ctx, id, listed[id])
		case strings.HasPrefix(id, MaliciousPrefix):
			a = c.fallback(id, listed[id], "not requested after repeated failures")
		default:
			err = fmt.Errorf("osv: advisory %s: not requested after %d failed details requests: %w", id, len(failed), lastErr)
		}
		switch {
		case err != nil && ctx.Err() != nil:
			return nil, nil, err
		case err != nil:
			c.log.Warn("osv advisory details failed", "id", id, "error", err)
			failed[id] = err
			lastErr = err
		case a != nil:
			details[id] = a
		}
	}
	return details, failed, nil
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

// detail fetches one advisory record. A nil advisory with a nil error means
// the id is dropped: the vulns endpoint does not know it (a record withdrawn
// between the two requests), or the record says it has been withdrawn. A MAL- id
// is never failed and is dropped only when it was withdrawn: whatever else went
// wrong, it is answered from the batch entry alone, because the malicious flag it
// carries is the whole signal. A canceled context is the one error a MAL- id
// passes on, so the call can stop.
func (c *Client) detail(ctx context.Context, id string, listed batchVuln) (*advisory.Advisory, error) {
	malicious := strings.HasPrefix(id, MaliciousPrefix)
	u := c.base + "/vulns/" + url.PathEscape(id)
	resp, err := c.http.Get(ctx, u, httpcache.Request{Accept: acceptJSON, TTL: TTL})
	if err != nil {
		err = fmt.Errorf("osv: advisory %s: %w", id, err)
		if malicious && ctx.Err() == nil {
			return c.fallback(id, listed, err.Error()), nil
		}
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		if malicious {
			return c.fallback(id, listed, "listed by querybatch but not found"), nil
		}
		c.log.Warn("advisory listed by querybatch but not found, dropped", "id", id)
		return nil, nil
	default:
		err := fmt.Errorf("osv: advisory %s: unexpected status %d", id, resp.StatusCode)
		if malicious {
			return c.fallback(id, listed, err.Error()), nil
		}
		return nil, err
	}
	var rec vulnRecord
	if err := json.Unmarshal(resp.Body, &rec); err != nil {
		err = fmt.Errorf("osv: advisory %s: decoding response: %w", id, err)
		if malicious {
			return c.fallback(id, listed, err.Error()), nil
		}
		return nil, err
	}
	if rec.Withdrawn != "" {
		// A withdrawn advisory is not a finding, which is why the offline index
		// never returns one either. The query API filters withdrawn records
		// today, so nothing here reaches this line, and that is exactly why it
		// has to exist: the day the API stops filtering them, the two paths must
		// not start disagreeing about the same advisory. A MAL- id is dropped
		// too, for the same reason the index drops it.
		c.log.Warn("advisory withdrawn by the source, dropped", "id", id, "withdrawn", rec.Withdrawn)
		return nil, nil
	}
	// The record is the only source of the timestamps, on both paths. The batch
	// entry carries a modified of its own, but the offline index is built from
	// the archive alone and has no batch entry to fall back on, and a record that
	// reads one way online and another way offline is worse than a record with no
	// modified date. It is still what a MAL- fallback advisory is built from
	// below, since there the record itself never arrived.
	a := c.toAdvisory(id, &rec)
	c.log.Debug("osv advisory", "id", id, "severity", a.Severity, "score", a.Score, "malicious", a.Malicious, "from_cache", resp.FromCache)
	return &a, nil
}

// fallback builds a MAL- advisory from its batch entry alone, logging why the
// record itself was not used.
func (c *Client) fallback(id string, listed batchVuln, reason string) *advisory.Advisory {
	c.log.Warn("malicious-package advisory answered from the batch entry", "id", id, "reason", reason)
	a := c.toAdvisory(id, &vulnRecord{Modified: listed.Modified})
	return &a
}

// advisoriesFromIndex answers from the offline index, losing a ref the index
// cannot answer for in the same *advisory.PartialError the network path uses, so
// a caller cannot tell the two paths apart by the shape of what comes back.
func (c *Client) advisoriesFromIndex(refs []model.PackageRef) (map[model.PackageRef][]advisory.Advisory, error) {
	out := make(map[model.PackageRef][]advisory.Advisory, len(refs))
	lost := &advisory.PartialError{Source: "osv", Refs: map[model.PackageRef]error{}}
	for _, ref := range refs {
		records, err := c.index.Lookup(ref.Ecosystem, ref.Name, ref.Version)
		if err != nil {
			if lost.Cause == nil {
				lost.Cause = err
			}
			lost.Refs[ref] = err
			continue
		}
		list := make([]advisory.Advisory, 0, len(records))
		for i := range records {
			list = append(list, c.advisoryFromRecord(&records[i]))
		}
		if len(list) > 0 {
			out[ref] = list
		}
	}
	switch {
	case len(lost.Refs) == 0:
		return out, nil
	case len(lost.Refs) == len(refs):
		return nil, lost.Cause
	default:
		return out, lost
	}
}

// advisoryFromRecord rebuilds the record the severity rule expects out of what
// the index stored, so that toAdvisory decides offline exactly as it decides
// online. The severity rule lives in one place on purpose: an offline run that
// disagreed with an online one about how bad an advisory is would be worse than
// no offline run at all.
func (c *Client) advisoryFromRecord(r *osvindex.Record) advisory.Advisory {
	rec := &vulnRecord{ID: r.ID, Aliases: r.Aliases, Summary: r.Summary}
	if r.SeverityLabel != "" {
		if label, err := json.Marshal(r.SeverityLabel); err == nil {
			rec.DatabaseSpecific = map[string]json.RawMessage{"severity": label}
		}
	}
	// Every stored vector is handed back in the record's order, not just the
	// first, so that cvss3Score skips an unusable one offline exactly as it does
	// online. The index keeps the list for this.
	rec.Severity = make([]vulnSeverity, 0, len(r.CVSSv3))
	for _, vector := range r.CVSSv3 {
		rec.Severity = append(rec.Severity, vulnSeverity{Type: "CVSS_V3", Score: vector})
	}
	a := c.toAdvisory(r.ID, rec)
	// The index parsed the timestamps when it was built, so they are not parsed
	// again from strings that are no longer there.
	a.Published, a.Modified = r.Published, r.Modified
	return a
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
	a.Severity, a.Score, a.SeveritySource = c.severity(id, rec)
	return a
}

// severity applies the order documented in the package comment: the database
// label, then the computed CVSS v3 base score, then unknown. The third value
// names the step that decided (advisory.SeveritySourceLabel or
// SeveritySourceCVSS3) and is empty for unknown.
func (c *Client) severity(id string, rec *vulnRecord) (advisory.Severity, float64, string) {
	score, hasScore := c.cvss3Score(id, rec.Severity)
	if label := rec.databaseSeverity(); label != "" {
		if sev, err := advisory.ParseSeverity(label); err == nil && sev != advisory.SeverityUnknown {
			return sev, score, advisory.SeveritySourceLabel
		}
		c.log.Debug("unrecognized database_specific.severity", "id", id, "severity", label)
	}
	if hasScore {
		// A vector that scores 0.0 is the FIRST rating None, a published
		// rating and not a missing one.
		return advisory.SeverityFromScore(score), score, advisory.SeveritySourceCVSS3
	}
	return advisory.SeverityUnknown, 0, ""
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
// The result is converted to UTC, which is the instant the record means and the
// spelling the offline index stores, so that the same advisory carries the same
// timestamp whichever path answered it.
func (c *Client) parseTime(id, field, value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		c.log.Debug("unparsable timestamp", "id", id, "field", field, "value", value, "error", err)
		return time.Time{}
	}
	return t.UTC()
}

// Ecosystem maps an ecosystem to the OSV ecosystem name, or "" when OSV has
// none. It is the support test a caller applies per ref: Advisories leaves a
// ref with an empty Ecosystem out of its answer without an error unless every
// ref was one.
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
