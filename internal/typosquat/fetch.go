package typosquat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
)

// maxNames caps every list so that each file, with its NOTICE line, stays under
// 15000 lines. hugovk publishes 15000 PyPI names and the two npm sources
// together exceed that; the least popular names are the ones dropped.
const maxNames = 14900

// cratesPerPage is the largest page crates.io serves.
const cratesPerPage = 100

// defaultCratesPages is how many pages Fetch reads from crates.io: 50 pages of
// 100 names, one request per second, so a refresh takes about a minute.
const defaultCratesPages = 50

// sourceTTL is the cache TTL of the source downloads. A refresh repeated within
// the hour, for example after a failure half way through the crates.io pages,
// reuses what was already fetched.
const sourceTTL = httpcache.DefaultTTL

// Sources are the URLs the popular lists are fetched from. The response shapes
// were verified against the live URLs on 2026-09-09 and are documented on each
// field; the parsers read only the fields listed there.
type Sources struct {
	// PyPI is the hugovk/top-pypi-packages artifact: 15000 names by 30-day
	// downloads, refreshed monthly. Shape: {"last_update": "...", "rows":
	// [{"download_count": N, "project": "name"}, ...]} ordered by downloads.
	PyPI string
	// NPMHighImpact is lib/top.js of wooorm/npm-high-impact: the packages npm
	// calls high impact (one million weekly downloads or 500 dependents). Shape:
	// a line "export const top = [" followed by one single-quoted name per line,
	// most downloaded first.
	NPMHighImpact string
	// NPMRank is raw.json of tristan-f-r/npm-rank (formerly LeoDog896/npm-rank;
	// the old URL redirects): the top 10000 packages. Shape: a JSON array of
	// objects with "name", ordered by popularity; the README promises the file
	// name and the array shape stay stable.
	NPMRank string
	// Crates is the crates.io list endpoint without a query string. Fetch adds
	// sort=downloads, per_page=100 and page=N. Shape: {"crates": [{"name":
	// "..."}, ...], "meta": {"total": N, "next_page": "?sort=...&page=2" or null}}.
	Crates string
	// CratesPages is how many pages Fetch reads; zero means defaultCratesPages.
	CratesPages int
}

// DefaultSources returns the live URLs.
func DefaultSources() Sources {
	return Sources{
		PyPI:          "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json",
		NPMHighImpact: "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js",
		NPMRank:       "https://github.com/tristan-f-r/npm-rank/releases/download/latest/raw.json",
		Crates:        "https://crates.io/api/v1/crates",
		CratesPages:   defaultCratesPages,
	}
}

// Licenses of the source data as observed on 2026-09-09, recorded in every
// NOTICE line. The date is the observation, not the fetch.
const (
	licensePyPI  = "CC BY 4.0 per the Zenodo record linked from the hugovk/top-pypi-packages README (the repository carries no license file, observed 2026-09-09)"
	licenseNPM   = "MIT (wooorm/npm-high-impact and tristan-f-r/npm-rank, observed 2026-09-09)"
	licenseCargo = "none stated by crates.io (https://crates.io/data-access, observed 2026-09-09), fetched under its API rules of one request per second with an identifying User-Agent"
)

// Option configures Fetch and Refresh.
type Option func(*fetcher)

// WithSources replaces the live URLs, for tests that serve fixtures.
func WithSources(s Sources) Option {
	return func(f *fetcher) { f.sources = s }
}

// WithLogger receives progress and diagnostics. The default discards.
func WithLogger(log *slog.Logger) Option {
	return func(f *fetcher) {
		if log != nil {
			f.log = log
		}
	}
}

// WithNow supplies the clock that stamps the fetched date. The default is time.Now.
func WithNow(now func() time.Time) Option {
	return func(f *fetcher) {
		if now != nil {
			f.now = now
		}
	}
}

// WithLimit caps the names kept per list. The default keeps each file under
// 15000 lines.
func WithLimit(n int) Option {
	return func(f *fetcher) {
		if n > 0 {
			f.limit = n
		}
	}
}

type fetcher struct {
	client  *httpcache.Client
	sources Sources
	log     *slog.Logger
	now     func() time.Time
	limit   int
}

func newFetcher(client *httpcache.Client, opts []Option) *fetcher {
	f := &fetcher{
		client:  client,
		sources: DefaultSources(),
		log:     slog.New(slog.DiscardHandler),
		now:     time.Now,
		limit:   maxNames,
	}
	for _, opt := range opts {
		opt(f)
	}
	if f.sources.CratesPages <= 0 {
		f.sources.CratesPages = defaultCratesPages
	}
	return f
}

// Fetch downloads the popular lists of every listed ecosystem through client:
// one request for PyPI, two for npm and CratesPages (by default 50) for
// crates.io, which the client spaces at one request per second. It stops at the
// first failure and returns the lists in the order npm, pypi, cargo.
func Fetch(ctx context.Context, client *httpcache.Client, opts ...Option) ([]*List, error) {
	if client == nil {
		return nil, errors.New("typosquat: a client is required")
	}
	f := newFetcher(client, opts)
	npm, err := f.npm(ctx)
	if err != nil {
		return nil, fmt.Errorf("npm list: %w", err)
	}
	pypi, err := f.pypi(ctx)
	if err != nil {
		return nil, fmt.Errorf("pypi list: %w", err)
	}
	cargo, err := f.cargo(ctx)
	if err != nil {
		return nil, fmt.Errorf("cargo list: %w", err)
	}
	return []*List{npm, pypi, cargo}, nil
}

// Refresh downloads the lists with Fetch and writes them under
// ListsDir(cacheDir), where Load prefers them for RefreshTTL. It makes about 50
// requests to crates.io at one request per second, so it takes about a minute;
// nothing is written unless every source succeeded.
func Refresh(ctx context.Context, client *httpcache.Client, cacheDir string, opts ...Option) error {
	lists, err := Fetch(ctx, client, opts...)
	if err != nil {
		return fmt.Errorf("refreshing popular lists: %w", err)
	}
	if err := WriteLists(ListsDir(cacheDir), lists); err != nil {
		return fmt.Errorf("refreshing popular lists: %w", err)
	}
	return nil
}

// get fetches one URL and returns the body of a 200. Any other status is an
// error, including the 404 the client reports as a response.
func (f *fetcher) get(ctx context.Context, url string) ([]byte, error) {
	resp, err := f.client.Get(ctx, url, httpcache.Request{TTL: sourceTTL})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	f.log.Debug("fetched popular list source", "url", url, "bytes", len(resp.Body), "from_cache", resp.FromCache)
	return resp.Body, nil
}

func (f *fetcher) newList(eco model.Ecosystem, source, license string, ranked []string) *List {
	names := make([]string, 0, min(len(ranked), f.limit))
	seen := make(map[string]struct{}, len(names))
	for _, name := range ranked {
		c := Canonical(eco, name)
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		names = append(names, c)
		if len(names) == f.limit {
			break
		}
	}
	f.log.Info("popular list fetched", "ecosystem", eco, "names", len(names), "ranked", len(ranked))
	return &List{Ecosystem: eco, Source: source, Fetched: f.now().UTC().Truncate(24 * time.Hour), License: license, Names: names}
}

func (f *fetcher) pypi(ctx context.Context) (*List, error) {
	body, err := f.get(ctx, f.sources.PyPI)
	if err != nil {
		return nil, err
	}
	ranked, err := parsePyPI(body)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", f.sources.PyPI, err)
	}
	return f.newList(model.PyPI, f.sources.PyPI, licensePyPI, ranked), nil
}

// npm unions the high-impact list (recent, ranked by downloads) with npm-rank
// (broader, its release asset updates less often), high impact first, so that
// the cap drops the least popular npm-rank names.
func (f *fetcher) npm(ctx context.Context) (*List, error) {
	body, err := f.get(ctx, f.sources.NPMHighImpact)
	if err != nil {
		return nil, err
	}
	ranked, err := parseNPMHighImpact(body)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", f.sources.NPMHighImpact, err)
	}
	body, err = f.get(ctx, f.sources.NPMRank)
	if err != nil {
		return nil, err
	}
	rank, err := parseNPMRank(body)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", f.sources.NPMRank, err)
	}
	ranked = append(ranked, rank...)
	source := f.sources.NPMHighImpact + " " + f.sources.NPMRank
	return f.newList(model.NPM, source, licenseNPM, ranked), nil
}

func (f *fetcher) cargo(ctx context.Context) (*List, error) {
	var ranked []string
	for page := 1; page <= f.sources.CratesPages; page++ {
		url := fmt.Sprintf("%s?sort=downloads&per_page=%d&page=%d", f.sources.Crates, cratesPerPage, page)
		body, err := f.get(ctx, url)
		if err != nil {
			return nil, err
		}
		names, next, err := parseCratesPage(body)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", url, err)
		}
		ranked = append(ranked, names...)
		f.log.Debug("crates.io page fetched", "page", page, "names", len(names))
		if next == "" || len(names) == 0 {
			break
		}
	}
	source := fmt.Sprintf("%s?sort=downloads&per_page=%d (pages 1 to %d)", f.sources.Crates, cratesPerPage, f.sources.CratesPages)
	return f.newList(model.Cargo, source, licenseCargo, ranked), nil
}

// parsePyPI reads the project names of the hugovk artifact, in file order.
func parsePyPI(data []byte) ([]string, error) {
	var doc struct {
		Rows []struct {
			Project string `json:"project"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Rows) == 0 {
		return nil, errors.New("no rows")
	}
	names := make([]string, 0, len(doc.Rows))
	for _, row := range doc.Rows {
		names = append(names, row.Project)
	}
	return names, nil
}

// parseNPMHighImpact reads the single-quoted names of lib/top.js. npm names
// cannot contain a quote, so a quoted string is exactly one name.
func parseNPMHighImpact(data []byte) ([]string, error) {
	const prefix = "export const top = ["
	text := strings.TrimSpace(string(data))
	if !strings.HasPrefix(text, prefix) {
		return nil, fmt.Errorf("want a file starting with %q", prefix)
	}
	var names []string
	rest := text[len(prefix):]
	for {
		start := strings.IndexByte(rest, '\'')
		if start < 0 {
			break
		}
		end := strings.IndexByte(rest[start+1:], '\'')
		if end < 0 {
			return nil, errors.New("unterminated quoted name")
		}
		names = append(names, rest[start+1:start+1+end])
		rest = rest[start+1+end+1:]
	}
	if len(names) == 0 {
		return nil, errors.New("no names")
	}
	return names, nil
}

// parseNPMRank reads the names of the npm-rank array, in rank order.
func parseNPMRank(data []byte) ([]string, error) {
	var packages []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &packages); err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, errors.New("no packages")
	}
	names := make([]string, 0, len(packages))
	for _, p := range packages {
		names = append(names, p.Name)
	}
	return names, nil
}

// parseCratesPage reads one page of the crates.io list: the crate names and the
// next_page link, empty on the last page.
func parseCratesPage(data []byte) (names []string, next string, err error) {
	var doc struct {
		Crates []struct {
			Name string `json:"name"`
		} `json:"crates"`
		Meta struct {
			NextPage *string `json:"next_page"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", err
	}
	names = make([]string, 0, len(doc.Crates))
	for _, c := range doc.Crates {
		names = append(names, c.Name)
	}
	if doc.Meta.NextPage != nil {
		next = *doc.Meta.NextPage
	}
	return names, next, nil
}
