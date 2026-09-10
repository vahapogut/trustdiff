package checks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/advisory/osv"
	"github.com/vahapogut/trustdiff/internal/advisory/osvindex"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// ErrNotConfigured is returned (wrapped) by DataLoader for a data source the run
// was built without, for example deps.dev when the caller passed a nil client.
// Checks treat it like any other unavailable source and report skipped.
var ErrNotConfigured = errors.New("data source not configured")

// ErrNoVersion is returned (wrapped) by the per-version methods of DataLoader when
// the ref carries no version. The runner resolves bare refs before it loads them;
// a check that reaches the loader with a bare ref has a bug.
var ErrNoVersion = errors.New("ref has no version")

// depsDevSource is the part of *depsdev.Client the loader uses; tests substitute
// a fake through newDataLoader.
type depsDevSource interface {
	Versions(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef]depsdev.VersionFacts, error)
	Findings(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef][]depsdev.Finding, error)
	SimilarNames(ctx context.Context, eco model.Ecosystem, name string) ([]depsdev.Similar, error)
}

var _ depsDevSource = (*depsdev.Client)(nil)

// DepsDevFindingsLoader is the optional method the runner uses to fill
// Subject.DepsDevFindings. DataLoader implements it. A Loader without it leaves
// the findings empty, which checks cannot tell from "no findings"; the Loader
// interface itself predates the findings batch and does not list the method.
type DepsDevFindingsLoader interface {
	DepsDevFindings(ctx context.Context, ref model.PackageRef) ([]depsdev.Finding, error)
}

// DataLoader implements Loader over the real sources: one registry.Source per
// ecosystem, an advisory.Source (OSV) and the deps.dev client. Every result is
// memoized for the life of the loader, which is one run: one fetch per package
// and per version however many checks and subjects ask, concurrent callers of the
// same key share one in-flight request, and errors are memoized too so a failing
// source is asked once. Package names are normalized with model.NormalizeName
// before they are used as keys, so a dependency name copied from a manifest shares
// the entry of the parsed ref.
//
// Prefetch warms the batch sources for every ref of a run in three calls (OSV
// querybatch, deps.dev versionbatch and findingsbatch); the per-ref methods return
// what Prefetch stored or fetch on demand for refs it did not cover, such as the
// dependencies TD007 inspects.
type DataLoader struct {
	reg registry.Registry
	adv advisory.Source
	dd  depsDevSource
	log *slog.Logger

	versions   memo[model.PackageRef, *registry.VersionList]
	infos      memo[model.PackageRef, *model.VersionInfo]
	owners     memo[model.PackageRef, []model.Publisher]
	downloads  memo[model.PackageRef, int64]
	advisories memo[model.PackageRef, []advisory.Advisory]
	facts      memo[model.PackageRef, *depsdev.VersionFacts]
	findings   memo[model.PackageRef, []depsdev.Finding]
	similar    memo[model.PackageRef, []depsdev.Similar]
}

var (
	_ Loader                = (*DataLoader)(nil)
	_ DepsDevFindingsLoader = (*DataLoader)(nil)
)

// NewLoader builds a loader for one run. adv and dd may be nil, for example when
// the run is offline and the caller chose not to build them; the methods that
// need them then return ErrNotConfigured and the runner reports the source as
// unavailable. A nil log discards diagnostics.
func NewLoader(reg registry.Registry, adv advisory.Source, dd *depsdev.Client, log *slog.Logger) *DataLoader {
	// A nil *depsdev.Client must become a nil interface, or the nil check below
	// would pass and the first call would dereference it.
	var source depsDevSource
	if dd != nil {
		source = dd
	}
	return newDataLoader(reg, adv, source, log)
}

func newDataLoader(reg registry.Registry, adv advisory.Source, dd depsDevSource, log *slog.Logger) *DataLoader {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &DataLoader{reg: reg, adv: adv, dd: dd, log: log}
}

// Prefetch warms the OSV and deps.dev batches for every ref that carries a
// version. Refs without a version are skipped: the batch endpoints answer per
// version, and the runner resolves bare refs before it calls Prefetch. Refs of an
// ecosystem a source does not index are left out of its batch, as the source
// itself would leave them out of its answer; the per-ref methods report them as
// unsupported without a request. The three batches run concurrently. A batch that
// fails stores its error for every ref it covered, so the source is not asked again
// for them; a batch that lost only some of its refs stores the error for those and
// the answers for the rest; a batch that failed because ctx ended stores nothing.
func (l *DataLoader) Prefetch(ctx context.Context, refs []model.PackageRef) {
	versioned := uniqueVersioned(refs)
	if len(versioned) == 0 {
		return
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		l.prefetchAdvisories(ctx, versioned)
	}()
	go func() {
		defer wg.Done()
		l.prefetchFacts(ctx, versioned)
	}()
	go func() {
		defer wg.Done()
		l.prefetchFindings(ctx, versioned)
	}()
	wg.Wait()
}

// uniqueVersioned returns the refs that carry a version, normalized and
// deduplicated, in first-seen order.
func uniqueVersioned(refs []model.PackageRef) []model.PackageRef {
	seen := make(map[model.PackageRef]bool, len(refs))
	out := make([]model.PackageRef, 0, len(refs))
	for _, ref := range refs {
		ref = normalizeRef(ref)
		if ref.Version == "" || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	return out
}

func (l *DataLoader) prefetchAdvisories(ctx context.Context, refs []model.PackageRef) {
	refs = osvSupported(refs)
	if l.adv == nil || len(refs) == 0 {
		return
	}
	l.log.Debug("prefetching advisories", "refs", len(refs))
	results, err := l.adv.Advisories(ctx, refs)
	if err != nil && ctx.Err() != nil {
		return
	}
	// A source that answered some refs and not others returns those answers together
	// with an *advisory.PartialError naming the ones it lost. Storing the batch error
	// for every ref would report an outage for packages the source did answer for,
	// and every check that reads them would skip instead of saying what came back.
	var partial *advisory.PartialError
	switch {
	case errors.As(err, &partial):
		l.logBatchFailure("advisory batch partly failed", len(partial.Refs), err)
	case err != nil:
		l.logBatchFailure("advisory batch failed", len(refs), err)
	}
	for _, ref := range refs {
		switch {
		case partial != nil:
			if lost, ok := partial.Refs[ref]; ok {
				l.advisories.store(ref, nil, lost)
				continue
			}
			l.advisories.store(ref, results[ref], nil)
		case err != nil:
			l.advisories.store(ref, nil, err)
		default:
			l.advisories.store(ref, results[ref], nil)
		}
	}
}

func (l *DataLoader) prefetchFacts(ctx context.Context, refs []model.PackageRef) {
	refs = depsDevSupported(refs)
	if l.dd == nil || len(refs) == 0 {
		return
	}
	l.log.Debug("prefetching deps.dev version facts", "refs", len(refs))
	results, err := l.dd.Versions(ctx, refs)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		l.logBatchFailure("deps.dev version batch failed", len(refs), err)
	}
	for _, ref := range refs {
		if err != nil {
			l.facts.store(ref, nil, err)
			continue
		}
		l.facts.store(ref, factsFor(results, ref), nil)
	}
}

func (l *DataLoader) prefetchFindings(ctx context.Context, refs []model.PackageRef) {
	refs = depsDevSupported(refs)
	if l.dd == nil || len(refs) == 0 {
		return
	}
	l.log.Debug("prefetching deps.dev findings", "refs", len(refs))
	results, err := l.dd.Findings(ctx, refs)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		l.logBatchFailure("deps.dev findings batch failed", len(refs), err)
	}
	for _, ref := range refs {
		if err != nil {
			l.findings.store(ref, nil, err)
			continue
		}
		l.findings.store(ref, results[ref], nil)
	}
}

// logBatchFailure reports a failed batch. An outage is worth a warning on stderr;
// an expected condition (offline with a cold cache, an ecosystem the source does
// not index, a source the run was built without) is already stated in the report
// as the skipped reason and only goes to the debug log.
func (l *DataLoader) logBatchFailure(msg string, refs int, err error) {
	// An offline run with no advisory index is the same kind of thing as an
	// offline run with a cold cache: expected, already said in every skipped
	// reason, and not something to print a warning about above the report.
	if definite(err) || errors.Is(err, httpcache.ErrOffline) || errors.Is(err, osvindex.ErrNoIndex) {
		l.log.Debug(msg, "refs", refs, "error", err)
		return
	}
	l.log.Warn(msg, "refs", refs, "error", err)
}

// osvSupported keeps the refs of ecosystems OSV indexes.
func osvSupported(refs []model.PackageRef) []model.PackageRef {
	out := make([]model.PackageRef, 0, len(refs))
	for _, ref := range refs {
		if osv.Ecosystem(ref.Ecosystem) != "" {
			out = append(out, ref)
		}
	}
	return out
}

// depsDevSupported keeps the refs of ecosystems deps.dev indexes.
func depsDevSupported(refs []model.PackageRef) []model.PackageRef {
	out := make([]model.PackageRef, 0, len(refs))
	for _, ref := range refs {
		if depsdev.System(ref.Ecosystem) != "" {
			out = append(out, ref)
		}
	}
	return out
}

// unsupportedError says a batch source does not index an ecosystem. It matches
// the source's own sentinel (osv.ErrUnsupported, depsdev.ErrUnsupported) through
// Unwrap and registry.ErrUnsupported through Is, so a check sees the same
// definite answer whichever sentinel it tests for.
type unsupportedError struct {
	eco      model.Ecosystem
	sentinel error
}

func (e *unsupportedError) Error() string   { return fmt.Sprintf("%s: %v", e.eco, e.sentinel) }
func (e *unsupportedError) Unwrap() error   { return e.sentinel }
func (e *unsupportedError) Is(t error) bool { return t == registry.ErrUnsupported }

// factsFor returns the batch entry for a ref, or facts with Found false when
// deps.dev did not list the version.
func factsFor(results map[model.PackageRef]depsdev.VersionFacts, ref model.PackageRef) *depsdev.VersionFacts {
	facts, ok := results[ref]
	if !ok {
		return &depsdev.VersionFacts{}
	}
	return &facts
}

// Versions implements Loader.
func (l *DataLoader) Versions(ctx context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error) {
	key := model.PackageRef{Ecosystem: eco, Name: model.NormalizeName(eco, name)}
	src, ok := l.reg.For(eco)
	if !ok {
		return nil, unsupportedEcosystem(eco)
	}
	list, err := l.versions.do(ctx, key, func(ctx context.Context) (*registry.VersionList, error) {
		l.log.Debug("fetching versions", "package", key.String())
		return src.Versions(ctx, key.Name)
	})
	if err != nil {
		return nil, fmt.Errorf("versions of %s: %w", key, err)
	}
	return list, nil
}

// VersionInfo implements Loader.
func (l *DataLoader) VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	key := normalizeRef(ref)
	if key.Version == "" {
		return nil, fmt.Errorf("version info of %s: %w", key, ErrNoVersion)
	}
	src, ok := l.reg.For(key.Ecosystem)
	if !ok {
		return nil, unsupportedEcosystem(key.Ecosystem)
	}
	info, err := l.infos.do(ctx, key, func(ctx context.Context) (*model.VersionInfo, error) {
		l.log.Debug("fetching version info", "ref", key.String())
		return src.VersionInfo(ctx, key)
	})
	if err != nil {
		return nil, fmt.Errorf("version info of %s: %w", key, err)
	}
	return info, nil
}

// Owners implements Loader.
func (l *DataLoader) Owners(ctx context.Context, eco model.Ecosystem, name string) ([]model.Publisher, error) {
	key := model.PackageRef{Ecosystem: eco, Name: model.NormalizeName(eco, name)}
	src, ok := l.reg.For(eco)
	if !ok {
		return nil, unsupportedEcosystem(eco)
	}
	owners, err := l.owners.do(ctx, key, func(ctx context.Context) ([]model.Publisher, error) {
		l.log.Debug("fetching owners", "package", key.String())
		return src.Owners(ctx, key.Name)
	})
	if err != nil {
		return nil, fmt.Errorf("owners of %s: %w", key, err)
	}
	return owners, nil
}

// Downloads implements Loader. The count is -1 whenever err is not nil.
func (l *DataLoader) Downloads(ctx context.Context, eco model.Ecosystem, name string) (int64, error) {
	key := model.PackageRef{Ecosystem: eco, Name: model.NormalizeName(eco, name)}
	src, ok := l.reg.For(eco)
	if !ok {
		return -1, unsupportedEcosystem(eco)
	}
	count, err := l.downloads.do(ctx, key, func(ctx context.Context) (int64, error) {
		l.log.Debug("fetching downloads", "package", key.String())
		return src.Downloads(ctx, key.Name)
	})
	if err != nil {
		return -1, fmt.Errorf("downloads of %s: %w", key, err)
	}
	return count, nil
}

// Advisories implements Loader. Ecosystems OSV does not index get
// osv.ErrUnsupported without a request, whether or not Prefetch saw the ref; a
// ref Prefetch did not cover is queried on its own.
func (l *DataLoader) Advisories(ctx context.Context, ref model.PackageRef) ([]advisory.Advisory, error) {
	key := normalizeRef(ref)
	if err := l.advisoryReady(key); err != nil {
		return nil, fmt.Errorf("advisories for %s: %w", key, err)
	}
	advisories, err := l.advisories.do(ctx, key, func(ctx context.Context) ([]advisory.Advisory, error) {
		l.log.Debug("fetching advisories", "ref", key.String())
		results, err := l.adv.Advisories(ctx, []model.PackageRef{key})
		if err != nil {
			return nil, err
		}
		return results[key], nil
	})
	if err != nil {
		return nil, fmt.Errorf("advisories for %s: %w", key, err)
	}
	return advisories, nil
}

// DepsDev implements Loader. Ecosystems deps.dev does not index get
// depsdev.ErrUnsupported without a request; a version deps.dev has never seen
// gets facts with Found false.
func (l *DataLoader) DepsDev(ctx context.Context, ref model.PackageRef) (*depsdev.VersionFacts, error) {
	key := normalizeRef(ref)
	if err := l.depsDevReady(key, true); err != nil {
		return nil, fmt.Errorf("deps.dev facts for %s: %w", key, err)
	}
	facts, err := l.facts.do(ctx, key, func(ctx context.Context) (*depsdev.VersionFacts, error) {
		l.log.Debug("fetching deps.dev version facts", "ref", key.String())
		results, err := l.dd.Versions(ctx, []model.PackageRef{key})
		if err != nil {
			return nil, err
		}
		return factsFor(results, key), nil
	})
	if err != nil {
		return nil, fmt.Errorf("deps.dev facts for %s: %w", key, err)
	}
	return facts, nil
}

// DepsDevFindings implements DepsDevFindingsLoader.
func (l *DataLoader) DepsDevFindings(ctx context.Context, ref model.PackageRef) ([]depsdev.Finding, error) {
	key := normalizeRef(ref)
	if err := l.depsDevReady(key, true); err != nil {
		return nil, fmt.Errorf("deps.dev findings for %s: %w", key, err)
	}
	findings, err := l.findings.do(ctx, key, func(ctx context.Context) ([]depsdev.Finding, error) {
		l.log.Debug("fetching deps.dev findings", "ref", key.String())
		results, err := l.dd.Findings(ctx, []model.PackageRef{key})
		if err != nil {
			return nil, err
		}
		return results[key], nil
	})
	if err != nil {
		return nil, fmt.Errorf("deps.dev findings for %s: %w", key, err)
	}
	return findings, nil
}

// SimilarNames implements Loader.
func (l *DataLoader) SimilarNames(ctx context.Context, eco model.Ecosystem, name string) ([]depsdev.Similar, error) {
	key := model.PackageRef{Ecosystem: eco, Name: model.NormalizeName(eco, name)}
	if err := l.depsDevReady(key, false); err != nil {
		return nil, fmt.Errorf("similar names for %s: %w", key, err)
	}
	similar, err := l.similar.do(ctx, key, func(ctx context.Context) ([]depsdev.Similar, error) {
		l.log.Debug("fetching similarly named packages", "package", key.String())
		return l.dd.SimilarNames(ctx, key.Ecosystem, key.Name)
	})
	if err != nil {
		return nil, fmt.Errorf("similar names for %s: %w", key, err)
	}
	return similar, nil
}

// advisoryReady reports why an advisory lookup cannot proceed: no source, an
// ecosystem OSV does not index, or a missing version.
func (l *DataLoader) advisoryReady(ref model.PackageRef) error {
	if l.adv == nil {
		return fmt.Errorf("%s: %w", SourceOSV, ErrNotConfigured)
	}
	if osv.Ecosystem(ref.Ecosystem) == "" {
		return &unsupportedError{eco: ref.Ecosystem, sentinel: osv.ErrUnsupported}
	}
	if ref.Version == "" {
		return ErrNoVersion
	}
	return nil
}

// depsDevReady reports why a deps.dev lookup cannot proceed: no client, an
// ecosystem deps.dev does not index, or a missing version when one is needed.
func (l *DataLoader) depsDevReady(ref model.PackageRef, needVersion bool) error {
	if l.dd == nil {
		return fmt.Errorf("%s: %w", SourceDepsDev, ErrNotConfigured)
	}
	if depsdev.System(ref.Ecosystem) == "" {
		return &unsupportedError{eco: ref.Ecosystem, sentinel: depsdev.ErrUnsupported}
	}
	if needVersion && ref.Version == "" {
		return ErrNoVersion
	}
	return nil
}

func unsupportedEcosystem(eco model.Ecosystem) error {
	return fmt.Errorf("no registry for %s: %w", eco, registry.ErrUnsupported)
}

// normalizeRef applies the ecosystem's canonical name spelling.
func normalizeRef(ref model.PackageRef) model.PackageRef {
	ref.Name = model.NormalizeName(ref.Ecosystem, ref.Name)
	return ref
}

// memo caches one value per key for the life of a run. The first caller of a key
// fetches while later callers wait for that result, so concurrent checks share one
// in-flight request; errors are stored too, so a failing source is asked once. The
// exception is a fetch that failed because the fetching caller's context ended:
// that says nothing about the source, so the entry is dropped and the next caller
// fetches again. A waiter whose own context ends stops waiting and returns its
// context error without touching the entry.
type memo[K comparable, V any] struct {
	mu      sync.Mutex
	entries map[K]*memoEntry[V]
}

type memoEntry[V any] struct {
	// ready is closed once val and err are set or the entry was abandoned.
	ready     chan struct{}
	val       V
	err       error
	abandoned bool
}

func (m *memo[K, V]) do(ctx context.Context, key K, fetch func(context.Context) (V, error)) (V, error) {
	for {
		m.mu.Lock()
		if m.entries == nil {
			m.entries = map[K]*memoEntry[V]{}
		}
		e, waiting := m.entries[key]
		if !waiting {
			e = &memoEntry[V]{ready: make(chan struct{})}
			m.entries[key] = e
		}
		m.mu.Unlock()

		if waiting {
			select {
			case <-e.ready:
				if e.abandoned {
					continue
				}
				return e.val, e.err
			case <-ctx.Done():
				var zero V
				return zero, ctx.Err()
			}
		}

		val, err := fetch(ctx)
		if err != nil && ctx.Err() != nil {
			m.mu.Lock()
			delete(m.entries, key)
			m.mu.Unlock()
			e.abandoned = true
			close(e.ready)
			return val, err
		}
		e.val, e.err = val, err
		close(e.ready)
		return val, err
	}
}

// store records a result obtained elsewhere, typically from a batch. An entry that
// already exists, complete or in flight, is left alone.
func (m *memo[K, V]) store(key K, val V, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = map[K]*memoEntry[V]{}
	}
	if _, exists := m.entries[key]; exists {
		return
	}
	e := &memoEntry[V]{ready: make(chan struct{}), val: val, err: err}
	close(e.ready)
	m.entries[key] = e
}
