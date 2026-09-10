package checks

import (
	"context"
	"sync"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// nowR is the clock every test run uses.
var nowR = time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)

// dayR returns a publish time n days before nowR.
func dayR(n int) time.Time { return nowR.AddDate(0, 0, -n) }

// pkgR builds a versionless ref.
func pkgR(eco model.Ecosystem, name string) model.PackageRef {
	return model.PackageRef{Ecosystem: eco, Name: name}
}

// stableListR builds a version list whose versions were published one day apart,
// oldest first, all stable, with the registry's latest set to the last one.
func stableListR(eco model.Ecosystem, name string, versions ...string) *registry.VersionList {
	list := &registry.VersionList{Ecosystem: eco, Name: name}
	for i, v := range versions {
		list.Versions = append(list.Versions, model.VersionInfo{
			Ref:         model.PackageRef{Ecosystem: eco, Name: name, Version: v},
			PublishedAt: dayR(len(versions) - i),
			Publisher:   &model.Publisher{Name: "alice"},
		})
	}
	if len(versions) > 0 {
		list.Latest = versions[len(versions)-1]
	}
	return list
}

// waitOrCtxR blocks until the gate closes or ctx ends; a nil gate returns at once.
func waitOrCtxR(ctx context.Context, gate chan struct{}) error {
	if gate == nil {
		return nil
	}
	select {
	case <-gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// counterR is a call counter shared by the fakes.
type counterR struct {
	mu    sync.Mutex
	calls map[string]int
}

func (c *counterR) inc(what string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls == nil {
		c.calls = map[string]int{}
	}
	c.calls[what]++
}

func (c *counterR) count(what string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[what]
}

// fakeSourceR is a registry.Source with canned answers. err, when set, is returned
// by every method; gate, when set, makes every method wait until it is closed.
type fakeSourceR struct {
	counterR
	eco       model.Ecosystem
	lists     map[string]*registry.VersionList
	infos     map[model.PackageRef]*model.VersionInfo
	owners    map[string][]model.Publisher
	downloads map[string]int64
	err       error
	gate      chan struct{}
	seen      []string
}

func newFakeSourceR(eco model.Ecosystem) *fakeSourceR {
	return &fakeSourceR{
		eco:       eco,
		lists:     map[string]*registry.VersionList{},
		infos:     map[model.PackageRef]*model.VersionInfo{},
		owners:    map[string][]model.Publisher{},
		downloads: map[string]int64{},
	}
}

// add registers a list and a detailed VersionInfo for each of its versions.
func (f *fakeSourceR) add(list *registry.VersionList) {
	f.lists[list.Name] = list
	for i := range list.Versions {
		info := list.Versions[i]
		f.infos[info.Ref] = &info
	}
}

func (f *fakeSourceR) record(what, name string) {
	f.inc(what)
	f.mu.Lock()
	f.seen = append(f.seen, name)
	f.mu.Unlock()
}

func (f *fakeSourceR) Ecosystem() model.Ecosystem { return f.eco }

func (f *fakeSourceR) Versions(ctx context.Context, name string) (*registry.VersionList, error) {
	f.record("versions", name)
	if err := waitOrCtxR(ctx, f.gate); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	list, ok := f.lists[name]
	if !ok {
		return nil, registry.ErrNotFound
	}
	return list, nil
}

func (f *fakeSourceR) VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	f.record("info", ref.String())
	if err := waitOrCtxR(ctx, f.gate); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	info, ok := f.infos[ref]
	if !ok {
		return nil, registry.ErrNotFound
	}
	return info, nil
}

func (f *fakeSourceR) Owners(ctx context.Context, name string) ([]model.Publisher, error) {
	f.record("owners", name)
	if err := waitOrCtxR(ctx, f.gate); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.owners[name], nil
}

func (f *fakeSourceR) Downloads(ctx context.Context, name string) (int64, error) {
	f.record("downloads", name)
	if err := waitOrCtxR(ctx, f.gate); err != nil {
		return -1, err
	}
	if f.err != nil {
		return -1, f.err
	}
	count, ok := f.downloads[name]
	if !ok {
		return -1, registry.ErrUnsupported
	}
	return count, nil
}

// fakeAdvisoriesR is an advisory.Source that records every batch it was asked.
type fakeAdvisoriesR struct {
	counterR
	results map[model.PackageRef][]advisory.Advisory
	err     error
	// lose names the refs this source cannot answer for. It answers the others and
	// returns an *advisory.PartialError, the shape the OSV client has when one
	// chunk of a batch fails and the rest came back.
	lose    map[model.PackageRef]error
	batches [][]model.PackageRef
}

func newFakeAdvisoriesR() *fakeAdvisoriesR {
	return &fakeAdvisoriesR{results: map[model.PackageRef][]advisory.Advisory{}}
}

func (f *fakeAdvisoriesR) Advisories(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef][]advisory.Advisory, error) {
	f.inc("advisories")
	f.mu.Lock()
	f.batches = append(f.batches, append([]model.PackageRef(nil), refs...))
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	out := map[model.PackageRef][]advisory.Advisory{}
	lost := &advisory.PartialError{Source: "osv", Refs: map[model.PackageRef]error{}}
	for _, ref := range refs {
		if err, ok := f.lose[ref]; ok {
			if lost.Cause == nil {
				lost.Cause = err
			}
			lost.Refs[ref] = err
			continue
		}
		if advisories, ok := f.results[ref]; ok {
			out[ref] = advisories
		}
	}
	if len(lost.Refs) > 0 {
		return out, lost
	}
	return out, nil
}

// fakeDepsDevR stands in for *depsdev.Client through the depsDevSource interface.
type fakeDepsDevR struct {
	counterR
	facts    map[model.PackageRef]depsdev.VersionFacts
	findings map[model.PackageRef][]depsdev.Finding
	similar  map[string][]depsdev.Similar
	err      error
	batches  map[string][][]model.PackageRef
}

func newFakeDepsDevR() *fakeDepsDevR {
	return &fakeDepsDevR{
		facts:    map[model.PackageRef]depsdev.VersionFacts{},
		findings: map[model.PackageRef][]depsdev.Finding{},
		similar:  map[string][]depsdev.Similar{},
		batches:  map[string][][]model.PackageRef{},
	}
}

func (f *fakeDepsDevR) batch(what string, refs []model.PackageRef) {
	f.inc(what)
	f.mu.Lock()
	f.batches[what] = append(f.batches[what], append([]model.PackageRef(nil), refs...))
	f.mu.Unlock()
}

func (f *fakeDepsDevR) Versions(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef]depsdev.VersionFacts, error) {
	f.batch("versions", refs)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	out := map[model.PackageRef]depsdev.VersionFacts{}
	for _, ref := range refs {
		if facts, ok := f.facts[ref]; ok {
			out[ref] = facts
		}
	}
	return out, nil
}

func (f *fakeDepsDevR) Findings(ctx context.Context, refs []model.PackageRef) (map[model.PackageRef][]depsdev.Finding, error) {
	f.batch("findings", refs)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	out := map[model.PackageRef][]depsdev.Finding{}
	for _, ref := range refs {
		if findings, ok := f.findings[ref]; ok {
			out[ref] = findings
		}
	}
	return out, nil
}

func (f *fakeDepsDevR) SimilarNames(_ context.Context, _ model.Ecosystem, name string) ([]depsdev.Similar, error) {
	f.inc("similar")
	if f.err != nil {
		return nil, f.err
	}
	return f.similar[name], nil
}

// fakeLoaderR is a Loader with canned answers for the runner tests. It has no
// DepsDevFindings method; fakeFindingsLoaderR adds it. fail maps a source name
// (SourceRegistry and its siblings) to the error every method of that source
// returns; failInfo makes VersionInfo fail for one ref only, the way a detail
// request can fail while the version list loaded.
type fakeLoaderR struct {
	counterR
	prefetched [][]model.PackageRef
	lists      map[model.PackageRef]*registry.VersionList
	infos      map[model.PackageRef]*model.VersionInfo
	owners     map[model.PackageRef][]model.Publisher
	downloads  map[model.PackageRef]int64
	advisories map[model.PackageRef][]advisory.Advisory
	facts      map[model.PackageRef]*depsdev.VersionFacts
	findings   map[model.PackageRef][]depsdev.Finding
	similar    map[model.PackageRef][]depsdev.Similar
	fail       map[string]error
	failInfo   map[model.PackageRef]error
}

func newFakeLoaderR() *fakeLoaderR {
	return &fakeLoaderR{
		lists:      map[model.PackageRef]*registry.VersionList{},
		infos:      map[model.PackageRef]*model.VersionInfo{},
		owners:     map[model.PackageRef][]model.Publisher{},
		downloads:  map[model.PackageRef]int64{},
		advisories: map[model.PackageRef][]advisory.Advisory{},
		facts:      map[model.PackageRef]*depsdev.VersionFacts{},
		findings:   map[model.PackageRef][]depsdev.Finding{},
		similar:    map[model.PackageRef][]depsdev.Similar{},
		fail:       map[string]error{},
		failInfo:   map[model.PackageRef]error{},
	}
}

// add registers a list and a VersionInfo for each of its versions.
func (f *fakeLoaderR) add(list *registry.VersionList) {
	f.lists[pkgR(list.Ecosystem, list.Name)] = list
	for i := range list.Versions {
		info := list.Versions[i]
		f.infos[info.Ref] = &info
	}
}

func (f *fakeLoaderR) prefetchCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.prefetched)
}

func (f *fakeLoaderR) Prefetch(_ context.Context, refs []model.PackageRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prefetched = append(f.prefetched, append([]model.PackageRef(nil), refs...))
}

func (f *fakeLoaderR) Versions(_ context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error) {
	f.inc("versions")
	if err := f.fail[SourceRegistry]; err != nil {
		return nil, err
	}
	list, ok := f.lists[pkgR(eco, name)]
	if !ok {
		return nil, registry.ErrNotFound
	}
	return list, nil
}

func (f *fakeLoaderR) VersionInfo(_ context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	f.inc("info")
	if err := f.fail[SourceRegistry]; err != nil {
		return nil, err
	}
	if err := f.failInfo[ref]; err != nil {
		return nil, err
	}
	info, ok := f.infos[ref]
	if !ok {
		return nil, registry.ErrNotFound
	}
	return info, nil
}

func (f *fakeLoaderR) Owners(_ context.Context, eco model.Ecosystem, name string) ([]model.Publisher, error) {
	f.inc("owners")
	if err := f.fail[SourceOwners]; err != nil {
		return nil, err
	}
	return f.owners[pkgR(eco, name)], nil
}

func (f *fakeLoaderR) Downloads(_ context.Context, eco model.Ecosystem, name string) (int64, error) {
	f.inc("downloads")
	if err := f.fail[SourceDownloads]; err != nil {
		return -1, err
	}
	count, ok := f.downloads[pkgR(eco, name)]
	if !ok {
		return -1, registry.ErrUnsupported
	}
	return count, nil
}

func (f *fakeLoaderR) Advisories(_ context.Context, ref model.PackageRef) ([]advisory.Advisory, error) {
	f.inc("advisories")
	if err := f.fail[SourceOSV]; err != nil {
		return nil, err
	}
	return f.advisories[ref], nil
}

func (f *fakeLoaderR) DepsDev(_ context.Context, ref model.PackageRef) (*depsdev.VersionFacts, error) {
	f.inc("depsdev")
	if err := f.fail[SourceDepsDev]; err != nil {
		return nil, err
	}
	if facts, ok := f.facts[ref]; ok {
		return facts, nil
	}
	return &depsdev.VersionFacts{}, nil
}

func (f *fakeLoaderR) SimilarNames(_ context.Context, eco model.Ecosystem, name string) ([]depsdev.Similar, error) {
	f.inc("similar")
	return f.similar[pkgR(eco, name)], nil
}

// fakeFindingsLoaderR is a fakeLoaderR that also serves deps.dev findings.
type fakeFindingsLoaderR struct {
	*fakeLoaderR
	findingsErr error
}

func (f *fakeFindingsLoaderR) DepsDevFindings(_ context.Context, ref model.PackageRef) ([]depsdev.Finding, error) {
	f.inc("findings")
	if f.findingsErr != nil {
		return nil, f.findingsErr
	}
	return f.findings[ref], nil
}

// fakeCheckR is a Check whose behavior is the run function.
type fakeCheckR struct {
	id   string
	name string
	ecos []model.Ecosystem
	run  func(ctx context.Context, s *Subject) Result
}

func (c fakeCheckR) ID() string                    { return c.id }
func (c fakeCheckR) Name() string                  { return c.name }
func (c fakeCheckR) Ecosystems() []model.Ecosystem { return c.ecos }
func (c fakeCheckR) Run(ctx context.Context, s *Subject) Result {
	if c.run == nil {
		return Result{}
	}
	return c.run(ctx, s)
}

// findingCheckR returns a check that reports one finding with the given title.
func findingCheckR(id, name, title string) fakeCheckR {
	c := fakeCheckR{id: id, name: name}
	c.run = func(_ context.Context, s *Subject) Result {
		return Result{Findings: []model.Finding{NewFinding(c, s, title, "explanation", map[string]any{"title": title})}}
	}
	return c
}

// passCheckR returns a check that runs and finds nothing.
func passCheckR(id, name string) fakeCheckR {
	return fakeCheckR{id: id, name: name}
}

// inputs parses refs into run inputs without location or direct flag.
func inputsR(refs ...string) []Input {
	out := make([]Input, 0, len(refs))
	for _, ref := range refs {
		out = append(out, Input{Ref: model.MustParseRef(ref)})
	}
	return out
}
