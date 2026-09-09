package baseline

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Signals is what observing a package needs from a run's data source: the detail
// of one published release and the package's current maintainer or owner set.
// internal/checks.Loader satisfies it, and because that loader memoizes every
// answer for the life of a run, observing after the checks have run costs no
// request: every answer is already there.
//
// The interface is this narrow on purpose. A baseline records what a registry
// showed, so it must be built from the same answers the checks judged, and taking
// a whole loader here would let this package fetch things nobody looked at.
type Signals interface {
	VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error)
	Owners(ctx context.Context, eco model.Ecosystem, name string) ([]model.Publisher, error)
}

// defaultJobs bounds the concurrent lookups when the caller names no limit. It
// matches the default of --jobs, so observing a project is as gentle on a
// registry as evaluating it.
const defaultJobs = 8

// Observe reads the trust signals of every ref and returns one entry per package,
// sorted the way the file stores them, together with the problems that kept an
// entry from being complete, worded for a note beside the report.
//
// A problem is never a failure: a package whose owners could not be read is
// recorded without a maintainer set, and the check that wanted one reports itself
// as skipped later rather than reading the gap as a change. jobs bounds the
// concurrent lookups; values below 1 mean defaultJobs.
//
// A ref without a version is not observed at all: an entry says which release the
// publisher and the provenance were read from, and there is no such release for a
// package name on its own. A project that locks one package at several versions
// gets one entry, at the first version in ref order, and a problem line says so.
func Observe(ctx context.Context, src Signals, refs []model.PackageRef, now time.Time, jobs int) ([]Entry, []string) {
	targets, problems := targets(refs)
	if jobs < 1 {
		jobs = defaultJobs
	}
	entries := make([]Entry, len(targets))
	found := make([][]string, len(targets))
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for i := range targets {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			entries[i], found[i] = observe(ctx, src, targets[i], now)
		}()
	}
	wg.Wait()
	for _, list := range found {
		problems = append(problems, list...)
	}
	slices.SortFunc(entries, func(a, b Entry) int {
		if c := strings.Compare(string(a.Ecosystem), string(b.Ecosystem)); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	slices.Sort(problems)
	return entries, problems
}

// targets reduces the refs of a run to one per package, in the file's order, and
// reports the refs it had to leave out or choose between.
func targets(refs []model.PackageRef) ([]model.PackageRef, []string) {
	var problems []string
	at := make(map[model.PackageRef]int, len(refs))
	out := make([]model.PackageRef, 0, len(refs))
	for _, ref := range refs {
		ref.Name = model.NormalizeName(ref.Ecosystem, ref.Name)
		if ref.Version == "" {
			problems = append(problems, fmt.Sprintf("%s: no version to observe, so it was not recorded", ref))
			continue
		}
		pkg := ref.Package()
		if i, seen := at[pkg]; seen {
			if out[i].Version != ref.Version {
				problems = append(problems, fmt.Sprintf("%s is locked at %s and at %s; recorded %s",
					pkg, out[i].Version, ref.Version, out[i].Version))
			}
			continue
		}
		at[pkg] = len(out)
		out = append(out, ref)
	}
	return out, problems
}

// observe reads one package's signals. The two lookups are independent: what one
// of them could not answer leaves its field absent and the other's answer stands.
func observe(ctx context.Context, src Signals, ref model.PackageRef, now time.Time) (Entry, []string) {
	e := Entry{Ecosystem: ref.Ecosystem, Name: ref.Name, Version: ref.Version, ObservedAt: now}
	var problems []string
	info, err := src.VersionInfo(ctx, ref)
	if err != nil {
		problems = append(problems, fmt.Sprintf("%s: the release was not read (%v), so its publisher and provenance were not recorded", ref, err))
	} else {
		if reason, unknown := info.Unknown[model.FacetProvenance]; unknown {
			problems = append(problems, fmt.Sprintf("%s: provenance was not read (%s), so it was not recorded", ref, reason))
		} else if info.Provenance.Kind != "" {
			e.Provenance = &Provenance{Kind: info.Provenance.Kind, Verified: info.Provenance.Verified, Identity: info.Provenance.Identity}
		}
		e.Publisher, e.PublisherSource = PublisherOf(info)
	}
	owners, err := src.Owners(ctx, ref.Ecosystem, ref.Name)
	if err != nil {
		problems = append(problems, fmt.Sprintf("%s: the maintainer set was not read (%v), so it was not recorded", ref.Package(), err))
	} else {
		e.Maintainers = names(owners)
		if len(e.Maintainers) == 0 {
			problems = append(problems, fmt.Sprintf("%s: the registry named no maintainer, so none was recorded", ref.Package()))
		}
	}
	e.normalize()
	return e, problems
}

// PublisherOf returns the publishing identity of a release and where it came
// from, or the empty string when the registry exposes neither. It is what the
// baseline records and what a check compares a later release with, so both sides
// answer the same question the same way.
//
// The registry's own account wins when there is one (npm _npmUser, crates.io
// published_by). PyPI names none, and there the identity of the release's
// attestation or trusted publisher is the only publishing identity there is; it
// is used only when the provenance was actually read, so a failed lookup is never
// recorded as "published by nobody".
func PublisherOf(v *model.VersionInfo) (identity string, source PublisherSource) {
	if v == nil {
		return "", ""
	}
	if v.Publisher != nil && v.Publisher.Name != "" {
		return v.Publisher.Name, FromRegistry
	}
	if _, unknown := v.Unknown[model.FacetProvenance]; unknown {
		return "", ""
	}
	if v.Provenance.Identity != "" {
		return v.Provenance.Identity, FromProvenance
	}
	return "", ""
}

// names turns publishers into the sorted name set an entry records.
func names(publishers []model.Publisher) []string {
	out := make([]string, 0, len(publishers))
	for _, p := range publishers {
		out = append(out, p.Name)
	}
	return normalizeNames(out)
}

// Update merges observations into the baseline at path and writes it back,
// creating the file and the directory when the project has none. It returns the
// entries it dropped and the file it wrote, so the caller can say what changed.
//
// keep, when it is not nil, is every package the project locks: entries for
// anything else are dropped, which is what a full snapshot does. A partial run
// passes nil and leaves the rest of the file alone, because diff and scan with
// --update-baseline observe only what they evaluated and must not delete the
// record of a package they never looked at.
//
// Expected call sites: (*App).runBaseline for the snapshot, and
// (*App).evaluateWithBaseline for the --update-baseline of diff and scan, both in
// internal/cli/baseline.go.
func Update(path string, observed []Entry, keep []model.PackageRef, now time.Time) (dropped []Entry, err error) {
	f, err := Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f = New(now)
	case err != nil:
		return nil, err
	}
	f.UpdatedAt = now.UTC().Truncate(time.Second)
	for i := range observed {
		f.Put(&observed[i])
	}
	if keep != nil {
		dropped = f.Keep(keep)
	}
	if err := Write(path, f); err != nil {
		return nil, err
	}
	return dropped, nil
}

// Change is one difference between what the baseline recorded for a package and
// what a fresh observation found.
type Change struct {
	// Was is the entry the file held.
	Was Entry
	// Now is the fresh observation.
	Now Entry
	// Added and Removed are the maintainers the set gained and lost, sorted. They
	// are never nil, so they encode as empty JSON arrays.
	Added   []string
	Removed []string
}

// VersionMoved reports whether the project locks another release than the one the
// record was taken from. A maintainer set that changed while the version stayed
// is the case no run over lockfile changes can see, because nothing in the
// lockfile changed for the checks to be given a subject for.
func (c *Change) VersionMoved() bool { return c.Was.Version != c.Now.Version }

// Compare reports the packages whose maintainer set differs between the recorded
// baseline and a fresh observation, sorted like the file.
//
// Only maintainer sets are compared. A publisher belongs to one release, so
// comparing the publisher of two different releases is TD002's job and needs the
// release history that check reads; the maintainer set belongs to the package and
// is exactly what nothing else can answer for PyPI and crates.io.
//
// A package the file did not hold is not a change: an observation made for the
// first time has nothing to differ from. An entry recorded without a maintainer
// set is not a change either, because absent means "was not read".
func Compare(recorded *File, observed []Entry) []Change {
	var out []Change
	for i := range observed {
		fresh := &observed[i]
		was, ok := recorded.Lookup(fresh.Package())
		if !ok || len(was.Maintainers) == 0 || len(fresh.Maintainers) == 0 {
			continue
		}
		added, removed := missing(fresh.Maintainers, was.Maintainers), missing(was.Maintainers, fresh.Maintainers)
		if len(added) == 0 && len(removed) == 0 {
			continue
		}
		out = append(out, Change{Was: was, Now: *fresh, Added: added, Removed: removed})
	}
	return out
}

// missing returns the names in a that are not in b, ignoring case the way a
// registry does. The result is never nil so it encodes as an empty JSON array.
func missing(a, b []string) []string {
	out := []string{}
	for _, name := range a {
		if !slices.ContainsFunc(b, func(other string) bool { return strings.EqualFold(other, name) }) {
			out = append(out, name)
		}
	}
	return out
}
