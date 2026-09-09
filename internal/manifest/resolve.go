package manifest

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
	"github.com/vahapogut/trustdiff/internal/registry"
)

// Source is the part of a registry the resolver needs: which versions a package
// has. checks.Loader satisfies it, which is how the check command hands the
// resolver the same cached, memoizing client the checks then read from, so that
// resolving a manifest and evaluating what it resolved to cost one fetch per
// package and not two.
type Source interface {
	Versions(ctx context.Context, eco model.Ecosystem, name string) (*registry.VersionList, error)
}

// Resolved is one declaration at the version the registry resolves it to today.
type Resolved struct {
	// Declaration is what the manifest wrote.
	Declaration Declaration
	// Ref is the declaration's package at the resolved version. It carries the
	// registry's own spelling of the name, which can differ from the manifest's:
	// crates.io answers serde_json for serde-json, and every other source the run
	// asks about the package has to be asked under the name the registry uses.
	Ref model.PackageRef
}

// Resolve resolves every declaration to the highest version its registry lists that
// satisfies it, leaving out yanked releases always and prereleases unless the
// declaration itself names one. jobs bounds the lookups made at once; a value below
// one means one.
//
// It returns the declarations it resolved, in the order they were given, and the
// ones it could not, with the reason. Nothing else is possible: a declaration whose
// range names nothing the registry has is reported, never rounded to the nearest
// version, because a report about a version the project would not install is worse
// than no report at all.
func Resolve(ctx context.Context, src Source, declarations []Declaration, jobs int) ([]Resolved, []Skipped) {
	if jobs < 1 {
		jobs = 1
	}
	// One answer per declaration, written by index, so the results keep the order
	// the manifest declared them in whatever order the lookups finish.
	type answer struct {
		name    string
		version string
		skipped *Skipped
	}
	answers := make([]answer, len(declarations))
	slots := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for i := range declarations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			d := &declarations[i]
			name, resolved, skipped := resolveOne(ctx, src, d)
			answers[i] = answer{name: name, version: resolved, skipped: skipped}
		}()
	}
	wg.Wait()

	out := make([]Resolved, 0, len(declarations))
	var skipped []Skipped
	for i := range answers {
		if answers[i].skipped != nil {
			skipped = append(skipped, *answers[i].skipped)
			continue
		}
		ref := declarations[i].Ref
		ref.Name = answers[i].name
		ref.Version = answers[i].version
		out = append(out, Resolved{Declaration: declarations[i], Ref: ref})
	}
	return out, skipped
}

// resolveOne resolves one declaration, returning the registry's spelling of the
// name and the version, or the reason nothing was resolved.
func resolveOne(ctx context.Context, src Source, d *Declaration) (name, resolved string, skipped *Skipped) {
	c, err := parseConstraint(d.Syntax, d.Range)
	if err != nil {
		return "", "", d.skipped("%v", err)
	}
	list, err := src.Versions(ctx, d.Ref.Ecosystem, d.Ref.Name)
	if err != nil {
		// A registry that answered "no such package" has answered; anything else
		// means it could not be consulted and a later run may do better, which is
		// what on_data_unavailable reacts to. The two are worded the way a skipped
		// check words them, so one run says one thing about one registry.
		if errors.Is(err, registry.ErrNotFound) || errors.Is(err, registry.ErrUnsupported) {
			return "", "", d.skipped("%v", err)
		}
		s := d.skipped("registry unavailable: %v", err)
		s.Unavailable = true
		return "", "", s
	}
	name = list.Name
	if name == "" {
		name = d.Ref.Name
	}
	pick, reason := highestAllowed(d.Ref.Ecosystem, list, c)
	if pick == "" {
		return "", "", d.skipped("%s", reason)
	}
	return name, pick, nil
}

// skipped builds the skipped record for a declaration, naming it the way the
// manifest does.
func (d *Declaration) skipped(format string, args ...any) *Skipped {
	name := d.Alias
	if name == "" {
		name = d.Ref.Name
	}
	return &Skipped{Name: name, Range: d.Range, Table: d.Table, Reason: fmt.Sprintf(format, args...)}
}

// highestAllowed picks the highest version of the list the constraint accepts,
// leaving out the yanked ones, or explains why there is none. The explanation says
// what stood in the way, because "no version matches" alone leaves a reader with
// nowhere to look: a range that matches only a yanked release and a range that
// matches nothing at all are different problems.
// eco is the declaration's ecosystem rather than the list's, because it is the one
// the caller asked about and a client that leaves the field empty must not silently
// change how versions are ordered.
func highestAllowed(eco model.Ecosystem, list *registry.VersionList, c *constraint) (pick, reason string) {
	var yanked int
	var newest string
	prereleasesOnly := len(list.Versions) > 0
	for i := range list.Versions {
		v := &list.Versions[i]
		raw := v.Ref.Version
		if raw == "" {
			continue
		}
		if !isPrerelease(eco, v) {
			prereleasesOnly = false
		}
		if newest == "" || higher(eco, raw, newest) {
			newest = raw
		}
		if !c.allows(raw) {
			continue
		}
		if v.Yanked {
			yanked++
			continue
		}
		if pick == "" || higher(eco, raw, pick) {
			pick = raw
		}
	}
	switch {
	case pick != "":
		return pick, ""
	case len(list.Versions) == 0 || newest == "":
		return "", "the registry lists no version of it"
	case yanked > 0:
		return "", fmt.Sprintf("the only %s the registry lists is yanked", countedMatches(yanked))
	case prereleasesOnly && !c.namesPrerelease():
		return "", fmt.Sprintf("every version the registry lists is a prerelease, and the range does not ask for one (newest %s)", newest)
	default:
		return "", fmt.Sprintf("no version the registry lists satisfies it (%d published, newest %s)", len(list.Versions), newest)
	}
}

// countedMatches words how many versions a range matched, for the reason above.
func countedMatches(n int) string {
	if n == 1 {
		return "version that matches"
	}
	return fmt.Sprintf("%d versions that match", n)
}

// isPrerelease reports whether a listed version is a prerelease. The registry's own
// flag is trusted first and the version scheme is asked when it is not set, because
// not every client fills the flag and a prerelease that reads as a release would be
// resolved to by a range that never asked for one.
func isPrerelease(eco model.Ecosystem, v *model.VersionInfo) bool {
	return v.Prerelease || version.IsPrerelease(eco, v.Ref.Version)
}
