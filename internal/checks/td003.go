package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// TD003 maintainers-changed reports a version whose maintainer set differs from the
// set recorded at the previous version, listing who was added and who was removed
// (brief section 4). It applies to every ecosystem, but only npm records the
// maintainer set per version (the packument's versions[<v>].maintainers,
// re-verified live on 2026-09-09); crates.io owners and PyPI roles are current
// state only, so those ecosystems report skipped until the baseline of M4 gives
// them a previous set to compare with. Names are compared case-insensitively. The
// check is skipped without a previous version or when either version records no
// maintainers at all, since an empty set is more likely missing data than a
// package that lost every maintainer.
//
// Evidence keys:
//
//	previous_version      the previous release the set was compared with
//	previous_maintainers  its maintainer names, sorted
//	maintainers           the evaluated version's maintainer names, sorted
//	added                 names present now and absent before, sorted
//	removed               names present before and absent now, sorted
type td003 struct{}

func init() { Register(td003{}) }

func (td003) ID() string                    { return "TD003" }
func (td003) Name() string                  { return "maintainers-changed" }
func (td003) Ecosystems() []model.Ecosystem { return nil }

// Run compares the two maintainer sets.
func (c td003) Run(_ context.Context, s *Subject) Result {
	if s.Ref.Ecosystem != model.NPM {
		return Skip(c.ID(), "baseline required (arrives in M4)")
	}
	if s.Version == nil {
		return noVersionSkip(c, s)
	}
	if s.Previous == nil {
		return Skip(c.ID(), "no earlier release to compare with")
	}
	ref := evaluatedRef(s)
	if len(s.Version.Maintainers) == 0 {
		return Skip(c.ID(), fmt.Sprintf("no maintainer set recorded for %s", ref.Version))
	}
	if len(s.Previous.Maintainers) == 0 {
		return Skip(c.ID(), fmt.Sprintf("no maintainer set recorded for the previous version %s", s.Previous.Ref.Version))
	}
	current := publisherNames(s.Version.Maintainers)
	previous := publisherNames(s.Previous.Maintainers)
	added := namesMissingFrom(current, previous)
	removed := namesMissingFrom(previous, current)
	if len(added) == 0 && len(removed) == 0 {
		return Result{}
	}

	var changes []string
	if len(added) > 0 {
		changes = append(changes, "added "+joinAnd(added))
	}
	if len(removed) > 0 {
		changes = append(changes, "removed "+joinAnd(removed))
	}
	title := fmt.Sprintf("Maintainers changed since %s: %s", s.Previous.Ref.Version, strings.Join(changes, ", "))
	explanation := fmt.Sprintf("%s listed %s as maintainer%s; %s lists %s: %s",
		s.Previous.Ref.Version, joinAnd(previous), plural(len(previous)),
		ref.Version, joinAnd(current), strings.Join(changes, " and "))
	evidence := map[string]any{
		"previous_version":     s.Previous.Ref.Version,
		"previous_maintainers": previous,
		"maintainers":          current,
		"added":                added,
		"removed":              removed,
	}
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
}

// publisherNames returns the distinct names of publishers, sorted, ignoring
// entries without a name.
func publisherNames(publishers []model.Publisher) []string {
	names := make([]string, 0, len(publishers))
	for _, p := range publishers {
		if p.Name != "" && !containsFold(names, p.Name) {
			names = append(names, p.Name)
		}
	}
	sort.Strings(names)
	return names
}

// namesMissingFrom returns the names in a that are not in b, ignoring case. The
// result is never nil so it encodes as an empty JSON array.
func namesMissingFrom(a, b []string) []string {
	out := []string{}
	for _, name := range a {
		if !containsFold(b, name) {
			out = append(out, name)
		}
	}
	return out
}
