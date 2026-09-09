package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/baseline"
	"github.com/vahapogut/trustdiff/internal/model"
)

// TD003 maintainers-changed reports a package whose maintainer set differs from
// the set recorded before, listing who was added and who was removed (brief
// section 4). It applies to every ecosystem and answers in one of two ways.
//
// The registry way compares the maintainer set of the evaluated version with the
// set of the previous version. Only npm records a set per version (the packument's
// versions[<v>].maintainers, re-verified live on 2026-09-09), so this is the npm
// answer. It is preferred where it exists because it is exact: it says the set
// changed between these two releases and not merely at some point since.
//
// The baseline way compares the registry's current maintainer or owner set with
// the set .trustdiff/baseline.json recorded when the package was last observed
// (internal/baseline). It is how crates.io and PyPI are answered, whose owner and
// role endpoints are current state only, and how npm is answered when a version
// carries no set. The comparison does not depend on the version at all, so a set
// that changed while the locked version stayed put is reported too, as long as the
// run has a subject for the package: scan evaluates every locked entry, while diff
// only evaluates what the change touched, and "trustdiff baseline" is what reports
// the rest.
//
// A baseline entry older than the window a project refreshes in is still an
// answer: the sets differ or they do not. The finding says how old the record is,
// because that is what decides how much it says about when the change happened.
//
// Names are compared case-insensitively. The check is skipped, never passed, when
// neither way can answer: without a previous version, when either version records
// no maintainers at all (an empty set is more likely missing data than a package
// that lost every maintainer), and when the project has no baseline entry for the
// package or the registry did not answer with an owner set.
//
// Evidence keys of the registry way:
//
//	previous_version      the previous release the set was compared with
//	previous_maintainers  its maintainer names, sorted
//	maintainers           the evaluated version's maintainer names, sorted
//	added                 names present now and absent before, sorted
//	removed               names present before and absent now, sorted
//
// Evidence keys of the baseline way:
//
//	baseline_maintainers   the maintainer names the baseline recorded, sorted
//	maintainers            the registry's current maintainer names, sorted
//	added                  names present now and absent from the record, sorted
//	removed                names the record had and the registry no longer lists
//	baseline_version       the release the record was taken from
//	baseline_observed_at   when the record was made (RFC 3339)
//	baseline_age_days      how many whole days ago that was
//	baseline_rewritten     true when the change under review edited or deleted the
//	                       record, in which case the base revision's record is what
//	                       was compared
//	baseline_rewritten_maintainers  what the working tree's record now claims
//	baseline_deleted       true when the change deleted the record altogether
type td003 struct{}

func init() { Register(td003{}) }

func (td003) ID() string                    { return "TD003" }
func (td003) Name() string                  { return "maintainers-changed" }
func (td003) Ecosystems() []model.Ecosystem { return nil }

// Run tries the registry way first and falls back to the baseline. Each way
// returns the reason it could not answer, and a check that cannot answer at all
// reports both reasons rather than a pass.
func (c td003) Run(_ context.Context, s *Subject) Result {
	if s.Version == nil {
		return noVersionSkip(c, s)
	}
	res, registryReason := c.fromVersions(s)
	if registryReason == "" {
		return res
	}
	res, baselineReason := c.fromBaseline(s)
	if baselineReason == "" {
		return res
	}
	return Skip(c.ID(), registryReason+"; "+baselineReason)
}

// fromVersions compares the maintainer sets the two releases carry. The reason it
// returns is empty when it answered, whether with a finding or with a pass.
func (c td003) fromVersions(s *Subject) (Result, string) {
	if s.Ref.Ecosystem != model.NPM {
		// Verified live on 2026-09-09: crates.io owners and PyPI roles are the
		// current set only, with no per-version record to compare with.
		return Result{}, fmt.Sprintf("%s records no maintainer set per version", s.Ref.Ecosystem)
	}
	if reason, unavailable := s.Skipped(SourcePrevious); unavailable {
		return Result{}, reason
	}
	if s.Previous == nil {
		return Result{}, "no earlier release to compare with"
	}
	ref := evaluatedRef(s)
	if len(s.Version.Maintainers) == 0 {
		return Result{}, fmt.Sprintf("no maintainer set recorded for %s", ref.Version)
	}
	if len(s.Previous.Maintainers) == 0 {
		return Result{}, fmt.Sprintf("no maintainer set recorded for the previous version %s", s.Previous.Ref.Version)
	}
	current := publisherNames(s.Version.Maintainers)
	previous := publisherNames(s.Previous.Maintainers)
	added := namesMissingFrom(current, previous)
	removed := namesMissingFrom(previous, current)
	if len(added) == 0 && len(removed) == 0 {
		return Result{}, ""
	}

	changes := maintainerChangeText(added, removed)
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
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}, ""
}

// fromBaseline compares the registry's current maintainer or owner set with the
// set the project recorded. The reason it returns is empty when it answered.
func (c td003) fromBaseline(s *Subject) (Result, string) {
	record, reason := baselineRecord(s)
	if reason != "" {
		return Result{}, reason
	}
	pkg := s.Ref.Package()
	recorded := record.Observed.Maintainers
	if len(recorded) == 0 {
		return Result{}, fmt.Sprintf("the baseline entry for %s records no maintainer set", pkg)
	}
	current := publisherNames(s.Owners)
	if len(current) == 0 {
		if reason, unavailable := s.Skipped(SourceOwners); unavailable {
			return Result{}, reason
		}
		return Result{}, fmt.Sprintf("the registry lists no maintainer for %s now", pkg)
	}
	added := namesMissingFrom(current, recorded)
	removed := namesMissingFrom(recorded, current)
	if len(added) == 0 && len(removed) == 0 {
		return Result{}, ""
	}

	changes := maintainerChangeText(added, removed)
	title := fmt.Sprintf("Maintainers changed since the baseline: %s", strings.Join(changes, ", "))
	explanation := fmt.Sprintf("the baseline recorded %s as maintainer%s of %s when %s was observed, %s; the registry lists %s now: %s",
		joinAnd(recorded), plural(len(recorded)), pkg, record.Observed.Version,
		baselineAgeText(&record.Observed, runClock(s)),
		joinAnd(current), strings.Join(changes, " and "))
	if record.Observed.Version == s.Ref.Version {
		explanation += "; the locked version did not move, so nothing but the baseline says this happened"
	}
	evidence := map[string]any{
		"baseline_maintainers": recorded,
		"maintainers":          current,
		"added":                added,
		"removed":              removed,
	}
	explanation += baselineEvidence(evidence, &record, runClock(s))
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}, ""
}

// maintainerChangeText words the two halves of a maintainer set change, so the
// registry way and the baseline way say it the same way.
func maintainerChangeText(added, removed []string) []string {
	changes := make([]string, 0, 2)
	if len(added) > 0 {
		changes = append(changes, "added "+joinAnd(added))
	}
	if len(removed) > 0 {
		changes = append(changes, "removed "+joinAnd(removed))
	}
	return changes
}

// The baseline as the checks see it. TD002 and TD003 are the two checks the
// record exists for, so the interface and the helpers live here, beside the check
// that cannot answer for any ecosystem without them.

// BaselineLoader is the optional method a Loader implements to serve the trust
// signals a project recorded in .trustdiff/baseline.json. The Loader interface
// itself does not list it, the way it does not list DepsDevFindings: a baseline is
// not fetched from anywhere, it is read from the project once per run and handed
// to the checks through the loader because that is the one thing on a Subject that
// a command can put its own data into.
//
// A Loader without the method leaves the checks that need a record reporting
// themselves as skipped, which is what a run built without a baseline should say.
type BaselineLoader interface {
	// Baseline returns the record of a package, ignoring the ref's version.
	Baseline(ref model.PackageRef) (baseline.Record, bool)
}

// baselineStaleAfter is how old an observation may be before a finding built on
// it says so. Ninety days is where a record stops saying much about when a change
// happened: it still answers whether the set differs, which is the question the
// check asks, but a reader deciding how alarming the answer is deserves to be
// told that the record predates most of a quarter's releases.
const baselineStaleAfter = 90 * 24 * time.Hour

// baselineRecord returns the record the run holds for the subject's package, or
// the reason there is none, worded for a skip.
func baselineRecord(s *Subject) (baseline.Record, string) {
	loader, ok := s.Loader.(BaselineLoader)
	if !ok {
		return baseline.Record{}, "the run read no baseline"
	}
	record, found := loader.Baseline(s.Ref.Package())
	if !found {
		return baseline.Record{}, fmt.Sprintf("no baseline entry for %s (record one with trustdiff baseline)", s.Ref.Package())
	}
	return record, ""
}

// baselineAgeText says how long ago an observation was made, and adds what an old
// record means when it is older than baselineStaleAfter. The age is always
// stated: a finding that rests on a record has to say how old the record is.
func baselineAgeText(e *baseline.Entry, now time.Time) string {
	days := int(e.Age(now) / (24 * time.Hour))
	text := fmt.Sprintf("%d day%s ago", days, plural(days))
	if days == 0 {
		text = "less than a day ago"
	}
	if e.Age(now) > baselineStaleAfter {
		text += ", which is longer ago than a baseline is meant to go unrefreshed, so the change may have happened at any point since"
	}
	return text
}

// baselineEvidence adds the keys every finding built on a record carries and
// returns the sentence the explanation appends for a record the change under
// review rewrote. Rewriting the record of who used to maintain a package is what
// an attacker with commit access would do, so it is said in words and not only in
// the evidence map.
func baselineEvidence(evidence map[string]any, record *baseline.Record, now time.Time) string {
	entry := &record.Observed
	evidence["baseline_version"] = entry.Version
	evidence["baseline_observed_at"] = whenText(entry.ObservedAt)
	evidence["baseline_age_days"] = int(entry.Age(now) / (24 * time.Hour))
	if !record.Rewritten {
		return ""
	}
	evidence["baseline_rewritten"] = true
	if record.Current == nil {
		evidence["baseline_deleted"] = true
		return "; the change under review deleted this package's baseline entry, so the record the base revision holds was compared"
	}
	evidence["baseline_rewritten_maintainers"] = record.Current.Maintainers
	if record.Current.Publisher != "" {
		evidence["baseline_rewritten_publisher"] = record.Current.Publisher
	}
	claims := "no maintainer"
	if len(record.Current.Maintainers) > 0 {
		claims = joinAnd(record.Current.Maintainers)
	}
	return fmt.Sprintf("; the change under review rewrote this package's baseline entry, which now records %s, so the record the base revision holds was compared instead", claims)
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
