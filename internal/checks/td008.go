package checks

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/typosquat"
)

// TD008 typosquat-suspect reports a package whose name looks like a misspelling
// of a popular package in the same ecosystem. The name is compared, in the
// canonical spelling of internal/typosquat (model.NormalizeName, lowercased, and
// for Cargo with "-" folded to "_"), with the ecosystem's popular list (the
// embedded snapshot, or the copy "cache refresh-lists" wrote when it is less
// than 30 days old at the run's clock) using the rules of that package: edit
// distance with a length-based threshold, adjacent transpositions, separator
// swaps, npm scope confusion, py, python, js and node affixes, digit and letter
// confusables and common-word insertions. A name that is itself popular is never
// a suspect, and the fuzzy rules leave popular names shorter than four
// characters alone, counting the bare half of a scoped name: a scope is shared by
// every package inside it, so it is not the part a squatter imitates and it buys
// no imitator a looser budget.
//
// A match is reported at the policy's level only for a candidate that could still
// be a squat: one whose first release is less than a year old, or whose weekly
// downloads are below the low-usage threshold. A package that is neither is one a
// project has been living with, and it is reported at warn however the policy is
// set, because blocking a gate on a name a project has installed for years is a
// cost with no finding behind it. A fact the run could not read never lowers the
// level: the demotion is the claim, and an unread half cannot make it.
//
// One thing takes that demotion back: the distance to the name the candidate
// resembles. crossenv is nine years old and still collects enough scanner traffic
// to clear a low-usage threshold, so age and users alone called the 2017 npm
// malware a package a project lives with. What tells it apart from a name that
// really is lived with is that cross-env has fourteen thousand times its
// downloads. A package a hundred times behind the name it imitates is where a typo
// lands, whatever its age, so the demotion does not apply to it. Both counts have
// to come from the registry's own weekly figures, which is one window for both
// names; a neighbor nobody could count vetoes nothing, for the same reason an
// unread half cannot demote.
//
// As a cross-check, deps.dev's similarly named packages are consulted through the
// Loader: a neighbor that is much more popular (it is in the popular list, or its
// weekly downloads are at least 100 times the candidate's when both are known)
// is added to the evidence, and reported on its own when no rule matched. A
// deps.dev error or an unsupported ecosystem means no cross-check, never a skip:
// the popular list is the primary source. The check is skipped only for an
// ecosystem without a popular list (Deno and JSR in this milestone). It applies
// to every ecosystem and is block by default.
//
// Evidence keys:
//
//	candidate        the evaluated name in canonical spelling
//	neighbor         the popular name it resembles (when a rule matched)
//	rule             the rule that matched: separator-swap, scope-confusion,
//	                 language-affix, confusable-characters, common-word,
//	                 transposition or edit-distance (when a rule matched)
//	distance         the Damerau-Levenshtein distance to the neighbor (when a rule matched)
//	list_fetched     the date of the popular list consulted, yyyy-mm-dd
//	list_origin      where that list came from: "embedded" for the snapshot in
//	                 the binary, the path of the refreshed file under the cache
//	                 directory, or "custom" for lists a caller supplied
//	deps_dev_neighbor a similarly named, much more popular package deps.dev
//	                  returned (when the cross-check found one)
//
// deps.dev, verified 2026-09-09 against a live GET
// /v3alpha/systems/NPM/packages/crossenv:similarlyNamedPackages: the response is
// {"packageKey": {"system", "name"}, "packages": [{"packageKey": {"system",
// "name"}}, ...]} and carries no popularity figure, so depsdev.Similar.Popularity
// is not consulted: a neighbor's popularity is judged here by list membership
// and by the registry download counts.

const (
	// depsDevNeighborFactor is how many times more weekly downloads a deps.dev
	// neighbor needs than the candidate to count as much more popular.
	depsDevNeighborFactor = 100
	// popularityGapFactor is how far behind the name it resembles a candidate has
	// to be before its own age and users stop counting for anything. It is the same
	// hundredfold, because it is the same question asked of the same numbers: is
	// this name the one people meant, or the one they mistyped.
	popularityGapFactor = 100
	// maxDepsDevNeighborLookups bounds the download lookups per subject.
	maxDepsDevNeighborLookups = 5
	// listDateLayout is the format of the list_fetched evidence.
	listDateLayout = "2006-01-02"
)

// typosquatSuspect holds the popular lists, loaded on first use because the
// refreshed copy lives in the cache directory and the embedded snapshot takes a
// moment to index. The load takes the run's clock, so that the 30-day freshness
// of a refreshed copy is judged at the same time as every other date of the run
// (TRUSTDIFF_NOW) and never at the wall clock; the lists are then kept for the
// life of the process.
type typosquatSuspect struct {
	mu    sync.Mutex
	lists *typosquat.Lists
	load  func(now time.Time) *typosquat.Lists
}

// registeredTyposquat is the instance the runner sees.
var registeredTyposquat = &typosquatSuspect{load: loadTyposquatLists}

func init() { Register(registeredTyposquat) }

// loadTyposquatLists prefers the refreshed copy under the trustdiff cache
// directory (TRUSTDIFF_CACHE_DIR or the platform default) when it is fresh at
// now and falls back to the embedded snapshot. The check has no logger, so a
// stale or unreadable copy is not reported here; a caller that wants the
// diagnostics (the check command under -v) loads the lists with typosquat.Load,
// its own clock and logger and passes them to SetTyposquatLists before the run.
func loadTyposquatLists(now time.Time) *typosquat.Lists {
	dir, err := httpcache.DefaultDir()
	if err != nil {
		return typosquat.Embedded()
	}
	return typosquat.Load(dir, now, nil)
}

// SetTyposquatLists replaces the popular lists TD008 consults, for a runner that
// loaded them itself (with a logger, or from a cache directory given on the
// command line). nil restores the default lazy loading.
func SetTyposquatLists(lists *typosquat.Lists) {
	registeredTyposquat.set(lists)
}

func (c *typosquatSuspect) set(lists *typosquat.Lists) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lists = lists
}

// popular returns the lists, loading them at now on first use.
func (c *typosquatSuspect) popular(now time.Time) *typosquat.Lists {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lists == nil {
		c.lists = c.load(now)
	}
	return c.lists
}

// ID implements Check.
func (*typosquatSuspect) ID() string { return "TD008" }

// Name implements Check.
func (*typosquatSuspect) Name() string { return "typosquat-suspect" }

// Ecosystems implements Check; nil means every ecosystem.
func (*typosquatSuspect) Ecosystems() []model.Ecosystem { return nil }

// Run implements Check.
func (c *typosquatSuspect) Run(ctx context.Context, s *Subject) Result {
	eco, name := s.Ref.Ecosystem, s.Ref.Name
	lists := c.popular(runClock(s))
	set, ok := lists.Popular(eco)
	if !ok || set.Len() == 0 {
		return Skip(c.ID(), "no popular package list for "+string(eco))
	}
	if set.Has(name) {
		return Result{}
	}
	candidate := typosquat.Canonical(eco, name)
	match, suspect := typosquat.Suspect(eco, name, set)
	neighbor, crossCheckDown := c.crossCheck(ctx, s, candidate, set)
	if !suspect && neighbor == "" {
		if crossCheckDown != "" {
			// The popular list is embedded and cannot fail, so a name it does not
			// resemble is half an answer: the cross-check is what catches a
			// look-alike the list has no entry for, and it did not run. Saying the
			// name is clean would be saying that machinery cleared it.
			return skipOutage(c, "the popular list matched nothing and the deps.dev cross-check could not be made", crossCheckDown)
		}
		return Result{}
	}

	evidence := map[string]any{"candidate": candidate}
	if list, ok := lists.List(eco); ok {
		evidence["list_fetched"] = list.Fetched.Format(listDateLayout)
	}
	if origin := lists.Origin(eco); origin != "" {
		evidence["list_origin"] = origin
	}
	var title, explanation string
	if suspect {
		evidence["neighbor"] = match.Neighbor
		evidence["rule"] = string(match.Rule)
		evidence["distance"] = match.Distance
		title = fmt.Sprintf("%q resembles the popular %s package %q", candidate, eco, match.Neighbor)
		explanation = fmt.Sprintf("%q is not among the %d most popular %s packages but %s (rule %s, edit distance %d)",
			candidate, set.Len(), eco, describeRule(match), match.Rule, match.Distance)
	} else {
		title = fmt.Sprintf("%q is similarly named to the much more popular %q", candidate, neighbor)
		explanation = fmt.Sprintf("%q is not among the %d most popular %s packages and deps.dev lists the much more popular %q as a similarly named package",
			candidate, set.Len(), eco, neighbor)
	}
	if neighbor != "" {
		evidence["deps_dev_neighbor"] = neighbor
		if suspect {
			explanation += fmt.Sprintf("; deps.dev also lists the much more popular %q as a similarly named package", neighbor)
		}
	}
	standing, clause := c.standing(ctx, s, resembled(match, suspect, neighbor), evidence)
	evidence["standing"] = standing
	explanation += clause
	f := NewFinding(c, s, title, explanation, evidence)
	if standing == standingEstablished {
		f.Level = min(f.Level, model.LevelWarn)
	}
	return Result{Findings: []model.Finding{f}}
}

// The standing of a candidate: what the run could tell about how long it has been
// around and how many people install it.
const (
	standingEstablished  = "established"
	standingOvershadowed = "overshadowed"
	standingYoung        = "young"
	standingLowUsage     = "low-usage"
	standingAgeUnknown   = "age-unknown"
	standingUsageUnkown  = "usage-unknown"
)

// establishedAge is how old a package has to be before this check stops treating it
// as one that could have been planted. A year is long past the window a squat
// lives in: a name registered to catch a typo is found and removed in days or
// weeks, and one that survives a year with real users is a package with a history,
// whatever else it is.
const establishedAge = 365 * 24 * time.Hour

// standing decides whether the finding may be reported below the level the policy
// set, and returns the sentence that says why. A look-alike is dangerous because it
// is new and almost nobody installs it; a package that is neither is a package a
// project has been living with, and reporting it at block failed the gate on names
// like lz4js and rison, which have been on npm for years.
//
// A fact the run could not read never demotes anything. The demotion is the claim
// here, so it rests on something somebody read; the other polarity would let a cold
// cache or a registry outage quietly downgrade the one check whose default is
// block, and nothing in the report would tell the two apart.
func (c *typosquatSuspect) standing(ctx context.Context, s *Subject, resembles []string, evidence map[string]any) (string, string) {
	if s.Package == nil {
		return standingAgeUnknown, ". The level stays at the configured one because the registry did not say when the package first appeared"
	}
	first := firstPublished(s.Package)
	if first.IsZero() {
		return standingAgeUnknown, ". The level stays at the configured one because the registry did not say when the package first appeared"
	}
	age := runClock(s).Sub(first)
	if age < establishedAge {
		return standingYoung, fmt.Sprintf(". The package first appeared %s, %s ago, which is inside the year this check treats a name as one that could have been planted",
			first.UTC().Format(time.RFC3339), durationText(age))
	}

	threshold := s.Setting("low-usage").MinWeeklyDownloads
	if s.Downloads >= 0 {
		if s.Downloads < threshold {
			return standingLowUsage, fmt.Sprintf(". The package has been on the registry since %s, but %d weekly downloads is below the low-usage threshold of %d",
				first.UTC().Format(time.RFC3339), s.Downloads, threshold)
		}
		if name, theirs, gap := c.popularityGap(ctx, s, resembles); gap {
			evidence["weekly_downloads"] = s.Downloads
			evidence["neighbor_weekly_downloads"] = theirs
			return standingOvershadowed, fmt.Sprintf(". The package has been on the registry since %s and has %d weekly downloads, but %q has %d, which is %d times as many. A package that far behind the name it resembles is where a typo lands whatever its age, so the level stays at the configured one",
				first.UTC().Format(time.RFC3339), s.Downloads, name, theirs, theirs/max(s.Downloads, 1))
		}
		return standingEstablished, fmt.Sprintf(". The level is lowered to warn because the package is one a project has been living with: it has been on the registry since %s and has %d weekly downloads, at or above the low-usage threshold of %d",
			first.UTC().Format(time.RFC3339), s.Downloads, threshold)
	}
	// No count from the registry. deps.dev answers the same question for the
	// registries that publish none, which is what TD012 falls back to; anything
	// else leaves the usage half unread, and an unread half cannot demote.
	if c.hasDepsDevFinding(s, lowUsageFindingType) {
		return standingLowUsage, ". deps.dev reports the package as low usage, and the registry publishes no counts of its own"
	}
	return standingUsageUnkown, ". The level stays at the configured one because nothing said how often the package is installed"
}

// resembled is the names this candidate was reported for looking like: the popular
// one a rule matched, and the one deps.dev named. Either may be absent and they may
// be the same package, so the caller reads whichever is there, once.
func resembled(match typosquat.Match, suspect bool, neighbor string) []string {
	var names []string
	if suspect && match.Neighbor != "" {
		names = append(names, match.Neighbor)
	}
	if neighbor != "" && !slices.Contains(names, neighbor) {
		names = append(names, neighbor)
	}
	return names
}

// popularityGap asks the registry how many people install the name this candidate
// resembles, and reports the first neighbor with popularityGapFactor times the
// candidate's own weekly downloads.
//
// Both counts come from the same registry's weekly figures, so they cover the same
// window and the ratio means something. A count the registry did not give is not a
// small count: the lookup simply found no gap, and the candidate keeps whatever its
// own age and users earned it. The candidate's own count is known here already,
// because a candidate with no count never reaches this far.
func (c *typosquatSuspect) popularityGap(ctx context.Context, s *Subject, resembles []string) (name string, theirs int64, gap bool) {
	if s.Loader == nil || s.Downloads < 0 {
		return "", 0, false
	}
	floor := popularityGapFactor * max(s.Downloads, 1)
	for _, n := range resembles {
		downloads, err := s.Loader.Downloads(ctx, s.Ref.Ecosystem, n)
		if err == nil && downloads >= floor {
			return n, downloads, true
		}
	}
	return "", 0, false
}

// hasDepsDevFinding reports whether deps.dev returned a finding of this type.
func (c *typosquatSuspect) hasDepsDevFinding(s *Subject, kind string) bool {
	for _, f := range s.DepsDevFindings {
		if f.Type == kind {
			return true
		}
	}
	return false
}

// describeRule words the match for the explanation; both names are quoted by
// the caller's sentence.
func describeRule(m typosquat.Match) string {
	switch m.Rule {
	case typosquat.RuleSeparator:
		return fmt.Sprintf("differs from %q only in separators", m.Neighbor)
	case typosquat.RuleScope:
		return fmt.Sprintf("is %q with its npm scope written differently", m.Neighbor)
	case typosquat.RuleAffix:
		return fmt.Sprintf("is %q with a language prefix or suffix added or removed", m.Neighbor)
	case typosquat.RuleConfusable:
		return fmt.Sprintf("differs from %q only in look-alike characters (1 for l, 0 for o)", m.Neighbor)
	case typosquat.RuleCommonWord:
		return fmt.Sprintf("is %q with a common word such as utils or cli inserted", m.Neighbor)
	case typosquat.RuleTransposition:
		return fmt.Sprintf("is %q with two adjacent characters swapped", m.Neighbor)
	default:
		return fmt.Sprintf("is within %d edit(s) of %q", m.Distance, m.Neighbor)
	}
}

// crossCheck asks deps.dev for similarly named packages and returns the first one
// that is much more popular than the candidate: a member of the popular list
// first, then, for at most maxDepsDevNeighborLookups neighbors, one whose weekly
// downloads are depsDevNeighborFactor times the candidate's.
//
// down is the reason deps.dev could not answer the similar-names question at all,
// and only for an outage: an ecosystem it does not index, a run built without it
// and a name it has never seen are answers, and the popular list is then the whole
// of what there was to know. Everything else that can come up short here, no
// Loader, an unknown download count, a neighbor lookup that failed, leaves the
// cross-check with no neighbor to offer and is not reported: the list still
// answered and those are not this check's deps.dev half.
func (c *typosquatSuspect) crossCheck(ctx context.Context, s *Subject, candidate string, set *typosquat.Set) (neighbor, down string) {
	if s.Loader == nil {
		return "", ""
	}
	similar, err := s.Loader.SimilarNames(ctx, s.Ref.Ecosystem, s.Ref.Name)
	if err != nil {
		if definite(err) {
			return "", ""
		}
		return "", sourceProblem(SourceDepsDev, err)
	}
	if len(similar) == 0 {
		return "", ""
	}
	neighbors := make([]string, 0, len(similar))
	for _, sim := range similar {
		n := typosquat.Canonical(s.Ref.Ecosystem, sim.Name)
		if n == "" || n == candidate {
			continue
		}
		if set.Has(n) {
			return n, ""
		}
		neighbors = append(neighbors, n)
	}
	if s.Downloads < 0 {
		return "", ""
	}
	floor := depsDevNeighborFactor * max(s.Downloads, 1)
	for i, n := range neighbors {
		if i == maxDepsDevNeighborLookups {
			break
		}
		downloads, err := s.Loader.Downloads(ctx, s.Ref.Ecosystem, n)
		if err == nil && downloads >= floor {
			return n, ""
		}
	}
	return "", ""
}
