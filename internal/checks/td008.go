package checks

import (
	"context"
	"fmt"
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
// characters alone.
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
	neighbor := c.crossCheck(ctx, s, candidate, set)
	if !suspect && neighbor == "" {
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
	return Result{Findings: []model.Finding{NewFinding(c, s, title, explanation, evidence)}}
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

// crossCheck asks deps.dev for similarly named packages and returns the first
// one that is much more popular than the candidate: a member of the popular
// list first, then, for at most maxDepsDevNeighborLookups neighbors, one whose
// weekly downloads are depsDevNeighborFactor times the candidate's. Anything
// unavailable (no Loader, a deps.dev error, unknown download counts) means no
// cross-check.
func (c *typosquatSuspect) crossCheck(ctx context.Context, s *Subject, candidate string, set *typosquat.Set) string {
	if s.Loader == nil {
		return ""
	}
	similar, err := s.Loader.SimilarNames(ctx, s.Ref.Ecosystem, s.Ref.Name)
	if err != nil || len(similar) == 0 {
		return ""
	}
	neighbors := make([]string, 0, len(similar))
	for _, sim := range similar {
		n := typosquat.Canonical(s.Ref.Ecosystem, sim.Name)
		if n == "" || n == candidate {
			continue
		}
		if set.Has(n) {
			return n
		}
		neighbors = append(neighbors, n)
	}
	if s.Downloads < 0 {
		return ""
	}
	floor := depsDevNeighborFactor * max(s.Downloads, 1)
	for i, n := range neighbors {
		if i == maxDepsDevNeighborLookups {
			break
		}
		downloads, err := s.Loader.Downloads(ctx, s.Ref.Ecosystem, n)
		if err == nil && downloads >= floor {
			return n
		}
	}
	return ""
}
