package typosquat

import (
	"slices"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Match is the popular neighbor a candidate name resembles.
type Match struct {
	// Candidate is the evaluated name in canonical spelling.
	Candidate string `json:"candidate"`
	// Neighbor is the popular name it resembles, in canonical spelling.
	Neighbor string `json:"neighbor"`
	// Rule is the heuristic that matched.
	Rule Rule `json:"rule"`
	// Distance is the Damerau-Levenshtein distance between the two spellings.
	Distance int `json:"distance"`
}

// Suspect reports whether name looks like a misspelling of a popular name in eco
// and returns the closest such neighbor: the smallest edit distance, then the
// earliest rule in Rules, then the alphabetically first name. A name that is
// itself popular, or empty, is never a suspect, and a nil or empty Set never
// matches.
//
// The scope rule runs for npm and JSR only, the ecosystems whose names carry a
// scope, and in both directions: types-node against a popular @types/node, and
// @babel/core against a popular babel-core. The other rules do not look at the
// ecosystem, so a scoped spelling evaluated elsewhere can still be an
// edit-distance match when the flattened popular name is long enough for two
// edits.
//
// The transposition and edit-distance rules skip popular names shorter than
// minFuzzyLength runes: two- and three-letter names are all within one edit of
// each other, so xo is not a suspect of ox nor np of pn. The exact rules still
// apply to them (ox-utils is a common-word match for ox).
func Suspect(eco model.Ecosystem, name string, popular *Set) (Match, bool) {
	c := Canonical(eco, name)
	if c == "" || popular.Len() == 0 || popular.hasCanonical(c) {
		return Match{}, false
	}
	var best Match
	found := false
	consider := func(neighbor string, rule Rule) {
		if neighbor == c {
			return
		}
		m := Match{Candidate: c, Neighbor: neighbor, Rule: rule, Distance: Distance(c, neighbor)}
		if !found || closer(m, best) {
			best, found = m, true
		}
	}
	lookup := func(groups map[string][]string, key string, rule Rule) {
		for _, neighbor := range groups[key] {
			consider(neighbor, rule)
		}
	}

	stripped := stripSeparators(c)
	lookup(popular.byStripped, stripped, RuleSeparator)

	if eco == model.NPM || eco == model.JSR {
		if scoped(c) {
			lookup(popular.byStripped, stripSeparators(flattenScope(c)), RuleScope)
		} else {
			lookup(popular.byFlat, stripped, RuleScope)
		}
	}

	for _, variant := range affixVariants(c) {
		lookup(popular.byStripped, variant, RuleAffix)
	}

	lookup(popular.byFolded, foldConfusables(stripped), RuleConfusable)

	for _, variant := range commonWordVariants(c) {
		lookup(popular.byStripped, variant, RuleCommonWord)
	}

	runes := []rune(c)
	// A transposition keeps the length, so the popular name is exactly as short
	// as the candidate.
	if len(runes) >= minFuzzyLength {
		for i := 0; i+1 < len(runes); i++ {
			if runes[i] == runes[i+1] {
				continue
			}
			swapped := slices.Clone(runes)
			swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
			if s := string(swapped); popular.hasCanonical(s) {
				consider(s, RuleTransposition)
			}
		}
	}

	var d distancer
	for i, neighbor := range popular.names {
		if len(popular.runes[i]) < minFuzzyLength {
			continue
		}
		limit := Threshold(neighbor)
		if absDiff(len(runes), len(popular.runes[i])) > limit {
			continue
		}
		if d.distance(runes, popular.runes[i]) <= limit {
			consider(neighbor, RuleEditDistance)
		}
	}
	return best, found
}

// closer orders matches: smaller distance, then earlier rule, then name.
func closer(a, b Match) bool {
	if a.Distance != b.Distance {
		return a.Distance < b.Distance
	}
	if ra, rb := rulePriority(a.Rule), rulePriority(b.Rule); ra != rb {
		return ra < rb
	}
	return a.Neighbor < b.Neighbor
}

func rulePriority(r Rule) int {
	return slices.Index(Rules(), r)
}

// affixVariants returns the separator-free spellings a popular name would have
// if the candidate had gained or lost a language affix: the candidate with each
// affix stripped from either end, and the candidate with each affix added.
func affixVariants(c string) []string {
	stripped := stripSeparators(c)
	var out []string
	add := func(v string) {
		if v != "" && v != stripped && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	for _, affix := range languageAffixes {
		if rest, ok := strings.CutPrefix(c, affix); ok {
			add(stripSeparators(strings.TrimLeft(rest, separators)))
		}
		if rest, ok := strings.CutSuffix(c, affix); ok {
			add(stripSeparators(strings.TrimRight(rest, separators)))
		}
		add(affix + stripped)
		add(stripped + affix)
	}
	return out
}

// commonWordVariants returns the separator-free spellings of the candidate with
// one common-word token removed.
func commonWordVariants(c string) []string {
	parts := tokens(c)
	if len(parts) < 2 {
		return nil
	}
	var out []string
	for i, part := range parts {
		if !commonWords[part] {
			continue
		}
		rest := strings.Join(slices.Concat(parts[:i], parts[i+1:]), "")
		if rest != "" && !slices.Contains(out, rest) {
			out = append(out, rest)
		}
	}
	return out
}
