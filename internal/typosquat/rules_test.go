package typosquat

import (
	"slices"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

func TestCanonical(t *testing.T) {
	tests := []struct {
		eco  model.Ecosystem
		name string
		want string
	}{
		{model.PyPI, "Foo_Bar.baz", "foo-bar-baz"},
		{model.PyPI, " Requests ", "requests"},
		{model.NPM, "React", "react"},
		{model.NPM, "@Types/Node", "@types/node"},
		{model.Cargo, "Serde_JSON", "serde_json"},
		{model.Deno, "Std", "std"},
	}
	for _, tt := range tests {
		if got := Canonical(tt.eco, tt.name); got != tt.want {
			t.Errorf("Canonical(%s, %q) = %q, want %q", tt.eco, tt.name, got, tt.want)
		}
	}
}

func TestSet(t *testing.T) {
	s := NewSet(model.PyPI, []string{"Requests", "requests", "", "beautifulsoup4", "python_dateutil"})
	if got, want := s.Names(), []string{"beautifulsoup4", "python-dateutil", "requests"}; !slices.Equal(got, want) {
		t.Errorf("Names() = %v, want %v", got, want)
	}
	if s.Len() != 3 {
		t.Errorf("Len() = %d, want 3", s.Len())
	}
	for _, name := range []string{"requests", "REQUESTS", "python.dateutil"} {
		if !s.Has(name) {
			t.Errorf("Has(%q) = false", name)
		}
	}
	if s.Has("request") {
		t.Error("Has(request) = true")
	}
	if s.Ecosystem() != model.PyPI {
		t.Errorf("Ecosystem() = %s", s.Ecosystem())
	}
}

// suspectCase is one row of the rules table. Every rule of Rules must appear as
// the wanted rule of at least one row; TestSuspectCoversEveryRule checks that.
type suspectCase struct {
	name     string
	eco      model.Ecosystem
	popular  []string
	input    string
	want     string
	rule     Rule
	distance int
}

var suspectCases = []suspectCase{
	{name: "separator removed", eco: model.PyPI, popular: []string{"python-dateutil"}, input: "pythondateutil", want: "python-dateutil", rule: RuleSeparator, distance: 1},
	{name: "separator swapped", eco: model.NPM, popular: []string{"react-dom"}, input: "react_dom", want: "react-dom", rule: RuleSeparator, distance: 1},
	{name: "separator added", eco: model.Cargo, popular: []string{"tokio"}, input: "tok.io", want: "tokio", rule: RuleSeparator, distance: 1},
	{name: "scope written as prefix", eco: model.NPM, popular: []string{"@types/node"}, input: "types-node", want: "@types/node", rule: RuleScope, distance: 2},
	{name: "prefix written as scope", eco: model.NPM, popular: []string{"babel-core"}, input: "@babel/core", want: "babel-core", rule: RuleScope, distance: 2},
	{name: "scope confusion on jsr", eco: model.JSR, popular: []string{"@std/path"}, input: "std-path", want: "@std/path", rule: RuleScope, distance: 2},
	{name: "short scope pair in npm", eco: model.NPM, popular: []string{"types-foo"}, input: "@types/foo", want: "types-foo", rule: RuleScope, distance: 2},
	{name: "outside npm a long scope pair is only an edit-distance match", eco: model.PyPI, popular: []string{"types-node"}, input: "@types/node", want: "types-node", rule: RuleEditDistance, distance: 2},
	{name: "python prefix added", eco: model.PyPI, popular: []string{"requests"}, input: "python-requests", want: "requests", rule: RuleAffix, distance: 7},
	{name: "py suffix added", eco: model.PyPI, popular: []string{"requests"}, input: "requestspy", want: "requests", rule: RuleAffix, distance: 2},
	{name: "node prefix removed", eco: model.NPM, popular: []string{"node-fetch"}, input: "fetch", want: "node-fetch", rule: RuleAffix, distance: 5},
	{name: "js prefix added", eco: model.NPM, popular: []string{"lodash"}, input: "jslodash", want: "lodash", rule: RuleAffix, distance: 2},
	{name: "digit one for l", eco: model.NPM, popular: []string{"lodash"}, input: "1odash", want: "lodash", rule: RuleConfusable, distance: 1},
	{name: "zero for o", eco: model.NPM, popular: []string{"react-dom"}, input: "react-d0m", want: "react-dom", rule: RuleConfusable, distance: 1},
	{name: "two digits beyond the edit threshold", eco: model.PyPI, popular: []string{"pillow"}, input: "pi11ow", want: "pillow", rule: RuleConfusable, distance: 2},
	{name: "utils inserted", eco: model.NPM, popular: []string{"lodash"}, input: "lodash-utils", want: "lodash", rule: RuleCommonWord, distance: 6},
	{name: "cli inserted", eco: model.PyPI, popular: []string{"requests"}, input: "requests-cli", want: "requests", rule: RuleCommonWord, distance: 4},
	{name: "dev inserted in front", eco: model.Cargo, popular: []string{"serde"}, input: "dev-serde", want: "serde", rule: RuleCommonWord, distance: 4},
	{name: "adjacent transposition", eco: model.PyPI, popular: []string{"requests"}, input: "reqeusts", want: "requests", rule: RuleTransposition, distance: 1},
	{name: "one omission", eco: model.PyPI, popular: []string{"requests"}, input: "requets", want: "requests", rule: RuleEditDistance, distance: 1},
	{name: "one addition", eco: model.NPM, popular: []string{"lodash"}, input: "lodashh", want: "lodash", rule: RuleEditDistance, distance: 1},
	{name: "two edits on a long name", eco: model.PyPI, popular: []string{"beautifulsoup4"}, input: "beatifulsop4", want: "beautifulsoup4", rule: RuleEditDistance, distance: 2},
	{name: "canonical spelling of the input", eco: model.PyPI, popular: []string{"colorama"}, input: "Colorsama", want: "colorama", rule: RuleEditDistance, distance: 1},
	{name: "closest neighbor wins over rule order", eco: model.PyPI, popular: []string{"python-requestz", "requests"}, input: "requestz", want: "requests", rule: RuleEditDistance, distance: 1},
	{name: "alphabetical first on a tie", eco: model.PyPI, popular: []string{"lodasx", "lodas"}, input: "lodasy", want: "lodas", rule: RuleEditDistance, distance: 1},
	{name: "popular itself", eco: model.PyPI, popular: []string{"requests"}, input: "requests"},
	{name: "popular in another spelling", eco: model.PyPI, popular: []string{"requests"}, input: "Requests"},
	{name: "two edits on a short name", eco: model.PyPI, popular: []string{"requests"}, input: "reqest"},
	{name: "three edits on a long name", eco: model.PyPI, popular: []string{"beautifulsoup4"}, input: "beatifulsop"},
	{name: "unrelated", eco: model.NPM, popular: []string{"express", "lodash", "react"}, input: "left-pad"},
	{name: "scope confusion is npm only", eco: model.PyPI, popular: []string{"types-foo"}, input: "@types/foo"},
	{name: "popular scoped name is never a suspect", eco: model.NPM, popular: []string{"@types/node", "types-node"}, input: "types-node"},
	{name: "empty name", eco: model.NPM, popular: []string{"express"}, input: ""},
	{name: "empty set", eco: model.NPM, input: "exprss"},
}

func TestSuspect(t *testing.T) {
	for _, tt := range suspectCases {
		t.Run(tt.name, func(t *testing.T) {
			set := NewSet(tt.eco, tt.popular)
			got, ok := Suspect(tt.eco, tt.input, set)
			if tt.want == "" {
				if ok {
					t.Fatalf("Suspect(%q) = %+v, want no match", tt.input, got)
				}
				return
			}
			if !ok {
				t.Fatalf("Suspect(%q) found nothing, want %q by %s", tt.input, tt.want, tt.rule)
			}
			want := Match{Candidate: Canonical(tt.eco, tt.input), Neighbor: tt.want, Rule: tt.rule, Distance: tt.distance}
			if got != want {
				t.Errorf("Suspect(%q) = %+v, want %+v", tt.input, got, want)
			}
		})
	}
}

// TestSuspectCoversEveryRule makes sure the table above reaches each rule.
// TestSuspectNilSet checks that a missing list never matches and never panics.
func TestSuspectNilSet(t *testing.T) {
	var set *Set
	if set.Has("express") || set.Len() != 0 || set.Names() != nil || set.Ecosystem() != "" {
		t.Error("a nil Set is not empty")
	}
	if m, ok := Suspect(model.NPM, "exprss", set); ok {
		t.Errorf("Suspect() over a nil Set = %+v", m)
	}
}

func TestSuspectCoversEveryRule(t *testing.T) {
	covered := map[Rule]bool{}
	for _, tt := range suspectCases {
		if tt.want != "" {
			covered[tt.rule] = true
		}
	}
	for _, rule := range Rules() {
		if !covered[rule] {
			t.Errorf("rule %s has no table case", rule)
		}
	}
	if len(covered) != len(Rules()) {
		t.Errorf("table covers %d rules, Rules() lists %d", len(covered), len(Rules()))
	}
}

// TestPopularNamesNeverFlagThemselves is the first property of the brief: a name
// in the top list is never a suspect, whatever it resembles.
func TestPopularNamesNeverFlagThemselves(t *testing.T) {
	lists := Embedded()
	for _, eco := range listed {
		set, ok := lists.Popular(eco)
		if !ok {
			t.Fatalf("no embedded list for %s", eco)
		}
		for _, name := range set.Names() {
			if m, flagged := Suspect(eco, name, set); flagged {
				t.Errorf("%s:%s flagged itself as %+v", eco, name, m)
			}
		}
	}
}

// TestSuspectAgainstEmbedded exercises the rules against the real lists: a few
// well-known incidents must be caught and a few well-known packages must not.
func TestSuspectAgainstEmbedded(t *testing.T) {
	tests := []struct {
		eco   model.Ecosystem
		input string
		want  string
	}{
		{model.NPM, "crossenv", "cross-env"},
		{model.NPM, "exprss", "express"},
		{model.PyPI, "python-dateutils", "python-dateutil"},
		{model.PyPI, "reqeusts", "requests"},
		{model.Cargo, "serde_jsom", "serde_json"},
		{model.NPM, "react", ""},
		{model.PyPI, "requests", ""},
		{model.Cargo, "tokio", ""},
	}
	lists := Embedded()
	for _, tt := range tests {
		t.Run(string(tt.eco)+":"+tt.input, func(t *testing.T) {
			set, _ := lists.Popular(tt.eco)
			got, ok := Suspect(tt.eco, tt.input, set)
			if tt.want == "" {
				if ok {
					t.Errorf("Suspect(%q) = %+v, want no match", tt.input, got)
				}
				return
			}
			if !ok || got.Neighbor != tt.want {
				t.Errorf("Suspect(%q) = %+v, %v; want neighbor %q", tt.input, got, ok, tt.want)
			}
		})
	}
}

func BenchmarkSuspect(b *testing.B) {
	set, _ := Embedded().Popular(model.NPM)
	for b.Loop() {
		Suspect(model.NPM, "left-pad-utilz", set)
	}
}
