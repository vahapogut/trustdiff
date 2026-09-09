package manifest

import (
	"strings"
	"testing"
)

// rangeCase is one range and the versions it must and must not accept. Both lists
// are spelled out rather than derived, because the point of the test is the
// boundary: a caret that stops one version too late installs a breaking change.
type rangeCase struct {
	text     string
	accepts  []string
	rejects  []string
	prelease bool
}

// assertRange checks one range against both its lists.
func assertRange(t *testing.T, syntax Syntax, tc *rangeCase) {
	t.Helper()
	c, err := parseConstraint(syntax, tc.text)
	if err != nil {
		t.Fatalf("parseConstraint(%s, %q) = %v", syntax, tc.text, err)
	}
	for _, v := range tc.accepts {
		if !c.allows(v) {
			t.Errorf("%s range %q rejects %s, want it accepted", syntax, tc.text, v)
		}
	}
	for _, v := range tc.rejects {
		if c.allows(v) {
			t.Errorf("%s range %q accepts %s, want it rejected", syntax, tc.text, v)
		}
	}
	if got := c.namesPrerelease(); got != tc.prelease {
		t.Errorf("%s range %q namesPrerelease = %v, want %v", syntax, tc.text, got, tc.prelease)
	}
}

func TestNPMRangeMatching(t *testing.T) {
	tests := []rangeCase{
		// The caret, and the zero versions that are the whole reason it exists.
		{text: "^1.2.3", accepts: []string{"1.2.3", "1.2.4", "1.9.0"}, rejects: []string{"1.2.2", "2.0.0", "1.0.0"}},
		{text: "^0.2.3", accepts: []string{"0.2.3", "0.2.9"}, rejects: []string{"0.2.2", "0.3.0", "1.0.0"}},
		{text: "^0.0.3", accepts: []string{"0.0.3"}, rejects: []string{"0.0.2", "0.0.4", "0.1.0"}},
		{text: "^0.0.x", accepts: []string{"0.0.0", "0.0.9"}, rejects: []string{"0.1.0"}},
		{text: "^0.0", accepts: []string{"0.0.0", "0.0.9"}, rejects: []string{"0.1.0"}},
		{text: "^0", accepts: []string{"0.0.1", "0.9.9"}, rejects: []string{"1.0.0"}},
		{text: "^1.x", accepts: []string{"1.0.0", "1.9.9"}, rejects: []string{"2.0.0", "0.9.9"}},

		// The tilde, which holds the minor when the text names one.
		{text: "~1.2.3", accepts: []string{"1.2.3", "1.2.9"}, rejects: []string{"1.2.2", "1.3.0"}},
		{text: "~1.2", accepts: []string{"1.2.0", "1.2.9"}, rejects: []string{"1.3.0", "1.1.9"}},
		{text: "~1", accepts: []string{"1.0.0", "1.9.9"}, rejects: []string{"2.0.0", "0.9.9"}},
		{text: "~0.0.3", accepts: []string{"0.0.3", "0.0.9"}, rejects: []string{"0.1.0", "0.0.2"}},
		{text: "~>1.2.3", accepts: []string{"1.2.9"}, rejects: []string{"1.3.0"}},

		// X-ranges, including the two spellings of everything.
		{text: "1.2.x", accepts: []string{"1.2.0", "1.2.7"}, rejects: []string{"1.3.0", "1.1.9"}},
		{text: "1.X", accepts: []string{"1.0.0", "1.9.9"}, rejects: []string{"2.0.0"}},
		{text: "*", accepts: []string{"0.0.1", "5.0.0"}, rejects: []string{"1.0.0-rc.1"}},
		{text: "", accepts: []string{"0.0.1", "5.0.0"}, rejects: []string{"1.0.0-rc.1"}},

		// Exact versions, and build metadata, which takes no part in comparison.
		{text: "1.2.3", accepts: []string{"1.2.3", "1.2.3+build.5"}, rejects: []string{"1.2.4", "1.2.3-rc.1"}},
		{text: "=1.2.3", accepts: []string{"1.2.3"}, rejects: []string{"1.2.4"}},
		{text: "v1.2.3", accepts: []string{"1.2.3"}, rejects: []string{"1.2.4"}},

		// Ordered comparisons, with the partial forms node-semver rewrites.
		{text: ">=1.2.3 <2.0.0", accepts: []string{"1.2.3", "1.9.9"}, rejects: []string{"1.2.2", "2.0.0"}},
		{text: ">= 1.2.3 < 2.0.0", accepts: []string{"1.2.3"}, rejects: []string{"2.0.0"}},
		{text: ">1.2", accepts: []string{"1.3.0", "2.0.0"}, rejects: []string{"1.2.0", "1.2.9"}},
		{text: ">1.2.3", accepts: []string{"1.2.4"}, rejects: []string{"1.2.3"}},
		{text: ">=1.2", accepts: []string{"1.2.0"}, rejects: []string{"1.1.9"}},
		{text: "<1.2", accepts: []string{"1.1.9"}, rejects: []string{"1.2.0"}},
		{text: "<=0.7.x", accepts: []string{"0.7.9"}, rejects: []string{"0.8.0"}},
		{text: ">*", rejects: []string{"1.0.0", "0.0.1"}},
		{text: ">=*", accepts: []string{"1.0.0"}},

		// Hyphen ranges.
		{text: "1.2.3 - 2.3.4", accepts: []string{"1.2.3", "2.3.4"}, rejects: []string{"1.2.2", "2.3.5"}},
		{text: "1.2 - 2.3", accepts: []string{"1.2.0", "2.3.9"}, rejects: []string{"1.1.9", "2.4.0"}},
		{text: "1.2.3 - 2", accepts: []string{"2.9.9"}, rejects: []string{"3.0.0"}},

		// Alternatives.
		{text: "^1 || ^3", accepts: []string{"1.5.0", "3.1.0"}, rejects: []string{"2.0.0", "4.0.0"}},
		{text: "1.2.3 || >=5", accepts: []string{"1.2.3", "5.0.0"}, rejects: []string{"1.2.4"}},

		// Prereleases: only a range that names one accepts one, and only of the
		// version it names.
		{text: "^1.0.0", rejects: []string{"1.5.0-rc.1", "2.0.0-rc.1"}},
		{
			text: ">=1.0.0-rc.1 <2.0.0", accepts: []string{"1.0.0-rc.1", "1.0.0-rc.2", "1.0.0", "1.9.9"},
			rejects: []string{"1.5.0-beta.1", "1.0.0-beta.9"}, prelease: true,
		},
		{
			text: "^1.2.3-alpha.1", accepts: []string{"1.2.3-alpha.2", "1.2.3-beta", "1.2.3", "1.9.0"},
			rejects: []string{"1.2.3-alpha.0", "1.3.0-alpha.1"}, prelease: true,
		},
	}
	for _, tt := range tests {
		t.Run(displayRange(tt.text), func(t *testing.T) { assertRange(t, SyntaxNPM, &tt) })
	}
}

func TestCargoRequirementMatching(t *testing.T) {
	tests := []rangeCase{
		// A bare requirement is a caret, which is the one thing Cargo spells
		// differently from npm.
		{text: "1.2.3", accepts: []string{"1.2.3", "1.9.0"}, rejects: []string{"1.2.2", "2.0.0"}},
		{text: "1.2", accepts: []string{"1.2.0", "1.9.9"}, rejects: []string{"1.1.9", "2.0.0"}},
		{text: "1", accepts: []string{"1.0.0", "1.9.9"}, rejects: []string{"0.9.9", "2.0.0"}},
		{text: "0.8.5", accepts: []string{"0.8.5", "0.8.9"}, rejects: []string{"0.8.4", "0.9.0"}},
		{text: "0.0.3", accepts: []string{"0.0.3"}, rejects: []string{"0.0.4"}},

		// The operators Cargo writes.
		{text: "^1.2.3", accepts: []string{"1.9.9"}, rejects: []string{"2.0.0"}},
		{text: "^0.2.3", accepts: []string{"0.2.9"}, rejects: []string{"0.3.0"}},
		{text: "^0.0", accepts: []string{"0.0.9"}, rejects: []string{"0.1.0"}},
		{text: "^0", accepts: []string{"0.9.9"}, rejects: []string{"1.0.0"}},
		{text: "~1.2.3", accepts: []string{"1.2.9"}, rejects: []string{"1.3.0"}},
		{text: "~1.2", accepts: []string{"1.2.9"}, rejects: []string{"1.3.0"}},
		{text: "~1", accepts: []string{"1.9.9"}, rejects: []string{"2.0.0"}},
		{text: "=1.2.3", accepts: []string{"1.2.3"}, rejects: []string{"1.2.4"}},
		{text: "=1.2", accepts: []string{"1.2.0", "1.2.9"}, rejects: []string{"1.3.0"}},
		{text: ">1.2", accepts: []string{"1.3.0"}, rejects: []string{"1.2.9"}},
		{text: ">=1.2", accepts: []string{"1.2.0"}, rejects: []string{"1.1.9"}},
		{text: "<1.2", accepts: []string{"1.1.9"}, rejects: []string{"1.2.0"}},
		{text: "<=1.2", accepts: []string{"1.2.9"}, rejects: []string{"1.3.0"}},

		// Wildcards, which are x-ranges rather than carets.
		{text: "*", accepts: []string{"0.0.1", "9.9.9"}, rejects: []string{"1.0.0-rc.1"}},
		{text: "1.*", accepts: []string{"1.0.0", "1.9.9"}, rejects: []string{"2.0.0"}},
		{text: "1.2.*", accepts: []string{"1.2.9"}, rejects: []string{"1.3.0"}},

		// Several comparators, which Cargo separates with commas.
		{text: ">=1.2, <1.5", accepts: []string{"1.2.0", "1.4.9"}, rejects: []string{"1.1.9", "1.5.0"}},
		{text: ">= 1.2.3, < 2.0.0", accepts: []string{"1.2.3"}, rejects: []string{"2.0.0"}},

		// Prereleases, under the same rule as npm's.
		{text: "1.0", rejects: []string{"1.5.0-rc.1"}},
		{text: ">=1.0.0-rc.1, <2.0.0", accepts: []string{"1.0.0-rc.1", "1.0.0"}, rejects: []string{"1.5.0-rc.1"}, prelease: true},
	}
	for _, tt := range tests {
		t.Run(displayRange(tt.text), func(t *testing.T) { assertRange(t, SyntaxCargo, &tt) })
	}
}

func TestPEP440SpecifierMatching(t *testing.T) {
	tests := []rangeCase{
		{text: "", accepts: []string{"1.0", "2.5.1"}, rejects: []string{"1.0rc1", "1.0.dev1"}},
		{text: ">=2.31,<3", accepts: []string{"2.31", "2.31.0", "2.99"}, rejects: []string{"2.30.9", "3.0"}},
		{text: ">= 1.26", accepts: []string{"1.26", "2.0"}, rejects: []string{"1.25.9"}},
		{text: "== 24.1", accepts: []string{"24.1", "24.1.0", "24.1+local"}, rejects: []string{"24.1.1", "24.2"}},
		{text: "==1.4.*", accepts: []string{"1.4", "1.4.0", "1.4.5"}, rejects: []string{"1.40", "1.5", "1.4rc1"}},
		{text: "==1.1.0.*", accepts: []string{"1.1", "1.1.0.2"}, rejects: []string{"1.2"}},
		{text: "!=1.5", accepts: []string{"1.4", "1.6"}, rejects: []string{"1.5", "1.5.0"}},
		{text: "!=1.5.*", accepts: []string{"1.4.9", "1.6"}, rejects: []string{"1.5.1"}},
		{text: "~=7.4", accepts: []string{"7.4", "7.9"}, rejects: []string{"7.3.9", "8.0"}},
		{text: "~=1.4.2", accepts: []string{"1.4.2", "1.4.9"}, rejects: []string{"1.4.1", "1.5.0"}},
		{text: "<=2.0", accepts: []string{"1.9", "2.0", "2.0.0"}, rejects: []string{"2.0.1"}},
		{text: "<2.0", accepts: []string{"1.9"}, rejects: []string{"2.0"}},
		{text: "===1.0.0+ubuntu1", accepts: []string{"1.0.0+ubuntu1"}, rejects: []string{"1.0.0", "1.0"}},

		// The PEP's two exclusion rules for the exclusive comparisons.
		{text: ">1.7", accepts: []string{"1.8", "1.7.1"}, rejects: []string{"1.7", "1.7.post1", "1.7+local"}},
		{text: "<1.7", accepts: []string{"1.6.9"}, rejects: []string{"1.7", "1.7rc1"}},

		// Prereleases are candidates only when the specifier names one.
		{text: ">=1.0", rejects: []string{"2.0rc1", "2.0.dev3"}},
		{text: ">=1.0rc1", accepts: []string{"1.0rc1", "1.0", "2.0rc1"}, rejects: []string{"0.9"}, prelease: true},
		{text: "==2.0.0rc1", accepts: []string{"2.0.0rc1"}, rejects: []string{"2.0.0"}, prelease: true},

		// The epoch, which orders above everything without one.
		{text: ">=1!0", accepts: []string{"1!0.1"}, rejects: []string{"9.9"}},
	}
	for _, tt := range tests {
		t.Run(displayRange(tt.text), func(t *testing.T) { assertRange(t, SyntaxPEP440, &tt) })
	}
}

func TestPoetryConstraintMatching(t *testing.T) {
	tests := []rangeCase{
		{text: "*", accepts: []string{"1.0", "9.9"}, rejects: []string{"1.0rc1"}},
		{text: "^2.31", accepts: []string{"2.31", "2.99"}, rejects: []string{"2.30.9", "3.0"}},
		{text: "^1.2.3", accepts: []string{"1.2.3", "1.9"}, rejects: []string{"1.2.2", "2.0"}},
		{text: "^0.2.3", accepts: []string{"0.2.3", "0.2.9"}, rejects: []string{"0.3.0"}},
		{text: "^0.0.3", accepts: []string{"0.0.3"}, rejects: []string{"0.0.4"}},
		{text: "^0.0", accepts: []string{"0.0.5"}, rejects: []string{"0.1"}},
		{text: "^0", accepts: []string{"0.9"}, rejects: []string{"1.0"}},
		{text: "~8.1", accepts: []string{"8.1", "8.1.9"}, rejects: []string{"8.2", "8.0.9"}},
		{text: "~1", accepts: []string{"1.9"}, rejects: []string{"2.0"}},
		{text: "~1.2.3", accepts: []string{"1.2.9"}, rejects: []string{"1.3"}},
		{text: "1.2.3", accepts: []string{"1.2.3"}, rejects: []string{"1.2.4"}},
		{text: "1.*", accepts: []string{"1.0", "1.9"}, rejects: []string{"2.0"}},
		{text: "1.2.*", accepts: []string{"1.2.9"}, rejects: []string{"1.3"}},
		{text: ">=13,<14", accepts: []string{"13.5"}, rejects: []string{"14.0", "12.9"}},
		{text: "^1.0 || ^3.0", accepts: []string{"1.5", "3.2"}, rejects: []string{"2.0", "4.0"}},
		{text: "^2.0.0rc1", accepts: []string{"2.0.0rc1", "2.5"}, rejects: []string{"3.0"}, prelease: true},
	}
	for _, tt := range tests {
		t.Run(displayRange(tt.text), func(t *testing.T) { assertRange(t, SyntaxPoetry, &tt) })
	}
}

// A range no grammar reads is an error, never a range that quietly accepts nothing
// or everything: the caller turns the error into a skipped declaration carrying the
// text, which is the only honest answer.
func TestParseConstraintRefusesWhatItCannotRead(t *testing.T) {
	tests := []struct {
		name   string
		syntax Syntax
		text   string
	}{
		{name: "an npm dist-tag", syntax: SyntaxNPM, text: "latest"},
		{name: "an npm range of nonsense", syntax: SyntaxNPM, text: "^^1.2.3"},
		{name: "an npm range with four pieces", syntax: SyntaxNPM, text: "1.2.3.4"},
		{name: "an npm hyphen range beside a comparator", syntax: SyntaxNPM, text: ">=1 2.0.0 - 3.0.0"},
		{name: "an npm hyphen range with no high side", syntax: SyntaxNPM, text: "1.0.0 -"},
		{name: "a Cargo requirement that is empty", syntax: SyntaxCargo, text: ""},
		{name: "a Cargo requirement with a trailing comma", syntax: SyntaxCargo, text: ">=1.0,"},
		{name: "npm's tilde arrow in Cargo", syntax: SyntaxCargo, text: "~>1.2"},
		{name: "a Cargo requirement of nonsense", syntax: SyntaxCargo, text: "one point two"},
		{name: "a PEP 440 specifier with no operator", syntax: SyntaxPEP440, text: "1.2.3"},
		{name: "a PEP 440 caret, which is Poetry's and not the PEP's", syntax: SyntaxPEP440, text: "^1.2.3"},
		{name: "a PEP 440 operator with no version", syntax: SyntaxPEP440, text: ">="},
		{name: "a PEP 440 wildcard on an ordered comparison", syntax: SyntaxPEP440, text: ">=1.4.*"},
		{name: "a PEP 440 prefix match on a prerelease", syntax: SyntaxPEP440, text: "==1.4rc1.*"},
		{name: "a compatible release naming one segment", syntax: SyntaxPEP440, text: "~=1"},
		{name: "a version PEP 440 does not accept", syntax: SyntaxPEP440, text: ">=not.a.version"},
		{name: "a Poetry constraint of nonsense", syntax: SyntaxPoetry, text: "the newest one"},
		{name: "an unknown grammar", syntax: Syntax("elvish"), text: "1.2.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseConstraint(tt.syntax, tt.text); err == nil {
				t.Fatalf("parseConstraint(%s, %q) succeeded, want an error", tt.syntax, tt.text)
			}
		})
	}
}

// A version the ecosystem's own scheme cannot parse satisfies nothing: a version
// nobody can order is not one to resolve a project's dependency to.
func TestConstraintRejectsUnparsableVersions(t *testing.T) {
	tests := []struct {
		syntax  Syntax
		text    string
		version string
	}{
		{syntax: SyntaxNPM, text: "*", version: "not-a-version"},
		{syntax: SyntaxCargo, text: "*", version: "1.2"},
		{syntax: SyntaxPEP440, text: "", version: "not-a-version"},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			c, err := parseConstraint(tt.syntax, tt.text)
			if err != nil {
				t.Fatal(err)
			}
			if c.allows(tt.version) {
				t.Fatalf("%s range %q accepts %q", tt.syntax, tt.text, tt.version)
			}
		})
	}
}

// displayRange names a subtest after the range it exercises, with the empty range
// given a name of its own so the output stays readable.
func displayRange(text string) string {
	if strings.TrimSpace(text) == "" {
		return "the empty range"
	}
	return text
}
