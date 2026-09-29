package typosquat

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/vahapogut/trustdiff/internal/model"
)

func TestHomoglyphMatches(t *testing.T) {
	tests := []struct{ name, popular, skeleton string }{
		{"\u0441halk", "chalk", "chalk"},
		{"r\u0435\u0430\u0441t", "react", "react"},
		{"@typ\u0435s/node", "@types/node", "@types/node"},
		{"@types/n\u043ede", "@types/node", "@types/node"},
		{"\u0441\u043e\u0441\u043e", "coco", "coco"},
		{"\u03c1andas", "pandas", "pandas"},
		{"\U0001D41C\U0001D421\U0001D41A\U0001D425\U0001D424", "chalk", "chalk"},
		{"\u04cf\u043edash", "lodash", "lodash"},
		{"f\u043erm", "form", "forrn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Suspect(model.NPM, tt.name, NewSet(model.NPM, []string{tt.popular}))
			if !ok || got.Rule != RuleHomoglyph || got.Neighbor != tt.popular || got.Skeleton != tt.skeleton {
				t.Fatalf("Suspect(%q) = %+v, %v", tt.name, got, ok)
			}
		})
	}
}

func TestHomoglyphDoesNotTransliterateOrFlagScripts(t *testing.T) {
	set := NewSet(model.NPM, []string{"chalk", "requests", "react", "server", "lodash"})
	for _, name := range []string{"\u0441\u0435\u0440\u0432\u0435\u0440", "\u65e5\u672c\u8a9e", "\u03c0\u03b1\u03ba\u03ad\u03c4\u03bf", "my-\u65e5\u672c\u8a9e", "\u0438nternational", "\u0441halk-extra"} {
		if got, ok := Suspect(model.NPM, name, set); ok {
			t.Errorf("legitimate/unrelated %q matched %+v", name, got)
		}
	}
	// A Unicode name that is itself popular is exempt just like any ASCII name.
	if got, ok := Suspect(model.NPM, "\u0441halk", NewSet(model.NPM, []string{"chalk", "\u0441halk"})); ok {
		t.Fatalf("popular name matched %+v", got)
	}
	for _, name := range []string{"chalk", "react", "1odash", "rnodule"} {
		_, changed := HomoglyphSkeleton(name)
		if changed {
			t.Errorf("ASCII name %q claimed a Unicode substitution", name)
		}
	}
}

// Every retained scalar that survives Canonical must match when substituted into
// a target name. This also covers multi-letter mappings beyond fuzzy thresholds,
// and checks that the generated table has no non-idempotent target chains.
func TestHomoglyphGeneratedMappingProperties(t *testing.T) {
	count := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		replacement := homoglyphMapping(r)
		if replacement == "" {
			continue
		}
		count++
		for _, ascii := range replacement {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789._-", ascii) {
				t.Fatalf("U+%04X has unsupported target %q", r, replacement)
			}
		}
		once, _ := HomoglyphSkeleton(string(r))
		twice, _ := HomoglyphSkeleton(once)
		if once != twice {
			t.Fatalf("U+%04X skeleton is not idempotent: %q then %q", r, once, twice)
		}
		if r < utf8.RuneSelf || unicode.ToLower(r) != r {
			continue
		}
		candidate, neighbor := "fixture-"+string(r)+"-package", "fixture-"+replacement+"-package"
		got, ok := Suspect(model.NPM, candidate, NewSet(model.NPM, []string{neighbor}))
		if !ok || got.Rule != RuleHomoglyph || got.Neighbor != neighbor {
			t.Fatalf("U+%04X: got %+v, %v", r, got, ok)
		}
	}
	if count != 1862 {
		t.Fatalf("mapping count = %d, want 1862; inspect the Unicode update", count)
	}
}

func FuzzHomoglyphSkeleton(f *testing.F) {
	for _, name := range []string{"\u0441halk", "@typ\u0435s/node", "\u65e5\u672c\u8a9e", "\xff", "m\u03c1"} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, input string) {
		first, _ := HomoglyphSkeleton(input)
		second, _ := HomoglyphSkeleton(first)
		if first != second {
			t.Fatalf("non-idempotent skeleton %q => %q => %q", input, first, second)
		}
	})
}
