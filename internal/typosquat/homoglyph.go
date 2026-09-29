package typosquat

import (
	"strings"
	"unicode/utf8"
)

// HomoglyphSkeleton applies the checked-in ASCII subset of Unicode confusables
// to a canonical name. changed is true only when a non-ASCII rune was mapped;
// ASCII-only similarities remain the existing rules' responsibility. Unmapped
// runes are preserved, never transliterated or stripped. This is a bounded
// package-name heuristic, not full UTS #39 normalization or script detection.
func HomoglyphSkeleton(name string) (skeleton string, changed bool) {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if replacement := homoglyphMapping(r); replacement != "" {
			b.WriteString(replacement)
			changed = changed || r >= utf8.RuneSelf
		} else {
			b.WriteRune(r)
		}
	}
	return b.String(), changed
}

func asciiName(name string) bool {
	for _, r := range name {
		if r >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
