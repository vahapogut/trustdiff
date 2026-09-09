package manifest

import (
	"fmt"
	"strings"
)

// parseCargoRequirement parses one of Cargo's version requirements: comparators
// separated by commas, all of which must hold. There is no "or" in the grammar, so
// the result is always exactly one comparator set.
//
// What separates it from npm's grammar is what a version with no operator in front
// of it means. Cargo assumes a caret, so "1.2.3" is "^1.2.3" and "1.2" is "^1.2",
// while an explicit wildcard stays an x-range, so "1.2.*" is >=1.2.0 <1.3.0. Once
// the operator is known the comparator means the same as it does in npm, which is
// why the expansions are shared: Cargo's rules for ">1.2", "<=1.2" and "=1.2" agree
// with node-semver's rewriting piece for piece.
func parseCargoRequirement(text string) (semverRange, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, fmt.Errorf("not a version requirement this reader parses: %q", text)
	}
	parts := strings.Split(trimmed, ",")
	set := make(comparatorSet, 0, len(parts))
	for _, part := range parts {
		comparators, err := cargoComparators(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		set = append(set, comparators...)
	}
	return semverRange{set}, nil
}

// cargoComparators turns one comparator of a requirement into the bounds it stands
// for.
func cargoComparators(token string) (comparatorSet, error) {
	rest, prefix := cutRangePrefix(token)
	rest = strings.TrimSpace(rest)
	p, ok := parsePartial(rest)
	// An operator with nothing after it names no version, and neither does an
	// empty comparator, which is what a trailing comma leaves behind.
	if !ok || rest == "" {
		return nil, fmt.Errorf("not a version requirement this reader parses: %q", token)
	}
	switch prefix {
	case "^":
		return caretComparators(p), nil
	case "~":
		return tildeComparators(p), nil
	case "=":
		// "=1.2.3" is that version and "=1.2" is every 1.2.x, which is the
		// x-range expansion.
		return xrangeComparators(p), nil
	case ">", ">=", "<", "<=":
		return primitiveComparators(prefix, p), nil
	case "":
		if p.explicit {
			// A wildcard written out: "*", "1.*", "1.2.*".
			return xrangeComparators(p), nil
		}
		// A bare version, which Cargo reads as a caret requirement.
		return caretComparators(p), nil
	default:
		// "~>" is npm's spelling of a tilde and not one Cargo accepts.
		return nil, fmt.Errorf("not a version requirement this reader parses: %q", token)
	}
}
