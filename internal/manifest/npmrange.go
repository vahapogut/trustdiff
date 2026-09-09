package manifest

import (
	"fmt"
	"slices"
	"strings"
)

// parseNPMRange parses a node-semver range set: ranges joined by "||", any one of
// which may hold, each of them comparators joined by whitespace, all of which must.
// The package comment states the whole grammar and what was left out of it.
func parseNPMRange(text string) (semverRange, error) {
	parts := strings.Split(text, "||")
	out := make(semverRange, 0, len(parts))
	for _, part := range parts {
		set, err := parseNPMComparatorSet(part)
		if err != nil {
			return nil, err
		}
		out = append(out, set)
	}
	return out, nil
}

// parseNPMComparatorSet parses one range of a range set.
func parseNPMComparatorSet(text string) (comparatorSet, error) {
	tokens := rangeTokens(text)
	if len(tokens) == 0 {
		// An empty range is every version, which is what npm reads "" and "*" as.
		return anySet(), nil
	}
	if hyphen := slices.Index(tokens, "-"); hyphen >= 0 {
		// A hyphen range is the whole range, not one comparator among others, so
		// anything else beside it is a range node-semver rejects too.
		if len(tokens) != 3 || hyphen != 1 {
			return nil, fmt.Errorf("not a version range this reader parses: a hyphen range must be the whole of %q", strings.TrimSpace(text))
		}
		return hyphenComparators(tokens[0], tokens[2])
	}
	set := make(comparatorSet, 0, len(tokens))
	for _, token := range tokens {
		comparators, err := npmComparators(token)
		if err != nil {
			return nil, err
		}
		set = append(set, comparators...)
	}
	return set, nil
}

// npmComparators turns one token of a range into the comparators it stands for.
func npmComparators(token string) (comparatorSet, error) {
	rest, prefix := cutRangePrefix(token)
	p, ok := parsePartial(rest)
	if !ok {
		return nil, fmt.Errorf("not a version range this reader parses: %q", token)
	}
	switch prefix {
	case "^":
		return caretComparators(p), nil
	case "~", "~>":
		return tildeComparators(p), nil
	case "":
		return xrangeComparators(p), nil
	default:
		return primitiveComparators(prefix, p), nil
	}
}

// hyphenComparators expands "low - high": at least the low side, at most the high
// one. A piece the low side leaves out reads as zero, and a piece the high side
// leaves out widens the bound, so "1.2.3 - 2.3" accepts every 2.3.x.
func hyphenComparators(lowText, highText string) (comparatorSet, error) {
	low, lowOK := parsePartial(lowText)
	high, highOK := parsePartial(highText)
	if !lowOK || !highOK {
		return nil, fmt.Errorf("not a version range this reader parses: %q - %q", lowText, highText)
	}
	var set comparatorSet
	if low.major != wildcard {
		set = append(set, comparator{op: opGTE, ver: low.version()})
	}
	switch {
	case high.major == wildcard:
		// No upper bound at all: "1.2.3 - *" is everything from 1.2.3 on.
	case high.minor == wildcard:
		set = append(set, comparator{op: opLT, ver: at(high.major+1, 0, 0)})
	case high.patch == wildcard:
		set = append(set, comparator{op: opLT, ver: at(high.major, high.minor+1, 0)})
	default:
		set = append(set, comparator{op: opLTE, ver: high.version()})
	}
	return set, nil
}

// rangeTokens splits a range into its comparators, gluing an operator back onto the
// version it applies to. npm allows the space that a person writing ">= 1.2.3"
// leaves there, and a range is otherwise separated by whitespace, so the two have to
// be told apart while reading rather than by splitting on spaces first.
func rangeTokens(text string) []string {
	var tokens []string
	for i := 0; i < len(text); {
		if isSpace(text[i]) {
			i++
			continue
		}
		start := i
		var token string
		if op := leadingOperator(text[i:]); op != "" {
			i += len(op)
			for i < len(text) && isSpace(text[i]) {
				i++
			}
			start, token = i, op
		}
		for i < len(text) && !isSpace(text[i]) {
			i++
		}
		tokens = append(tokens, token+text[start:i])
	}
	return tokens
}

// rangePrefixes are the operators a comparator can begin with, longest first so
// that ">=" is never read as ">".
var rangePrefixes = []string{">=", "<=", "~>", "^", "~", ">", "<", "="}

// leadingOperator returns the operator s begins with, or an empty string.
func leadingOperator(s string) string {
	for _, op := range rangePrefixes {
		if strings.HasPrefix(s, op) {
			return op
		}
	}
	return ""
}

// cutRangePrefix separates a comparator's operator from the version it applies to.
func cutRangePrefix(token string) (rest, prefix string) {
	prefix = leadingOperator(token)
	return token[len(prefix):], prefix
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }
