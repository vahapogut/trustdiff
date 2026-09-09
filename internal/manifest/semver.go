package manifest

import (
	"strconv"
	"strings"
)

// This file is the semantic version arithmetic npm's and Cargo's range grammars are
// both built on: a parsed version, a comparator, and the expansions that turn a
// caret, a tilde or a version with pieces left out into comparators. The two
// grammars differ in how they are spelled and in what a bare version means, which
// npmrange.go and cargoreq.go handle; what a comparator then means is the same in
// both, so it lives once here.
//
// golang.org/x/mod/semver could compare two complete versions, but a range is built
// from partial ones ("^1.2", ">=0.7.x") that it rejects outright, and the caret and
// tilde expansions are the whole of the problem, so the comparison is done here
// against the same parsed form the expansions produce.

// semverVersion is a semantic version as npm and Cargo compare them. Build metadata
// is dropped while parsing: the specification says it takes no part in comparison,
// and both ecosystems follow it.
type semverVersion struct {
	major, minor, patch int64
	// pre holds the dot separated prerelease identifiers, nil when the version has
	// none. It is what makes 1.0.0-rc.1 sort below 1.0.0.
	pre []string
}

// parseSemver parses a complete version, "1.2.3" or "1.2.3-rc.1+build". A leading
// "v" and a leading "=" are accepted because both appear in manifests written by
// hand, and npm accepts them too.
func parseSemver(s string) (semverVersion, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre string
	var hasPre bool
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s, pre, hasPre = s[:i], s[i+1:], true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semverVersion{}, false
	}
	var v semverVersion
	numbers := [3]*int64{&v.major, &v.minor, &v.patch}
	for i, part := range parts {
		n, ok := parseNumber(part)
		if !ok {
			return semverVersion{}, false
		}
		*numbers[i] = n
	}
	if hasPre {
		v.pre = strings.Split(pre, ".")
		for _, id := range v.pre {
			if id == "" {
				return semverVersion{}, false
			}
		}
	}
	return v, true
}

// compareSemver orders two versions: -1, 0 or +1. It is the specification's
// ordering, so a version with a prerelease sorts below the same version without
// one, and prerelease identifiers compare numerically when both are numbers and as
// text otherwise.
func compareSemver(a, b semverVersion) int {
	if c := compareInt64(a.major, b.major); c != 0 {
		return c
	}
	if c := compareInt64(a.minor, b.minor); c != 0 {
		return c
	}
	if c := compareInt64(a.patch, b.patch); c != 0 {
		return c
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	return comparePrerelease(a.pre, b.pre)
}

// comparePrerelease orders two prerelease identifier lists. A longer list wins when
// the shorter one is its prefix, which is what makes 1.0.0-rc.1 sort below
// 1.0.0-rc.1.1.
func comparePrerelease(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		na, aNumeric := identifierNumber(a[i])
		nb, bNumeric := identifierNumber(b[i])
		switch {
		case aNumeric && bNumeric:
			if c := compareUint(na, nb); c != 0 {
				return c
			}
		case aNumeric:
			// A numeric identifier always has lower precedence than a text one.
			return -1
		case bNumeric:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return compareInt(len(a), len(b))
}

// identifierNumber reads a prerelease identifier as a number, reporting false when
// it is text.
func identifierNumber(id string) (uint64, bool) {
	n, err := strconv.ParseUint(id, 10, 64)
	return n, err == nil
}

func compareUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// semverOp is a comparator's operator.
type semverOp uint8

// The operators a comparator can carry. Every spelling a range grammar allows is
// expanded into these before anything is compared.
const (
	opEQ semverOp = iota
	opGT
	opGTE
	opLT
	opLTE
)

// comparator is one bound on a version.
type comparator struct {
	op  semverOp
	ver semverVersion
}

// test reports whether v satisfies the comparator, on the numbers alone. The
// prerelease rule that decides whether a prerelease may satisfy the set at all is
// comparatorSet.allows, because it is a property of the whole set.
func (c comparator) test(v semverVersion) bool {
	cmp := compareSemver(v, c.ver)
	switch c.op {
	case opEQ:
		return cmp == 0
	case opGT:
		return cmp > 0
	case opGTE:
		return cmp >= 0
	case opLT:
		return cmp < 0
	default:
		return cmp <= 0
	}
}

// comparatorSet is comparators that must all hold. An empty set is "any version",
// which is what an empty npm range and a bare "*" mean.
type comparatorSet []comparator

// allows reports whether the version satisfies every comparator of the set.
//
// The prerelease rule is node-semver's, and Cargo's is the same: a version carrying
// a prerelease satisfies the set only when some comparator of the set names a
// prerelease of the same major.minor.patch. It is why "^1.0.0" never accepts
// "2.0.0-rc.1" and why ">=1.0.0-rc.1 <2.0.0" accepts "1.0.0-rc.2" but not
// "1.5.0-beta". Without it a caret range would start installing other packages'
// release candidates the moment one appeared.
func (s comparatorSet) allows(v semverVersion) bool {
	for _, c := range s {
		if !c.test(v) {
			return false
		}
	}
	if len(v.pre) == 0 {
		return true
	}
	for _, c := range s {
		if len(c.ver.pre) > 0 && c.ver.major == v.major && c.ver.minor == v.minor && c.ver.patch == v.patch {
			return true
		}
	}
	return false
}

// semverRange is comparator sets joined by "or": a version satisfies the range when
// it satisfies any one of them. npm spells the join "||"; Cargo has no join and
// always produces exactly one set.
type semverRange []comparatorSet

// allows reports whether the published version satisfies the range. A version the
// ecosystem's own scheme cannot parse satisfies nothing: a registry that lists a
// version nobody can order is not one this can pick a highest from.
func (r semverRange) allows(raw string) bool {
	v, ok := parseSemver(raw)
	if !ok {
		return false
	}
	for _, set := range r {
		if set.allows(v) {
			return true
		}
	}
	return false
}

// namesPrerelease reports whether the range itself names a prerelease anywhere,
// which is what lets a prerelease be resolved at all.
func (r semverRange) namesPrerelease() bool {
	for _, set := range r {
		for _, c := range set {
			if len(c.ver.pre) > 0 {
				return true
			}
		}
	}
	return false
}

// wildcard marks a piece of a partial version that was left out or written as an x.
const wildcard = int64(-1)

// partial is a version with pieces left out or written as an "x", "X" or "*", which
// is what every range grammar here is built from. A piece that is missing and a
// piece written as an x mean the same thing to both grammars, so both are wildcard.
type partial struct {
	major, minor, patch int64
	// pre is the prerelease the partial carries, nil when it has none.
	pre []string
	// explicit is true when a wildcard was written rather than left out, which is
	// the one difference Cargo makes: "1.2" is a caret requirement and "1.2.*" is
	// an x-range.
	explicit bool
}

// parsePartial reads a version with pieces left out. Once a piece is a wildcard the
// pieces after it are wildcards too, whatever they say, which is node-semver's rule
// and keeps "1.x.3" from meaning anything surprising.
func parsePartial(s string) (partial, bool) {
	p := partial{major: wildcard, minor: wildcard, patch: wildcard}
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		p.explicit = true
		return p, true
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre string
	var hasPre bool
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s, pre, hasPre = s[:i], s[i+1:], true
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return partial{}, false
	}
	numbers := [3]*int64{&p.major, &p.minor, &p.patch}
	for i, part := range parts {
		if isWildcardPiece(part) {
			p.explicit = true
			break
		}
		n, ok := parseNumber(part)
		if !ok {
			return partial{}, false
		}
		*numbers[i] = n
	}
	if hasPre {
		if p.patch == wildcard {
			// A prerelease belongs to one exact version, so "1.2.x-rc.1" names
			// nothing this can expand.
			return partial{}, false
		}
		p.pre = strings.Split(pre, ".")
		for _, id := range p.pre {
			if id == "" {
				return partial{}, false
			}
		}
	}
	return p, true
}

// isWildcardPiece reports whether a piece of a partial version is a wildcard.
func isWildcardPiece(part string) bool {
	return part == "" || part == "x" || part == "X" || part == "*"
}

// parseNumber reads one piece of a version. Only digits are accepted, so a sign or
// a stray character is not read as a number the way strconv alone would read "+1".
func parseNumber(part string) (int64, bool) {
	if part == "" {
		return 0, false
	}
	for i := 0; i < len(part); i++ {
		if part[i] < '0' || part[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(part, 10, 64)
	return n, err == nil
}

// complete reports whether every piece of the partial is a number, which is the one
// case that can name a single version.
func (p partial) complete() bool {
	return p.major != wildcard && p.minor != wildcard && p.patch != wildcard
}

// version builds the version the partial names, reading a wildcard piece as zero.
// It is the low bound of every expansion below.
func (p partial) version() semverVersion {
	return semverVersion{
		major: zeroed(p.major),
		minor: zeroed(p.minor),
		patch: zeroed(p.patch),
		pre:   p.pre,
	}
}

// zeroed reads a wildcard piece as zero.
func zeroed(n int64) int64 {
	if n == wildcard {
		return 0
	}
	return n
}

// at builds a version from three numbers, for the upper bounds the expansions
// compute.
func at(major, minor, patch int64) semverVersion {
	return semverVersion{major: major, minor: minor, patch: patch}
}

// nothing is a comparator set no version satisfies. It is what ">x" and "<x" mean:
// no version is greater than every version, and none is less than every version.
// "<0.0.0" says it without naming a prerelease of its own, which matters because a
// range that names one accepts prereleases and this range accepts nothing at all: a
// prerelease below 0.0.0 fails the set's prerelease rule instead.
func nothing() comparatorSet {
	return comparatorSet{{op: opLT, ver: semverVersion{}}}
}

// anySet is the empty set, which every release satisfies and no prerelease does.
func anySet() comparatorSet { return comparatorSet{} }

// caretComparators expands "^p": hold the leftmost non-zero piece and allow
// everything above it. It is the same rule in npm and in Cargo, and the zero major
// and zero minor cases are the point of it: before 1.0.0 a minor release is allowed
// to break, so ^0.2.3 stops at 0.3.0 and ^0.0.3 stops at 0.0.4.
func caretComparators(p partial) comparatorSet {
	switch {
	case p.major == wildcard:
		return anySet()
	case p.minor == wildcard:
		return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(p.major+1, 0, 0)}}
	case p.patch == wildcard:
		if p.major == 0 {
			return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(0, p.minor+1, 0)}}
		}
		return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(p.major+1, 0, 0)}}
	case p.major == 0 && p.minor == 0:
		return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(0, 0, p.patch+1)}}
	case p.major == 0:
		return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(0, p.minor+1, 0)}}
	default:
		return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(p.major+1, 0, 0)}}
	}
}

// tildeComparators expands "~p": hold the minor when the text names one, the major
// when it does not.
func tildeComparators(p partial) comparatorSet {
	switch {
	case p.major == wildcard:
		return anySet()
	case p.minor == wildcard:
		return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(p.major+1, 0, 0)}}
	default:
		return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(p.major, p.minor+1, 0)}}
	}
}

// xrangeComparators expands a partial written without an operator: the pieces it
// names are held and the pieces it leaves out are free. A partial that names every
// piece is one exact version.
func xrangeComparators(p partial) comparatorSet {
	switch {
	case p.major == wildcard:
		return anySet()
	case p.minor == wildcard:
		return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(p.major+1, 0, 0)}}
	case p.patch == wildcard:
		return comparatorSet{{op: opGTE, ver: p.version()}, {op: opLT, ver: at(p.major, p.minor+1, 0)}}
	default:
		return comparatorSet{{op: opEQ, ver: p.version()}}
	}
}

// primitiveComparators expands an ordered comparison over a partial version. A
// partial widens the bound to the whole of what it names, which is node-semver's
// rewriting and Cargo's comparator semantics alike: ">1.2" is ">=1.3.0" because
// every 1.2.x is not greater than 1.2, and "<=0.7.x" is "<0.8.0" because every
// 0.7.x should pass.
func primitiveComparators(op string, p partial) comparatorSet {
	if p.major == wildcard {
		// Nothing is greater or less than every version; everything is at least,
		// at most or equal to some version.
		if op == ">" || op == "<" {
			return nothing()
		}
		return anySet()
	}
	if p.complete() {
		return comparatorSet{{op: semverOpOf(op), ver: p.version()}}
	}
	// One piece is missing, so the bound moves to the edge of the range the text
	// names. The pieces below the named one read as zero.
	minor, next := p.minor, at(p.major+1, 0, 0)
	if minor == wildcard {
		minor = 0
	} else {
		next = at(p.major, p.minor+1, 0)
	}
	low := at(p.major, minor, 0)
	switch op {
	case ">":
		return comparatorSet{{op: opGTE, ver: next}}
	case ">=":
		return comparatorSet{{op: opGTE, ver: low}}
	case "<":
		return comparatorSet{{op: opLT, ver: low}}
	case "<=":
		return comparatorSet{{op: opLT, ver: next}}
	default:
		// "=1.2" names every 1.2.x, which is the x-range it is written as.
		return xrangeComparators(p)
	}
}

// semverOpOf maps a spelled operator onto the comparator's own.
func semverOpOf(op string) semverOp {
	switch op {
	case ">":
		return opGT
	case ">=":
		return opGTE
	case "<":
		return opLT
	case "<=":
		return opLTE
	default:
		return opEQ
	}
}
