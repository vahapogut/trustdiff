package version

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// pep440Pattern is the canonical PEP 440 regular expression from appendix B of the
// PEP, as maintained by the packaging project. Verified 2026-09-09 against
// https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions
// and https://github.com/pypa/packaging/blob/main/src/packaging/version.py.
//
// The pattern uses no lookaround, so it is valid RE2 as written. Two differences
// from the reference are deliberate: the possessive quantifiers packaging adds on
// CPython 3.11 only prune backtracking and RE2 has none, and the reference compiles
// with re.IGNORECASE under re.ASCII, which is reproduced here by lowering ASCII
// letters before matching a case-sensitive pattern (Go's (?i) would also fold
// non-ASCII letters such as the long s into "post").
const pep440Pattern = `^v?` +
	`(?:` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`)` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`

var pep440Regexp = regexp.MustCompile(pep440Pattern)

// preSpellings maps every accepted pre-release label to its normal form. The
// alternate spellings and their targets are the PEP's "Pre-release spelling"
// rule (verified 2026-09-09): alpha is a, beta is b, and c, pre and preview are rc.
var preSpellings = map[string]string{
	"a":       "a",
	"alpha":   "a",
	"b":       "b",
	"beta":    "b",
	"rc":      "rc",
	"c":       "rc",
	"pre":     "rc",
	"preview": "rc",
}

// preRanks orders the pre-release kinds among themselves.
var preRanks = map[string]int{"a": 0, "b": 1, "rc": 2}

// Ranks for versions without a pre-release segment. A version whose only suffix
// is a dev release sorts before every alpha (1.0.dev0 < 1.0a1); any other version
// without a pre-release sorts after every release candidate (1.0rc1 < 1.0 and
// 1.0rc1 < 1.0.post1). Mirrors the packaging comparison key, verified 2026-09-09.
const (
	preRankDevOnly = -1
	preRankFinal   = 3
)

// pep440 is a parsed PEP 440 version. Numbers are kept as digit strings with
// leading zeros removed rather than as machine integers, so components of any
// length (date stamps, hashes spelled in digits) normalize and compare correctly.
type pep440 struct {
	epoch   string   // "0" when absent
	release []string // at least one component
	preKind string   // "" when absent, otherwise a, b or rc
	preNum  string   // "" when absent
	post    optNumber
	dev     optNumber
	local   []localSegment
}

// optNumber is a numeric suffix that may be absent.
type optNumber struct {
	set    bool
	digits string
}

// localSegment is one dot-separated part of a local version label. Numeric
// segments hold normalized digits; the others hold lowercase text.
type localSegment struct {
	text    string
	numeric bool
}

// parsePEP440 is the PyPI scheme (PEP 440). Canonical is the PEP's normalized
// spelling, which the reference implementation produces as str(Version(raw)).
func parsePEP440(raw string) (parsed, error) {
	p, err := parsePEP440Parts(raw)
	if err != nil {
		return parsed{}, err
	}
	v := Version{
		Ecosystem:  model.PyPI,
		Raw:        raw,
		Canonical:  p.String(),
		Prerelease: p.isPrerelease(),
	}
	return parsed{v: v, pep: p}, nil
}

// parsePEP440Parts splits raw into its segments. Leading and trailing whitespace
// and a leading v are ignored and letters are read case-insensitively, as the
// PEP's normalization rules require (verified 2026-09-09).
func parsePEP440Parts(raw string) (*pep440, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("%w: empty version", ErrInvalid)
	}
	m := pep440Regexp.FindStringSubmatch(asciiLower(s))
	if m == nil {
		return nil, fmt.Errorf("%w: %q is not a PEP 440 version", ErrInvalid, raw)
	}
	group := func(name string) string { return m[pep440Regexp.SubexpIndex(name)] }

	p := &pep440{epoch: numberOrZero(group("epoch"))}

	parts := strings.Split(group("release"), ".")
	p.release = make([]string, len(parts))
	for i, part := range parts {
		p.release[i] = normalizeDigits(part)
	}

	// Implicit pre-release number: "1.0a" is "1.0a0".
	if label := group("pre_l"); label != "" {
		p.preKind = preSpellings[label]
		p.preNum = numberOrZero(group("pre_n"))
	}

	// Implicit post releases: "1.0-1" is "1.0.post1". A spelled label defaults
	// its missing number to zero, so "1.0.post" is "1.0.post0".
	switch {
	case group("post_n1") != "":
		p.post = optNumber{set: true, digits: normalizeDigits(group("post_n1"))}
	case group("post_l") != "":
		p.post = optNumber{set: true, digits: numberOrZero(group("post_n2"))}
	}

	if group("dev_l") != "" {
		p.dev = optNumber{set: true, digits: numberOrZero(group("dev_n"))}
	}

	// Local segments accept ".", "-" and "_" as separators; the normal form uses
	// "." and, as the reference does, drops leading zeros from numeric segments.
	if local := group("local"); local != "" {
		segments := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
		p.local = make([]localSegment, len(segments))
		for i, seg := range segments {
			if isDigits(seg) {
				p.local[i] = localSegment{text: normalizeDigits(seg), numeric: true}
			} else {
				p.local[i] = localSegment{text: seg}
			}
		}
	}
	return p, nil
}

// String returns the PEP 440 normal form: [N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local].
func (p *pep440) String() string {
	var b strings.Builder
	if p.epoch != "0" {
		b.WriteString(p.epoch)
		b.WriteByte('!')
	}
	b.WriteString(strings.Join(p.release, "."))
	if p.preKind != "" {
		b.WriteString(p.preKind)
		b.WriteString(p.preNum)
	}
	if p.post.set {
		b.WriteString(".post")
		b.WriteString(p.post.digits)
	}
	if p.dev.set {
		b.WriteString(".dev")
		b.WriteString(p.dev.digits)
	}
	if len(p.local) > 0 {
		b.WriteByte('+')
		for i, seg := range p.local {
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(seg.text)
		}
	}
	return b.String()
}

// isPrerelease reports whether the version carries a pre-release or a dev
// segment. A post release without either is a final release.
func (p *pep440) isPrerelease() bool {
	return p.preKind != "" || p.dev.set
}

// preRank places the version among alphas, betas and release candidates.
func (p *pep440) preRank() int {
	if p.preKind != "" {
		return preRanks[p.preKind]
	}
	if p.dev.set && !p.post.set {
		return preRankDevOnly
	}
	return preRankFinal
}

// comparePEP440Parts orders two parsed versions the way the PEP's "Summary of
// permitted suffixes and relative ordering" section and the packaging comparison
// key do (verified 2026-09-09): epoch, then the release segment with trailing zero
// components ignored, then the pre, post and dev suffixes, then the local label.
func comparePEP440Parts(a, b *pep440) int {
	if c := compareDigits(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := compareRelease(a.release, b.release); c != 0 {
		return c
	}
	if c := compareInts(a.preRank(), b.preRank()); c != 0 {
		return c
	}
	if c := compareDigits(numberOrZero(a.preNum), numberOrZero(b.preNum)); c != 0 {
		return c
	}
	// A version without a post release sorts before one with it.
	if c := compareOptNumber(a.post, b.post, false); c != 0 {
		return c
	}
	// A version with a dev release sorts before one without it.
	if c := compareOptNumber(a.dev, b.dev, true); c != 0 {
		return c
	}
	return compareLocal(a.local, b.local)
}

// comparePEP440 orders two canonical PEP 440 spellings. Canonical strings always
// re-parse, so the byte comparison fallback is unreachable in practice and only
// keeps Compare total if a caller passes something that never went through Parse.
func comparePEP440(a, b string) int {
	pa, errA := parsePEP440Parts(a)
	pb, errB := parsePEP440Parts(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	return comparePEP440Parts(pa, pb)
}

// compareRelease compares release segments after dropping trailing zero
// components, so that 1.0 == 1.0.0; a shorter prefix sorts lower otherwise.
func compareRelease(a, b []string) int {
	a, b = trimZeros(a), trimZeros(b)
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareDigits(a[i], b[i]); c != 0 {
			return c
		}
	}
	return compareInts(len(a), len(b))
}

func trimZeros(parts []string) []string {
	n := len(parts)
	for n > 0 && parts[n-1] == "0" {
		n--
	}
	return parts[:n]
}

// compareOptNumber orders an optional numeric suffix. presentFirst says whether a
// version carrying the suffix sorts before one without it (true for dev, false
// for post).
func compareOptNumber(a, b optNumber, presentFirst bool) int {
	if a.set != b.set {
		c := -1
		if a.set {
			c = 1
		}
		if presentFirst {
			c = -c
		}
		return c
	}
	if !a.set {
		return 0
	}
	return compareDigits(a.digits, b.digits)
}

// compareLocal implements the PEP's local label ordering (verified 2026-09-09):
// numeric segments compare as integers, others lexicographically and case
// insensitively, a numeric segment is greater than a lexicographic one, and a
// label with more segments is greater when the shorter one is its prefix. A
// version without a local label sorts before the same version with one.
func compareLocal(a, b []localSegment) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		switch {
		case a[i].numeric && b[i].numeric:
			if c := compareDigits(a[i].text, b[i].text); c != 0 {
				return c
			}
		case a[i].numeric:
			return 1
		case b[i].numeric:
			return -1
		default:
			if c := strings.Compare(a[i].text, b[i].text); c != 0 {
				return c
			}
		}
	}
	return compareInts(len(a), len(b))
}

// compareDigits orders two normalized digit strings numerically without
// converting them, so component length is unbounded.
func compareDigits(a, b string) int {
	if c := compareInts(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func compareInts(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// normalizeDigits applies the PEP's integer normalization: the value is what int()
// would read, so leading zeros go and "00" becomes "0".
func normalizeDigits(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// numberOrZero normalizes s, treating an absent number as the implicit zero.
func numberOrZero(s string) string {
	if s == "" {
		return "0"
	}
	return normalizeDigits(s)
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// asciiLower lowers only A to Z, leaving every other byte alone so the pattern's
// ASCII classes reject non-ASCII input the way the reference's re.ASCII does.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
