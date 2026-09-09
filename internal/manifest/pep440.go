package manifest

import (
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
)

// This file decides which published PyPI versions a requirement accepts. The
// ordering and the normalization are internal/model/version's PEP 440 parser, which
// this only asks questions of; what is written here is the specifier grammar on top
// of it, and the few rules the PEP states that ordering alone does not answer.

// pepOperators are the specifier operators, longest first so that "===" is never
// read as "==" and ">=" never as ">".
var pepOperators = []string{"===", "==", "!=", "<=", ">=", "~=", "<", ">"}

// pepParts is what a canonical PEP 440 version says beyond its order: the epoch and
// release segments a prefix match compares, and whether the version carries a post
// release or a local label, which two of the ordered comparisons have to know
// about. It is read off the canonical spelling, whose shape the parser defines, and
// not by parsing the version a second time.
type pepParts struct {
	epoch   string
	release []string
	post    bool
	local   bool
}

// pepClause is one clause of a specifier.
type pepClause struct {
	op string
	// text is the operand as written, which "===" compares literally.
	text string
	// spec is the operand parsed, for the ordered comparisons. It is the zero
	// value for "===" and for a prefix clause, which do not order anything.
	spec  version.Version
	parts pepParts
	// prefix is the ".*" form of "==" and "!=".
	prefix bool
}

// pepSet is clauses that must all hold.
type pepSet []pepClause

// pepConstraint is sets any one of which may hold. PEP 440 has no "or", so a
// specifier is always one set; Poetry writes alternatives with "||" and can produce
// several.
type pepConstraint []pepSet

// allows reports whether the published version satisfies the constraint. A version
// PEP 440 cannot parse satisfies nothing: a version nobody can order is not one to
// resolve a project's dependency to.
func (c pepConstraint) allows(raw string) bool {
	v, err := version.Parse(model.PyPI, raw)
	if err != nil {
		return false
	}
	parts, ok := splitCanonicalPEP(v.Canonical)
	if !ok {
		return false
	}
	for _, set := range c {
		if set.allows(v, parts, raw) {
			return true
		}
	}
	return false
}

// namesPrerelease reports whether the constraint itself names a prerelease
// anywhere, which is the only thing that lets a prerelease be resolved.
func (c pepConstraint) namesPrerelease() bool {
	for _, set := range c {
		if set.namesPrerelease() {
			return true
		}
	}
	return false
}

// allows reports whether the version satisfies every clause of the set.
//
// The prerelease rule is pip's: a prerelease is a candidate only when the
// requirement itself names one. It is applied here rather than per clause because
// it is a property of the requirement, which is also why ">=1.0" never installs
// "2.0.0rc1" however much greater than 1.0 it is.
func (s pepSet) allows(v version.Version, parts pepParts, raw string) bool {
	if v.Prerelease && !s.namesPrerelease() {
		return false
	}
	for i := range s {
		if !s[i].test(v, parts, raw) {
			return false
		}
	}
	return true
}

// namesPrerelease reports whether any clause's operand is a prerelease.
func (s pepSet) namesPrerelease() bool {
	for i := range s {
		if s[i].spec.Prerelease {
			return true
		}
	}
	return false
}

// test reports whether one version satisfies one clause. raw is the version as the
// registry published it, which arbitrary equality compares as text.
func (c *pepClause) test(v version.Version, parts pepParts, raw string) bool {
	switch c.op {
	case "===":
		// Arbitrary equality compares the two spellings and nothing else, which is
		// what it is for: a version PEP 440 would not accept at all.
		return strings.TrimSpace(raw) == c.text
	case "==":
		return c.equals(v, parts)
	case "!=":
		return !c.equals(v, parts)
	case "<=":
		return v.Compare(c.spec) <= 0
	case ">=":
		return v.Compare(c.spec) >= 0
	case "<":
		return v.Compare(c.spec) < 0 && !c.prereleaseOfSpec(v, parts)
	case ">":
		return v.Compare(c.spec) > 0 && !c.appendedToSpec(parts)
	default:
		return false
	}
}

// prereleaseOfSpec reports whether the version is a prerelease of the very version
// the clause names. The PEP's exclusive ordered comparison excludes it: "<1.7" must
// not accept 1.7rc1, which would otherwise slip in as the greatest version below
// the bound. A clause that names a prerelease itself means what it says.
func (c *pepClause) prereleaseOfSpec(v version.Version, parts pepParts) bool {
	if !v.Prerelease || c.spec.Prerelease {
		return false
	}
	return sameRelease(parts, c.parts)
}

// appendedToSpec reports whether the version is the one the clause names with
// something added to it: a post release or a local label. The mirror rule excludes
// both from ">", because ">1.7" asks for a release after 1.7 and neither 1.7.post1
// nor 1.7+local is one.
func (c *pepClause) appendedToSpec(parts pepParts) bool {
	if !sameRelease(parts, c.parts) {
		return false
	}
	return parts.local || (parts.post && !c.parts.post)
}

// equals answers "==" for one version, in both its forms.
func (c *pepClause) equals(v version.Version, parts pepParts) bool {
	if c.prefix {
		return prefixMatch(parts, c.parts)
	}
	if parts.local && !c.parts.local {
		// A specifier that names no local label compares against the public
		// version, so "==1.0" accepts the wheel published as "1.0+local".
		public, err := version.Parse(model.PyPI, publicOf(v.Canonical))
		return err == nil && public.Compare(c.spec) == 0
	}
	return v.Compare(c.spec) == 0
}

// prefixMatch answers the ".*" form: the candidate must agree with every release
// segment the prefix names, with the shorter release read as though it were padded
// with zeros, so that "==1.1.*" accepts 1.1, 1.1.4 and 1.1rc1 but not 1.10.
func prefixMatch(candidate, spec pepParts) bool {
	if candidate.epoch != spec.epoch {
		return false
	}
	for i, segment := range spec.release {
		if releaseAt(candidate.release, i) != segment {
			return false
		}
	}
	return true
}

// releaseAt reads one release segment, reading a segment past the end as the zero
// the PEP pads with.
func releaseAt(release []string, i int) string {
	if i < len(release) {
		return release[i]
	}
	return "0"
}

// sameRelease reports whether two versions share an epoch and a release, which is
// what the PEP calls the same base version. Trailing zeros are dropped first
// because 1.7 and 1.7.0 are the same release.
func sameRelease(a, b pepParts) bool {
	if a.epoch != b.epoch {
		return false
	}
	x, y := trimTrailingZeros(a.release), trimTrailingZeros(b.release)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// trimTrailingZeros drops the zero segments at the end of a release.
func trimTrailingZeros(release []string) []string {
	n := len(release)
	for n > 0 && release[n-1] == "0" {
		n--
	}
	return release[:n]
}

// splitCanonicalPEP reads the epoch, the release segments, and whether there is a
// post release or a local label, out of a canonical PEP 440 version. The canonical
// spelling is [N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local], so the release is the
// run of digits and dots at the front and everything after it is suffix.
func splitCanonicalPEP(canonical string) (pepParts, bool) {
	p := pepParts{epoch: "0"}
	rest := canonical
	if i := strings.IndexByte(rest, '+'); i >= 0 {
		p.local, rest = true, rest[:i]
	}
	if i := strings.IndexByte(rest, '!'); i >= 0 {
		p.epoch, rest = rest[:i], rest[i+1:]
	}
	end := 0
	for {
		start := end
		for end < len(rest) && isDigitByte(rest[end]) {
			end++
		}
		if end == start {
			break
		}
		p.release = append(p.release, rest[start:end])
		// A dot continues the release only when a digit follows it: the dot of
		// ".post1" belongs to the suffix.
		if end+1 < len(rest) && rest[end] == '.' && isDigitByte(rest[end+1]) {
			end++
			continue
		}
		break
	}
	if len(p.release) == 0 {
		return pepParts{}, false
	}
	p.post = strings.Contains(rest[end:], "post")
	return p, true
}

// publicOf drops a local label, leaving the public version the PEP compares against
// a specifier that names none.
func publicOf(canonical string) string {
	if i := strings.IndexByte(canonical, '+'); i >= 0 {
		return canonical[:i]
	}
	return canonical
}

func isDigitByte(b byte) bool { return b >= '0' && b <= '9' }

// parsePEPConstraint parses a PyPI requirement's version part. poetry says the text
// is a Poetry constraint, which is the PEP's clauses plus the caret, tilde,
// wildcard, bare version and "||" forms Poetry adds; the package comment states
// both grammars.
func parsePEPConstraint(text string, poetry bool) (pepConstraint, error) {
	alternatives := []string{text}
	if poetry {
		alternatives = strings.Split(text, "||")
	}
	out := make(pepConstraint, 0, len(alternatives))
	for _, alternative := range alternatives {
		set, err := parsePEPSet(alternative, poetry)
		if err != nil {
			return nil, err
		}
		out = append(out, set)
	}
	return out, nil
}

// parsePEPSet parses one comma separated list of clauses.
func parsePEPSet(text string, poetry bool) (pepSet, error) {
	trimmed := strings.TrimSpace(text)
	// A requirement with no version part accepts every version, and so does
	// Poetry's "*". Both are an empty set of clauses, which every release passes.
	if trimmed == "" || (poetry && trimmed == "*") {
		return pepSet{}, nil
	}
	parts := strings.Split(trimmed, ",")
	set := make(pepSet, 0, len(parts))
	for _, part := range parts {
		clauses, err := parsePEPClauses(part, poetry)
		if err != nil {
			return nil, err
		}
		set = append(set, clauses...)
	}
	return set, nil
}

// parsePEPClauses reads one clause, which is one operator and one operand, into the
// clauses it stands for. Most produce one; "~=" and Poetry's caret and tilde
// produce the two bounds they mean.
func parsePEPClauses(text string, poetry bool) ([]pepClause, error) {
	token := strings.TrimSpace(text)
	var op string
	for _, candidate := range pepOperators {
		if strings.HasPrefix(token, candidate) {
			op = candidate
			break
		}
	}
	operand := strings.TrimSpace(token[len(op):])
	switch {
	case op == "" && poetry:
		return poetryClauses(operand)
	case op == "":
		return nil, fmt.Errorf("not a version specifier this reader parses: %q names no operator", token)
	case operand == "":
		return nil, fmt.Errorf("not a version specifier this reader parses: %q names no version", token)
	case op == "===":
		// Arbitrary equality is a text comparison, so the operand is kept as
		// written and never parsed.
		return []pepClause{{op: op, text: operand}}, nil
	case op == "~=":
		return compatibleRelease(operand)
	}
	prefix := false
	if rest, cut := strings.CutSuffix(operand, ".*"); cut {
		if op != "==" && op != "!=" {
			return nil, fmt.Errorf("not a version specifier this reader parses: %q may not end in .*", token)
		}
		prefix, operand = true, rest
	}
	clause, err := newPEPClause(op, operand, prefix)
	if err != nil {
		return nil, err
	}
	return []pepClause{clause}, nil
}

// newPEPClause parses one operand into a clause.
func newPEPClause(op, operand string, prefix bool) (pepClause, error) {
	v, err := version.Parse(model.PyPI, operand)
	if err != nil {
		return pepClause{}, fmt.Errorf("not a version specifier this reader parses: %q is not a PEP 440 version", operand)
	}
	parts, ok := splitCanonicalPEP(v.Canonical)
	if !ok {
		return pepClause{}, fmt.Errorf("not a version specifier this reader parses: %q is not a PEP 440 version", operand)
	}
	if prefix && !plainRelease(v.Canonical) {
		// A prefix match whose own prefix carries a pre, post or dev segment is a
		// corner of the PEP this reader does not implement, and saying so is
		// better than answering it approximately.
		return pepClause{}, fmt.Errorf("not a version specifier this reader parses: %q.* is a prefix match this reader does not implement", operand)
	}
	return pepClause{op: op, text: operand, spec: v, parts: parts, prefix: prefix}, nil
}

// compatibleRelease expands "~=": at least the version named, and no more than the
// release segment above the last one it names, which is what the PEP defines it as.
func compatibleRelease(operand string) ([]pepClause, error) {
	lower, err := newPEPClause(">=", operand, false)
	if err != nil {
		return nil, err
	}
	if len(lower.parts.release) < 2 {
		return nil, fmt.Errorf("not a version specifier this reader parses: ~=%s names one release segment, and ~= needs at least two", operand)
	}
	upper := pepClause{
		op:     "==",
		text:   operand,
		prefix: true,
		parts:  pepParts{epoch: lower.parts.epoch, release: lower.parts.release[:len(lower.parts.release)-1]},
	}
	return []pepClause{lower, upper}, nil
}

// poetryClauses reads a constraint written without an operator, which is Poetry's
// own grammar: a caret, a tilde, a wildcard, or a bare version meaning that exact
// version.
func poetryClauses(operand string) ([]pepClause, error) {
	switch {
	case operand == "":
		return nil, fmt.Errorf("not a version constraint this reader parses: it names no version")
	case operand == "*":
		// Any version, which is no clause at all. parsePEPSet reads a constraint
		// that is nothing but "*" the same way; this is the one inside a list.
		return nil, nil
	case strings.HasPrefix(operand, "^"):
		return poetryBounds(operand[1:], caretBound)
	case strings.HasPrefix(operand, "~"):
		return poetryBounds(operand[1:], tildeBound)
	case strings.Contains(operand, "*"):
		return poetryWildcard(operand)
	default:
		clause, err := newPEPClause("==", operand, false)
		if err != nil {
			return nil, err
		}
		return []pepClause{clause}, nil
	}
}

// poetryBounds expands a caret or a tilde into the two bounds it means: at least
// the version written, and less than the version bound says.
func poetryBounds(operand string, bound func(release []string) string) ([]pepClause, error) {
	lower, err := newPEPClause(">=", operand, false)
	if err != nil {
		return nil, err
	}
	upper, err := newPEPClause("<", bound(lower.parts.release), false)
	if err != nil {
		return nil, err
	}
	return []pepClause{lower, upper}, nil
}

// caretBound is the version a caret stops below: the segment above the leftmost one
// that is not zero, or above the last segment written when they are all zero. It is
// why ^1.2.3 stops at 2, ^0.2.3 at 0.3 and ^0.0.3 at 0.0.4.
func caretBound(release []string) string {
	i := len(release) - 1
	for j, segment := range release {
		if segment != "0" {
			i = j
			break
		}
	}
	return bumpRelease(release, i)
}

// tildeBound is the version a tilde stops below: the segment above the minor when
// the text names one, and above the major when it does not.
func tildeBound(release []string) string {
	if len(release) == 1 {
		return bumpRelease(release, 0)
	}
	return bumpRelease(release, 1)
}

// bumpRelease renders the release with the segment at i raised by one and every
// segment after it dropped, which reads as a zero in every PEP 440 comparison.
func bumpRelease(release []string, i int) string {
	parts := make([]string, i+1)
	copy(parts, release[:i+1])
	parts[i] = incrementDigits(parts[i])
	return strings.Join(parts, ".")
}

// incrementDigits raises a normalized digit string by one without converting it, so
// that a release segment of any length keeps working.
func incrementDigits(s string) string {
	digits := []byte(s)
	for i := len(digits) - 1; i >= 0; i-- {
		if digits[i] != '9' {
			digits[i]++
			return strings.TrimLeft(string(digits), "0")
		}
		digits[i] = '0'
	}
	return "1" + string(digits)
}

// poetryWildcard expands Poetry's "1.*", which means the same as PEP 440's "==1.*".
func poetryWildcard(operand string) ([]pepClause, error) {
	rest, ok := strings.CutSuffix(operand, ".*")
	if !ok {
		return nil, fmt.Errorf("not a version constraint this reader parses: %q is not a wildcard this reader reads", operand)
	}
	clause, err := newPEPClause("==", rest, true)
	if err != nil {
		return nil, err
	}
	return []pepClause{clause}, nil
}

// plainRelease reports whether a canonical version is an epoch and a release and
// nothing else, which is what a prefix match's own operand has to be.
func plainRelease(canonical string) bool {
	rest := canonical
	if strings.IndexByte(rest, '+') >= 0 {
		return false
	}
	if i := strings.IndexByte(rest, '!'); i >= 0 {
		rest = rest[i+1:]
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] != '.' && !isDigitByte(rest[i]) {
			return false
		}
	}
	return rest != ""
}
