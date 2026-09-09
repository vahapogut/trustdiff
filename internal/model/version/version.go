// Package version parses and orders version strings per ecosystem: semantic
// versions for npm, crates.io, Deno and JSR (through golang.org/x/mod/semver) and
// PEP 440 versions for PyPI. Checks use it to tell prereleases from releases, to
// order versions and to pick the latest stable one.
package version

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/vahapogut/trustdiff/internal/model"
)

// ErrInvalid is wrapped by every parse failure.
var ErrInvalid = errors.New("invalid version")

// Version is a parsed version. Canonical is the normalized spelling used for
// comparisons; Raw is what the registry published.
type Version struct {
	Ecosystem  model.Ecosystem
	Raw        string
	Canonical  string
	Prerelease bool
}

// Parse parses s according to the ecosystem's version scheme.
func Parse(eco model.Ecosystem, s string) (Version, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Version{}, fmt.Errorf("%w: empty version", ErrInvalid)
	}
	switch eco {
	case model.PyPI:
		return parsePEP440(raw)
	default:
		return parseSemver(eco, raw)
	}
}

// parseSemver accepts semantic versions with or without a leading v and strips
// build metadata for comparison, as npm and Cargo do.
func parseSemver(eco model.Ecosystem, raw string) (Version, error) {
	canonical := raw
	if !strings.HasPrefix(canonical, "v") {
		canonical = "v" + canonical
	}
	if !semver.IsValid(canonical) {
		return Version{}, fmt.Errorf("%w: %q is not a semantic version", ErrInvalid, raw)
	}
	return Version{
		Ecosystem:  eco,
		Raw:        raw,
		Canonical:  semver.Canonical(canonical),
		Prerelease: semver.Prerelease(canonical) != "",
	}, nil
}

// Compare orders two versions of the same ecosystem: -1, 0 or +1.
func Compare(eco model.Ecosystem, a, b string) (int, error) {
	va, err := Parse(eco, a)
	if err != nil {
		return 0, err
	}
	vb, err := Parse(eco, b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// Compare orders v against other, which must belong to the same ecosystem.
func (v Version) Compare(other Version) int {
	if v.Ecosystem == model.PyPI {
		return comparePEP440(v.Canonical, other.Canonical)
	}
	return semver.Compare(v.Canonical, other.Canonical)
}

// IsPrerelease reports whether s is a prerelease. Unparsable versions are not
// prereleases: an odd spelling should not make a version disappear from history.
func IsPrerelease(eco model.Ecosystem, s string) bool {
	v, err := Parse(eco, s)
	return err == nil && v.Prerelease
}

// LatestStable returns the highest parsable non-prerelease version, or false when
// there is none.
func LatestStable(eco model.Ecosystem, versions []string) (string, bool) {
	var best *Version
	for _, s := range versions {
		v, err := Parse(eco, s)
		if err != nil || v.Prerelease {
			continue
		}
		if best == nil || v.Compare(*best) > 0 {
			vv := v
			best = &vv
		}
	}
	if best == nil {
		return "", false
	}
	return best.Raw, true
}

// Sort orders versions ascending in place. Unparsable versions keep their relative
// order and sort before every parsable one, so callers can still see them.
func Sort(eco model.Ecosystem, versions []string) {
	parsed := make(map[string]Version, len(versions))
	for _, s := range versions {
		if v, err := Parse(eco, s); err == nil {
			parsed[s] = v
		}
	}
	less := func(a, b string) int {
		va, oka := parsed[a]
		vb, okb := parsed[b]
		switch {
		case oka && okb:
			return va.Compare(vb)
		case oka:
			return 1
		case okb:
			return -1
		default:
			return 0
		}
	}
	sortStable(versions, less)
}

func sortStable(s []string, cmp func(a, b string) int) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && cmp(s[j-1], s[j]) > 0; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
