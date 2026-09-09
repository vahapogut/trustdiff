// Package version parses and orders version strings per ecosystem: semantic
// versions for npm, crates.io, Deno and JSR (through golang.org/x/mod/semver) and
// PEP 440 versions for PyPI. Checks use it to tell prereleases from releases, to
// order versions and to pick the latest stable one.
package version

import (
	"errors"
	"fmt"
	"slices"
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

// parsed pairs a Version with the PEP 440 segments behind it, so the functions
// that order whole histories compare PyPI versions without matching the pattern
// again on every comparison. pep is nil for semantic versions.
type parsed struct {
	v   Version
	pep *pep440
}

// Parse parses s according to the ecosystem's version scheme.
func Parse(eco model.Ecosystem, s string) (Version, error) {
	p, err := parse(eco, s)
	return p.v, err
}

func parse(eco model.Ecosystem, s string) (parsed, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return parsed{}, fmt.Errorf("%w: empty version", ErrInvalid)
	}
	if eco == model.PyPI {
		return parsePEP440(raw)
	}
	v, err := parseSemver(eco, raw)
	if err != nil {
		return parsed{}, err
	}
	return parsed{v: v}, nil
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
	pa, err := parse(eco, a)
	if err != nil {
		return 0, err
	}
	pb, err := parse(eco, b)
	if err != nil {
		return 0, err
	}
	return compareParsed(&pa, &pb), nil
}

// Compare orders v against other, which must belong to the same ecosystem.
func (v Version) Compare(other Version) int {
	if v.Ecosystem == model.PyPI {
		return comparePEP440(v.Canonical, other.Canonical)
	}
	return semver.Compare(v.Canonical, other.Canonical)
}

// compareParsed orders two parsed versions of the same ecosystem, using the
// retained PEP 440 segments when both sides have them.
func compareParsed(a, b *parsed) int {
	if a.pep != nil && b.pep != nil {
		return comparePEP440Parts(a.pep, b.pep)
	}
	return a.v.Compare(b.v)
}

// IsPrerelease reports whether s is a prerelease. Unparsable versions are not
// prereleases: an odd spelling should not make a version disappear from history.
func IsPrerelease(eco model.Ecosystem, s string) bool {
	v, err := Parse(eco, s)
	return err == nil && v.Prerelease
}

// LatestStable returns the highest parsable non-prerelease version, or false when
// there is none. Ties keep the first spelling seen.
func LatestStable(eco model.Ecosystem, versions []string) (string, bool) {
	var best *parsed
	for _, s := range versions {
		p, err := parse(eco, s)
		if err != nil || p.v.Prerelease {
			continue
		}
		if best == nil || compareParsed(&p, best) > 0 {
			best = &p
		}
	}
	if best == nil {
		return "", false
	}
	return best.v.Raw, true
}

// Sort orders versions ascending in place. Unparsable versions keep their relative
// order and sort before every parsable one, so callers can still see them. Versions
// that compare equal (1.0 and 1.0.0 on PyPI) also keep their relative order.
func Sort(eco model.Ecosystem, versions []string) {
	entries := make([]parsed, len(versions))
	ok := make([]bool, len(versions))
	for i, s := range versions {
		p, err := parse(eco, s)
		entries[i], ok[i] = p, err == nil
	}
	order := make([]int, len(versions))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(i, j int) int {
		switch {
		case ok[i] && ok[j]:
			return compareParsed(&entries[i], &entries[j])
		case ok[i]:
			return 1
		case ok[j]:
			return -1
		default:
			return 0
		}
	})
	sorted := make([]string, len(versions))
	for i, j := range order {
		sorted[i] = versions[j]
	}
	copy(versions, sorted)
}
