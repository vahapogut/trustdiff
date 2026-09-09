package manifest

import (
	"fmt"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/model/version"
)

// constraint is a parsed dependency range: it answers, for one published version,
// whether the declaration accepts it. One of its two halves is set, decided by the
// grammar the range was written in.
type constraint struct {
	syntax Syntax
	semver semverRange
	pep    pepConstraint
}

// parseConstraint parses a range written in one of the grammars this package reads.
// The error it returns is the reason a declaration is skipped, so it is worded as
// one: lower case, and saying what could not be read rather than where.
func parseConstraint(syntax Syntax, text string) (*constraint, error) {
	c := &constraint{syntax: syntax}
	var err error
	switch syntax {
	case SyntaxNPM:
		c.semver, err = parseNPMRange(text)
	case SyntaxCargo:
		c.semver, err = parseCargoRequirement(text)
	case SyntaxPEP440:
		c.pep, err = parsePEPConstraint(text, false)
	case SyntaxPoetry:
		c.pep, err = parsePEPConstraint(text, true)
	default:
		return nil, fmt.Errorf("no reader for a %q version range", string(syntax))
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// allows reports whether the published version satisfies the range, prereleases
// included: each grammar's own prerelease rule is part of the answer, because the
// two ecosystems' rules differ and neither is the caller's to apply.
func (c *constraint) allows(raw string) bool {
	if c.syntax == SyntaxPEP440 || c.syntax == SyntaxPoetry {
		return c.pep.allows(raw)
	}
	return c.semver.allows(raw)
}

// namesPrerelease reports whether the range itself names a prerelease, which is what
// the resolver says when it explains that the only versions on offer were
// prereleases.
func (c *constraint) namesPrerelease() bool {
	if c.syntax == SyntaxPEP440 || c.syntax == SyntaxPoetry {
		return c.pep.namesPrerelease()
	}
	return c.semver.namesPrerelease()
}

// higher reports whether a is a higher version than b in the ecosystem's own
// scheme. It is internal/model/version's comparison, so that resolving a manifest
// orders versions exactly as every check does.
func higher(eco model.Ecosystem, a, b string) bool {
	c, err := version.Compare(eco, a, b)
	return err == nil && c > 0
}
