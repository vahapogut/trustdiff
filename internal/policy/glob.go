package policy

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Pattern selects packages in cooldown_exclude and in the package field of an allow
// entry. The textual form is [<ecosystem>:]<name>[@<version>]: an ecosystem prefix
// restricts the pattern to that ecosystem, a pattern without one matches every
// ecosystem, and a version restricts the pattern to matching versions.
//
// Name and version are globs with path.Match semantics: "*" matches any run of
// characters except "/", "?" one character, "[a-z]" a class. Because the star stops
// at a slash, "npm:@myorg/*" matches every package in the scope and "npm:*" matches
// no scoped package. "**" is rejected; it would mean the same as "*". Names are
// normalized with model.NormalizeName for the ecosystem being matched, on both the
// pattern and the package, so "pypi:MyOrg_*" matches "myorg-tools".
type Pattern struct {
	raw       string
	ecosystem model.Ecosystem
	name      string
	version   string
}

// ParsePattern parses the textual form. It rejects an empty pattern, an unknown
// ecosystem prefix, whitespace, "**", an empty version after "@" and a malformed
// glob.
func ParsePattern(s string) (Pattern, error) {
	text := strings.TrimSpace(s)
	if text == "" {
		return Pattern{}, errors.New("empty package pattern (want <ecosystem>:<name>, for example npm:@myorg/* or pypi:myorg-*)")
	}
	p := Pattern{raw: text}
	rest := text
	if eco, after, ok := strings.Cut(text, ":"); ok {
		ecosystem, err := model.ParseEcosystem(eco)
		if err != nil {
			return Pattern{}, fmt.Errorf("package pattern %q: %w", text, err)
		}
		p.ecosystem = ecosystem
		rest = after
	}
	if strings.Contains(rest, ":") {
		return Pattern{}, fmt.Errorf("package pattern %q: only one colon is allowed, between the ecosystem and the name", text)
	}
	if strings.ContainsAny(rest, " \t\r\n") {
		return Pattern{}, fmt.Errorf("package pattern %q: whitespace is not allowed", text)
	}
	p.name, p.version = splitPatternVersion(rest)
	if p.name == "" {
		return Pattern{}, fmt.Errorf("package pattern %q: empty package name", text)
	}
	if p.version == "" && strings.LastIndex(rest, "@") > 0 {
		return Pattern{}, fmt.Errorf("package pattern %q: empty version after @", text)
	}
	for _, part := range []string{p.name, p.version} {
		if strings.Contains(part, "**") {
			return Pattern{}, fmt.Errorf("package pattern %q: \"**\" is not supported; \"*\" matches any run of characters except \"/\", so \"npm:@myorg/*\" matches every package in the scope", text)
		}
		if part == "" {
			continue
		}
		if _, err := path.Match(part, ""); err != nil {
			return Pattern{}, fmt.Errorf("package pattern %q: malformed glob %q: %w", text, part, err)
		}
	}
	return p, nil
}

// splitPatternVersion separates name and version at the last "@" that is not the
// scope marker of an npm or JSR name.
func splitPatternVersion(rest string) (name, version string) {
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return rest, ""
	}
	return rest[:at], rest[at+1:]
}

// MustParsePattern is ParsePattern for constants and tests; it panics on error.
func MustParsePattern(s string) Pattern {
	p, err := ParsePattern(s)
	if err != nil {
		panic(err)
	}
	return p
}

// Ecosystem returns the ecosystem the pattern is restricted to, or the empty string
// when it matches every ecosystem.
func (p Pattern) Ecosystem() model.Ecosystem { return p.ecosystem }

// Match reports whether the pattern selects the package version. A pattern without
// a version matches every version; a pattern with one needs the ref to carry a
// matching version.
func (p Pattern) Match(ref model.PackageRef) bool {
	if p.ecosystem != "" && ref.Ecosystem != p.ecosystem {
		return false
	}
	name := model.NormalizeName(ref.Ecosystem, ref.Name)
	namePattern := model.NormalizeName(ref.Ecosystem, p.name)
	if ok, err := path.Match(namePattern, name); err != nil || !ok {
		return false
	}
	if p.version == "" {
		return true
	}
	ok, err := path.Match(p.version, ref.Version)
	return err == nil && ok
}

// String returns the pattern as it was written.
func (p Pattern) String() string { return p.raw }

// UnmarshalYAML accepts a scalar in the form ParsePattern accepts.
func (p *Pattern) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: want a package pattern such as npm:@myorg/* or pypi:myorg-*, got a %s", n.Line, yamlKind(n))
	}
	parsed, err := ParsePattern(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*p = parsed
	return nil
}

// MarshalYAML writes the pattern as it was written.
func (p Pattern) MarshalYAML() (any, error) { return p.raw, nil }
