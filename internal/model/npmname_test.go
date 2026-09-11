package model

import (
	"strings"
	"testing"
)

// NPMNameProblem is npm's own legacy name grammar, the rules
// validate-npm-package-name holds the packages that already exist to. A name it
// refuses cannot be on the registry, which is what lets trustdiff treat one as a
// fact rather than send it to a server. Finding F25 of docs/review-2026-09-10.md.
func TestNPMNameProblemIsNpmsOwnGrammar(t *testing.T) {
	refused := []struct{ name, says string }{
		{"", "greater than zero"},
		{".", "period"},
		{"..", "period"},
		{".hidden", "period"},
		{"_leading", "underscore"},
		{" padded", "leading or trailing spaces"},
		{"node_modules", "not a valid package name"},
		{"Favicon.ICO", "not a valid package name"},
		// The characters that would carry meaning into a URL.
		{"foo?a=b", "URL-friendly"},
		{"foo#frag", "URL-friendly"},
		{"%2e%2e", "URL-friendly"},
		{"a,b", "URL-friendly"},
		{"a/b", "URL-friendly"},
		{"@types", "URL-friendly"},
		{"@scope/pkg/extra", "URL-friendly"},
		{"@sc ope/pkg", "URL-friendly"},
		// A scoped name is checked half by half, and the package half may not start
		// with a period, which is the case that turns into a dot segment.
		{"@scope/..", "period"},
		{"@scope/.pkg", "period"},
	}
	for _, tt := range refused {
		if got := NPMNameProblem(tt.name); !strings.Contains(got, tt.says) {
			t.Errorf("NPMNameProblem(%q) = %q, want it to say %q", tt.name, got, tt.says)
		}
	}
	accepted := []string{
		"express",
		"lodash.merge",
		"@types/node",
		// What npm now only warns about for new names is still a name a package
		// that already exists can carry, and still one the registry serves.
		"JSONStream",
		"@Types/Node",
		"with~tilde!(star)*'",
		"http",
		strings.Repeat("a", 300),
		// Two the upstream grammar accepts and that are safe in a path: "@.." is not
		// a dot segment, it is a scope named "..".
		"@../foo",
		// The upstream grammar refuses a leading hyphen, and this one rule is left
		// out: registry.npmjs.org/- answered 200 with a package published before the
		// rule existed on 2026-09-11 and 2026-09-12, so a name it refuses can exist.
		"-",
	}
	for _, name := range accepted {
		if got := NPMNameProblem(name); got != "" {
			t.Errorf("NPMNameProblem(%q) = %q, want none", name, got)
		}
	}
}

// ParseRef holds an npm name to that grammar, which is what makes a ref named on
// the command line a usage error rather than a request. Other ecosystems keep
// their own rules.
func TestParseRefHoldsAnNpmNameToNpmsGrammar(t *testing.T) {
	for _, in := range []string{"npm:foo?a=b", "npm:..", "npm:@scope/..", "npm:_leading@1.0.0"} {
		if _, err := ParseRef(in); err == nil || !strings.Contains(err.Error(), "not a valid npm name") {
			t.Errorf("ParseRef(%q) error = %v, want one that says it is not a valid npm name", in, err)
		}
	}
	for _, in := range []string{"npm:-", "npm:JSONStream@1.3.5", "npm:@types/node", "pypi:zope.interface", "jsr:@std/path", "cargo:serde_json"} {
		if _, err := ParseRef(in); err != nil {
			t.Errorf("ParseRef(%q) = %v, want it accepted", in, err)
		}
	}
}
