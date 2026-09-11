package model

import (
	"fmt"
	"regexp"
	"strings"
)

// PackageRef names a package, optionally at one version, in one ecosystem.
// The textual form is <ecosystem>:<name>[@<version>], for example npm:express@4.19.2,
// npm:@types/node@20.0.0, pypi:requests or cargo:serde.
type PackageRef struct {
	Ecosystem Ecosystem `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version,omitempty"`
}

// pep503Separators matches runs of the characters PEP 503 collapses into one dash.
var pep503Separators = regexp.MustCompile(`[-_.]+`)

// ParseRef parses the textual form. Names are normalized with NormalizeName.
func ParseRef(s string) (PackageRef, error) {
	s = strings.TrimSpace(s)
	eco, rest, ok := strings.Cut(s, ":")
	if !ok {
		return PackageRef{}, fmt.Errorf("invalid ref %q: want <ecosystem>:<name>[@<version>]", s)
	}
	ecosystem, err := ParseEcosystem(eco)
	if err != nil {
		return PackageRef{}, fmt.Errorf("invalid ref %q: %w", s, err)
	}

	name, version := splitVersion(rest)
	if name == "" {
		return PackageRef{}, fmt.Errorf("invalid ref %q: empty package name", s)
	}
	if strings.ContainsAny(name, " \t\\") {
		return PackageRef{}, fmt.Errorf("invalid ref %q: package name %q contains illegal characters", s, name)
	}
	// npm and JSR names may carry a scope: @scope/name. Nothing else may contain "/" or start with "@".
	scoped := (ecosystem == NPM || ecosystem == JSR) && strings.HasPrefix(name, "@")
	if scoped {
		scope, pkg, ok := strings.Cut(name[1:], "/")
		if !ok || scope == "" || pkg == "" || strings.Contains(pkg, "/") {
			return PackageRef{}, fmt.Errorf("invalid ref %q: scoped name must look like @scope/name", s)
		}
	} else {
		if strings.HasPrefix(name, "@") {
			return PackageRef{}, fmt.Errorf("invalid ref %q: package name must not start with @", s)
		}
		if strings.Contains(name, "/") {
			return PackageRef{}, fmt.Errorf("invalid ref %q: package name %q contains a slash", s, name)
		}
	}
	// An npm name is held to npm's own grammar, so a name the registry could never
	// hold is a usage error here rather than a request later.
	if ecosystem == NPM {
		if problem := NPMNameProblem(name); problem != "" {
			return PackageRef{}, fmt.Errorf("invalid ref %q: not a valid npm name: %s", s, problem)
		}
	}
	// A trailing "@" (anything after the scope marker) means a version was intended but not given.
	if version == "" && strings.LastIndex(rest, "@") > 0 {
		return PackageRef{}, fmt.Errorf("invalid ref %q: empty version after @", s)
	}
	if strings.ContainsAny(version, " \t") {
		return PackageRef{}, fmt.Errorf("invalid ref %q: version %q contains whitespace", s, version)
	}
	return PackageRef{Ecosystem: ecosystem, Name: NormalizeName(ecosystem, name), Version: version}, nil
}

// splitVersion separates name and version at the last "@" that is not the leading
// scope marker of an npm name.
func splitVersion(rest string) (name, version string) {
	at := strings.LastIndex(rest, "@")
	if at <= 0 {
		return rest, ""
	}
	return rest[:at], rest[at+1:]
}

// MustParseRef is ParseRef for tests and constants; it panics on error.
func MustParseRef(s string) PackageRef {
	r, err := ParseRef(s)
	if err != nil {
		panic(err)
	}
	return r
}

// NormalizeName applies the registry's canonical spelling so that the same package
// compares equal however it was written. Only PyPI has one: PEP 503 (lowercase,
// runs of "-", "_" and "." become one "-"). Every other name is returned as
// written. npm in particular is case-sensitive: the registry rejects uppercase in
// new names but still serves the legacy mixed-case ones as packages of their own
// (JSONStream and jsonstream are two unrelated packages, verified 2026-09-09), and
// OSV, deps.dev and the download counts API index them that way too, so folding
// case would evaluate a different package. A caller that wants a case-insensitive
// comparison (typosquat neighbors, allow-list globs) folds case at the comparison
// site, not in the identity.
func NormalizeName(eco Ecosystem, name string) string {
	if eco == PyPI {
		return strings.ToLower(pep503Separators.ReplaceAllString(name, "-"))
	}
	return name
}

// SameName reports whether two spellings name one package, which is the test a
// caller applies before it adopts a registry's own spelling of a name over the one
// it asked with. NormalizeName cannot answer it: that is the identity a ref carries
// everywhere, and only PyPI has a normalization its registry publishes.
//
// crates.io allocates a crate name case-insensitively and treats "-" and "_" as the
// same character, and serves the crate document under every one of those spellings
// (GET https://crates.io/api/v1/crates/Serde-Json answers serde_json's document,
// read 2026-09-10), while the registered spelling is the only one OSV matches. npm
// and JSR names stay exact: npm serves legacy mixed-case names as packages of their
// own, so folding case there would call two packages one. internal/typosquat folds
// the same way for its own comparison, in Canonical, and for the same reason.
func SameName(eco Ecosystem, a, b string) bool {
	if eco == Cargo {
		return strings.EqualFold(strings.ReplaceAll(a, "-", "_"), strings.ReplaceAll(b, "-", "_"))
	}
	return NormalizeName(eco, a) == NormalizeName(eco, b)
}

// String renders the ref in the form ParseRef accepts.
func (r PackageRef) String() string {
	if r.Version == "" {
		return fmt.Sprintf("%s:%s", r.Ecosystem, r.Name)
	}
	return fmt.Sprintf("%s:%s@%s", r.Ecosystem, r.Name, r.Version)
}

// HasVersion reports whether the ref pins a version.
func (r PackageRef) HasVersion() bool { return r.Version != "" }

// Package returns the ref without its version.
func (r PackageRef) Package() PackageRef { return PackageRef{Ecosystem: r.Ecosystem, Name: r.Name} }

// WithVersion returns a copy of the ref at the given version.
func (r PackageRef) WithVersion(v string) PackageRef {
	r.Version = v
	return r
}
