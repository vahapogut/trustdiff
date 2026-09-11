package model

import "strings"

// NPMNameProblem says why npm's registry could never have held a package under
// name, in npm's own words, or returns the empty string when it could.
//
// The rules are the errors of validate-npm-package-name, which is the grammar npm
// holds the packages that already exist to, read from its lib/index.js on main on
// 2026-09-12 (https://github.com/npm/validate-npm-package-name). What that package
// only warns about for a new name is not refused here: uppercase, more than 214
// characters, the characters ~'!()* and the names of Node's core modules. Packages
// that carry such names were published before the warnings existed and are still
// served, registry.npmjs.org/JSONStream among them. The messages are npm's, word
// for word, so a person who looks a rule up finds it.
//
// One of its errors is left out on purpose. It refuses a name that starts with a
// hyphen, and registry.npmjs.org/- answered 200 with a package published before
// that rule existed, checked on 2026-09-11 and again on 2026-09-12. A name that
// rule refuses can therefore exist, and the whole claim of this function is that
// its names cannot.
//
// The claim is what lets a caller treat a refused name as a fact rather than a
// question. Such a name is never sent to the registry, which matters because it
// is exactly the kind that carries meaning into a URL: "?" starts a query, "#"
// ends the path, "%" starts an escape and ".." is resolved away before the
// request arrives.
func NPMNameProblem(name string) string {
	switch {
	case name == "":
		return "name length must be greater than zero"
	case strings.HasPrefix(name, "."):
		return "name cannot start with a period"
	case strings.HasPrefix(name, "_"):
		return "name cannot start with an underscore"
	case strings.TrimSpace(name) != name:
		return "name cannot contain leading or trailing spaces"
	}
	for _, excluded := range []string{"node_modules", "favicon.ico"} {
		if strings.EqualFold(name, excluded) {
			return excluded + " is not a valid package name"
		}
	}
	if uriComponentSafe(name) {
		return ""
	}
	// A scoped name, @scope/package, is not safe as a whole because of its "@" and
	// its "/", so its two halves are held to the rule apart, the way npm does it.
	if scope, pkg, ok := npmScopedHalves(name); ok {
		if strings.HasPrefix(pkg, ".") {
			return "name cannot start with a period"
		}
		if uriComponentSafe(scope) && uriComponentSafe(pkg) {
			return ""
		}
	}
	return "name can only contain URL-friendly characters"
}

// npmScopedHalves splits @scope/package the way npm's own pattern,
// ^(?:@([^/]+?)[/])?([^/]+?)$, does when its scope group matches: two non-empty
// halves and exactly one slash between them.
func npmScopedHalves(name string) (scope, pkg string, ok bool) {
	rest, scoped := strings.CutPrefix(name, "@")
	if !scoped {
		return "", "", false
	}
	scope, pkg, found := strings.Cut(rest, "/")
	if !found || scope == "" || pkg == "" || strings.Contains(pkg, "/") {
		return "", "", false
	}
	return scope, pkg, true
}

// uriComponentSafe reports whether JavaScript's encodeURIComponent would leave s
// as it is, which is npm's test: letters, digits and -_.!~*'() and nothing else.
func uriComponentSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("-_.!~*'()", c) >= 0:
		default:
			return false
		}
	}
	return true
}
