package pypi

import (
	"log/slog"
	"regexp"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// requirementName matches the project name that opens a PEP 508 requirement:
// letters, digits, and single or repeated runs of ".", "_" and "-" between them.
// Grammar verified 2026-09-09 against https://peps.python.org/pep-0508/#names
// (the same name rule as PEP 426 and PEP 503).
var requirementName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?`)

// markerExtra matches an environment marker that refers to an extra in either
// operand order, "extra == 'socks'" or "'socks' == extra". A requirement with
// such a marker is installed only when the extra is requested (pip install
// pkg[socks]); python_version, platform and implementation markers are not
// matched and stay runtime requirements.
var markerExtra = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.])extra\s*==|==\s*extra(?:[^A-Za-z0-9_.]|$)`)

// urlMarkerStart finds the marker separator of a URL requirement: PEP 508
// requires whitespace before the ";" there, so a ";" inside the URL is not it.
var urlMarkerStart = regexp.MustCompile(`\s;`)

// splitRequirement separates a requirement line as PyPI stores it in
// requires_dist into the normalized project name and the rest as written:
// extras, version specifier or URL, and the environment marker after ";". The
// rest is empty for a bare name. ok is false when the line does not start with a
// project name.
func splitRequirement(raw string) (name, rest string, ok bool) {
	s := strings.TrimSpace(raw)
	loc := requirementName.FindStringIndex(s)
	if loc == nil {
		return "", "", false
	}
	return model.NormalizeName(model.PyPI, s[:loc[1]]), strings.TrimSpace(s[loc[1]:]), true
}

// splitMarker separates the environment marker from the rest of a requirement
// (what follows the project name). PEP 508 introduces the marker with ";"; for
// a URL requirement ("name @ url ; marker") the ";" must follow whitespace.
// marker is empty when there is none.
func splitMarker(rest string) (spec, marker string) {
	at, semi := strings.Index(rest, "@"), strings.Index(rest, ";")
	if at >= 0 && (semi < 0 || at < semi) {
		loc := urlMarkerStart.FindStringIndex(rest)
		if loc == nil {
			return rest, ""
		}
		return strings.TrimSpace(rest[:loc[0]]), strings.TrimSpace(rest[loc[1]:])
	}
	if semi < 0 {
		return rest, ""
	}
	return strings.TrimSpace(rest[:semi]), strings.TrimSpace(rest[semi+1:])
}

// isExtra reports whether a marker makes the requirement part of an extra.
func isExtra(marker string) bool { return markerExtra.MatchString(marker) }

// dependencies maps requires_dist to project name and requirement, split into
// the runtime dependencies a plain install pulls in and the ones guarded by an
// extra marker, which pip installs only when that extra is requested (urllib3
// 2.2.0 added "h2<5,>=4; extra == 'h2'", which no plain install sees). A
// project that appears on several lines of the same kind (different markers,
// typically per Python version) gets the requirements joined with " || " in
// PyPI's order. Lines that do not start with a project name are logged and
// dropped; PyPI rejects such metadata on upload today, so they only occur in
// very old releases. Either map is nil when it would be empty.
func dependencies(requires []string, log *slog.Logger) (runtime, optional map[string]string) {
	if len(requires) == 0 {
		return nil, nil
	}
	runtime = make(map[string]string, len(requires))
	optional = map[string]string{}
	for _, raw := range requires {
		name, rest, ok := splitRequirement(raw)
		if !ok {
			log.Debug("requirement without a project name dropped", "requirement", raw)
			continue
		}
		into := runtime
		if _, marker := splitMarker(rest); isExtra(marker) {
			into = optional
		}
		if prev, dup := into[name]; dup {
			rest = prev + " || " + rest
		}
		into[name] = rest
	}
	return nilIfEmpty(runtime), nilIfEmpty(optional)
}

// nilIfEmpty turns an empty map into nil, the model's "none declared".
func nilIfEmpty(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}
