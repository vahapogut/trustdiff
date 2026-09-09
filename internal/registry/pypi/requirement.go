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

// dependencies maps requires_dist to project name and requirement. A project
// that appears on several lines (different markers, typically per Python
// version) gets the requirements joined with " || " in PyPI's order. Lines that
// do not start with a project name are logged and dropped; PyPI rejects such
// metadata on upload today, so they only occur in very old releases.
func dependencies(requires []string, log *slog.Logger) map[string]string {
	if len(requires) == 0 {
		return nil
	}
	deps := make(map[string]string, len(requires))
	for _, raw := range requires {
		name, rest, ok := splitRequirement(raw)
		if !ok {
			log.Debug("requirement without a project name dropped", "requirement", raw)
			continue
		}
		if prev, dup := deps[name]; dup {
			rest = prev + " || " + rest
		}
		deps[name] = rest
	}
	if len(deps) == 0 {
		return nil
	}
	return deps
}
