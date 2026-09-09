package version

import (
	"fmt"
	"strings"

	"github.com/vahapogut/trustdiff/internal/model"
)

// parsePEP440 is the PyPI scheme (PEP 440). The full parser with the canonical
// regular expression, epochs, pre, post and dev segments and local versions is
// implemented in task 1.2; until then the common release forms are accepted so the
// package compiles and the other packages can build against the API.
func parsePEP440(raw string) (Version, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return Version{}, fmt.Errorf("%w: empty version", ErrInvalid)
	}
	pre := strings.ContainsAny(s, "abc") || strings.Contains(s, "rc") || strings.Contains(s, "dev")
	return Version{Ecosystem: model.PyPI, Raw: raw, Canonical: s, Prerelease: pre}, nil
}

// comparePEP440 orders two canonical PEP 440 spellings. Placeholder until task 1.2.
func comparePEP440(a, b string) int {
	return strings.Compare(a, b)
}
