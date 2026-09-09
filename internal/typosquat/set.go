package typosquat

import (
	"slices"

	"github.com/vahapogut/trustdiff/internal/model"
)

// Set is the popular names of one ecosystem in canonical spelling, with the
// indexes Suspect needs to answer the separator, scope and confusable rules by
// lookup instead of by scanning. It is immutable once built and safe for
// concurrent use; it is passed by pointer because the indexes make it large. A
// nil *Set behaves as an empty one.
type Set struct {
	eco   model.Ecosystem
	names []string
	index map[string]struct{}
	// byStripped groups names by their spelling without separators; byFlat does
	// the same for scoped npm names written as scope-name; byFolded groups by the
	// spelling with confusable characters folded. Each group is sorted.
	byStripped map[string][]string
	byFlat     map[string][]string
	byFolded   map[string][]string
	// runes caches the rune form of every name for the edit distance scan.
	runes [][]rune
}

// NewSet builds a Set from names in any spelling. Empty names are dropped and
// duplicates after canonicalization collapse into one.
func NewSet(eco model.Ecosystem, names []string) *Set {
	canonical := make([]string, 0, len(names))
	for _, name := range names {
		if c := Canonical(eco, name); c != "" {
			canonical = append(canonical, c)
		}
	}
	slices.Sort(canonical)
	canonical = slices.Compact(canonical)

	s := &Set{
		eco:        eco,
		names:      canonical,
		index:      make(map[string]struct{}, len(canonical)),
		byStripped: map[string][]string{},
		byFlat:     map[string][]string{},
		byFolded:   map[string][]string{},
		runes:      make([][]rune, len(canonical)),
	}
	for i, name := range canonical {
		s.index[name] = struct{}{}
		stripped := stripSeparators(name)
		folded := foldConfusables(stripped)
		s.byStripped[stripped] = append(s.byStripped[stripped], name)
		s.byFolded[folded] = append(s.byFolded[folded], name)
		if scoped(name) {
			flat := stripSeparators(flattenScope(name))
			s.byFlat[flat] = append(s.byFlat[flat], name)
		}
		s.runes[i] = []rune(name)
	}
	return s
}

// Ecosystem is the ecosystem the names belong to.
func (s *Set) Ecosystem() model.Ecosystem {
	if s == nil {
		return ""
	}
	return s.eco
}

// Has reports whether name, in any spelling, is popular.
func (s *Set) Has(name string) bool {
	if s == nil {
		return false
	}
	return s.hasCanonical(Canonical(s.eco, name))
}

// hasCanonical is Has for a name already in canonical spelling.
func (s *Set) hasCanonical(name string) bool {
	if s == nil {
		return false
	}
	_, ok := s.index[name]
	return ok
}

// Len is the number of popular names.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.names)
}

// Names returns the popular names in canonical spelling, sorted. The slice is a
// copy.
func (s *Set) Names() []string {
	if s == nil {
		return nil
	}
	return slices.Clone(s.names)
}
