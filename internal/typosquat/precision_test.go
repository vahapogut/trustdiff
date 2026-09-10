package typosquat

import (
	"os"
	"slices"
	"testing"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	_ "github.com/vahapogut/trustdiff/internal/lockfile/npm"
	"github.com/vahapogut/trustdiff/internal/model"
)

// precisionCorpus is the largest lockfile the repository records, the frontend of
// Apache Superset. It is read where it already lives as a parser fixture rather
// than copied here, so a refresh of the upstream file has one place to land. This
// is the only test in the tree that reads another package's testdata, and it is
// deliberate: the alternative is a second copy of 1.7 MB to keep in step.
const precisionCorpus = "../lockfile/npm/testdata/superset-frontend-package-lock.json"

// supersetFalsePositives is every name of that corpus Suspect flags. Superset
// installs nothing malicious, so each of them is a legitimate package TD008 would
// block at its default level, and they are written out rather than counted so that
// a change to the rules or to the embedded list has to name what it gained or lost.
//
// What remains is the exact rules meeting real names: css-font-parser and
// cssfontparser differ only in separators, js-yaml-loader carries a js prefix over
// yaml-loader, lz4js a js suffix over lz4, rison is one edit from jison, and
// webpack-visualizer-plugin2 is its own numbered successor. None of them is a scope
// paying for the distance between the packages it holds, which is what finding F8
// of docs/review-2026-09-10.md was about.
var supersetFalsePositives = []string{
	"css-font-parser",
	"js-yaml-loader",
	"lz4js",
	"rison",
	"webpack-visualizer-plugin2",
}

// TestPrecision measures Suspect over a real lockfile of a project that installs
// nothing malicious, which makes every flag a false positive. TestRecall measures
// the other half, and TestPopularNamesNeverFlagThemselves measures the popular
// names against themselves; this is the only one that asks what the rules do to
// the ordinary names a large project locks, which is what a person running the
// gate actually meets. A rule that gains recall by matching more loosely pays for
// it here.
func TestPrecision(t *testing.T) {
	p, ok := lockfile.For("package-lock.json")
	if !ok {
		t.Fatal("no parser for package-lock.json")
	}
	f, err := os.Open(precisionCorpus)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // a fixture opened for reading
	lf, err := p.Parse(precisionCorpus, f)
	if err != nil {
		t.Fatal(err)
	}
	set, ok := Embedded().Popular(model.NPM)
	if !ok {
		t.Fatal("no embedded list for npm")
	}

	seen := map[string]bool{}
	var names, candidates, flagged []string
	for _, e := range lf.Installs() {
		c := Canonical(model.NPM, e.Ref.Name)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		names = append(names, c)
		if set.hasCanonical(c) {
			continue
		}
		candidates = append(candidates, c)
		m, ok := Suspect(model.NPM, c, set)
		if !ok {
			continue
		}
		flagged = append(flagged, c)
		t.Logf("flagged: %s -> %s by %s (distance %d)", c, m.Neighbor, m.Rule, m.Distance)
	}
	if len(names) < 1000 {
		t.Fatalf("%s: %d distinct names, want a corpus of at least 1000", precisionCorpus, len(names))
	}
	slices.Sort(flagged)
	t.Logf("distinct names: %d; not in the embedded list: %d; flagged: %d (%.1f%% of the names that could be)",
		len(names), len(candidates), len(flagged), 100*float64(len(flagged))/float64(len(candidates)))
	if !slices.Equal(flagged, supersetFalsePositives) {
		t.Errorf("flagged %v, want %v", flagged, supersetFalsePositives)
	}
}
