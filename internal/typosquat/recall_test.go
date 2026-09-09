package typosquat

import (
	"encoding/csv"
	"io"
	"os"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
)

// minRecall is the share of confirmed typosquats, whose target is in the
// embedded list of their ecosystem, that Suspect must flag.
const minRecall = 0.80

// datasetEcosystems maps the ecosystem column of typosquats.csv to ours; the
// rows for Go and GitHub Actions have no list and are not counted.
var datasetEcosystems = map[string]model.Ecosystem{
	"npm":       model.NPM,
	"pypi":      model.PyPI,
	"crates.io": model.Cargo,
}

type typosquatRow struct {
	malicious, target, classification string
	eco                               model.Ecosystem
}

func readTyposquats(t *testing.T) []typosquatRow {
	t.Helper()
	f, err := os.Open("testdata/typosquats.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	col := map[string]int{}
	for i, name := range header {
		col[name] = i
	}
	for _, want := range []string{"malicious_package", "target_package", "ecosystem", "classification"} {
		if _, ok := col[want]; !ok {
			t.Fatalf("typosquats.csv: column %q missing from header %v", want, header)
		}
	}
	var rows []typosquatRow
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		eco, ok := datasetEcosystems[rec[col["ecosystem"]]]
		if !ok {
			continue
		}
		rows = append(rows, typosquatRow{
			malicious:      rec[col["malicious_package"]],
			target:         rec[col["target_package"]],
			classification: rec[col["classification"]],
			eco:            eco,
		})
	}
	return rows
}

// TestRecall measures Suspect against the ecosyste-ms typosquatting dataset
// (testdata/typosquats.csv) and the embedded lists. Only rows whose target is in
// the embedded list count: a target the list does not know cannot be matched by
// any rule and says nothing about the rules. The log lines report the measured
// numbers so a change to the rules or the lists shows its effect.
func TestRecall(t *testing.T) {
	rows := readTyposquats(t)
	if len(rows) < 100 {
		t.Fatalf("typosquats.csv: %d usable rows, want at least 100", len(rows))
	}
	lists := Embedded()
	var eligible, flagged, exact int
	missed := map[string]int{}
	for _, row := range rows {
		set, ok := lists.Popular(row.eco)
		if !ok {
			t.Fatalf("no embedded list for %s", row.eco)
		}
		if !set.Has(row.target) {
			continue
		}
		eligible++
		m, ok := Suspect(row.eco, row.malicious, set)
		if !ok {
			missed[row.classification]++
			t.Logf("missed: %s:%s -> %s (%s)", row.eco, row.malicious, row.target, row.classification)
			continue
		}
		flagged++
		if m.Neighbor == Canonical(row.eco, row.target) {
			exact++
		} else {
			t.Logf("other neighbor: %s:%s -> %s, got %s by %s (distance %d)", row.eco, row.malicious, row.target, m.Neighbor, m.Rule, m.Distance)
		}
	}
	recall := float64(flagged) / float64(eligible)
	t.Logf("rows in supported ecosystems: %d; targets in the embedded lists: %d; flagged: %d (recall %.1f%%); flagged with the dataset's target as the neighbor: %d (%.1f%%); misses by classification: %v",
		len(rows), eligible, flagged, 100*recall, exact, 100*float64(exact)/float64(eligible), missed)
	if eligible < 50 {
		t.Fatalf("only %d dataset targets are in the embedded lists, too few to measure recall", eligible)
	}
	if recall < minRecall {
		t.Errorf("recall %.1f%% is below %.0f%%", 100*recall, 100*minRecall)
	}
}
