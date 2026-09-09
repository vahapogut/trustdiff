//go:build integration

package integration

import (
	"testing"

	"github.com/vahapogut/trustdiff/internal/advisory/osv"
	"github.com/vahapogut/trustdiff/internal/model"
)

// TestOSVQueryBatch asks OSV about lodash 4.17.20, which CVE-2021-23337 and
// CVE-2020-28500 affect (both fixed in 4.17.21), so the answer always lists at
// least one advisory; the test checks only that each carries an id.
func TestOSVQueryBatch(t *testing.T) {
	ctx, l := start(t)
	client := osv.New(l.http, osv.WithLogger(l.log))
	ref := model.MustParseRef("npm:lodash@4.17.20")

	got, err := client.Advisories(ctx, []model.PackageRef{ref})
	if err != nil {
		t.Fatalf("Advisories: %v", err)
	}
	advisories := got[ref]
	if len(advisories) == 0 {
		t.Fatalf("no advisories for %s", ref)
	}
	for i := range advisories {
		a := &advisories[i]
		if a.ID == "" {
			t.Errorf("advisory %d of %s has no id", i, ref)
		}
		if a.URL == "" {
			t.Errorf("advisory %s has no URL", a.ID)
		}
	}
	t.Logf("%s: %d advisories, first %s", ref, len(advisories), advisories[0].ID)
}
