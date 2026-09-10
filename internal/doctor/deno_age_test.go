package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
)

// denoValue reads minimumDependencyAge out of a deno.json body through the real
// codec, so the object and list cases arrive in the shape the reader produces:
// Kind set, Text empty and Raw holding the value's own bytes. Building the value
// by hand would test the judge against a shape the file never has.
func denoValue(t *testing.T, body string) *configfile.Value {
	t.Helper()
	doc := configfile.NewDoc("deno.json", configfile.FormatJSON, []byte(body))
	v, err := configfile.Get(doc, configfile.Key{"minimumDependencyAge"})
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	return &v
}

// Deno takes five spellings of this setting and an object around any of them, and
// judging them all with the ISO 8601 unit reported four of the five as mistakes.
// A value a manager accepts and acts on is never a mistake; it is either enough or
// it is not. Finding F12 of docs/review-2026-09-10.md.
func TestDenoMinimumDependencyAgeReadsEverySpellingDenoTakes(t *testing.T) {
	rule := DenoMinimumAge{Default: 24 * time.Hour, DefaultSince: "2.9"}
	now := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	params := func() *Params {
		return &Params{Cooldown: threeDays, Now: now, Version: "2.9.1", VersionExact: true}
	}

	tests := []struct {
		name   string
		body   string
		status Status
		says   []string
	}{
		{
			name:   "an ISO 8601 duration, which is the spelling a fix writes",
			body:   `{"minimumDependencyAge": "P3D"}`,
			status: StatusSet,
		},
		{
			name:   "a number of minutes, which is Deno's own second spelling",
			body:   `{"minimumDependencyAge": 4320}`,
			status: StatusSet,
			says:   []string{"in minutes"},
		},
		{
			name:   "a number of minutes that is not enough",
			body:   `{"minimumDependencyAge": 120}`,
			status: StatusWeak,
			says:   []string{"2 hours", "in minutes", "P3D"},
		},
		{
			name:   "an absolute cutoff long enough ago",
			body:   `{"minimumDependencyAge": "2026-08-01"}`,
			status: StatusSet,
			says:   []string{"counted from the cutoff 2026-08-01"},
		},
		{
			name:   "a cutoff so recent that it waits for almost nothing",
			body:   `{"minimumDependencyAge": "2026-09-09"}`,
			status: StatusWeak,
			says:   []string{"counted from the cutoff 2026-09-09"},
		},
		{
			name:   "an RFC 3339 timestamp",
			body:   `{"minimumDependencyAge": "2026-08-01T00:00:00Z"}`,
			status: StatusSet,
		},
		{
			name:   "zero, which Deno documents as turning the wait off",
			body:   `{"minimumDependencyAge": 0}`,
			status: StatusWeak,
			says:   []string{"turns the wait off"},
		},
		{
			name:   "the object form, with the age inside it",
			body:   `{"minimumDependencyAge": {"age": "P3D", "exclude": ["npm:@mycompany/cli"]}}`,
			status: StatusSet,
			says:   []string{"1 package is exempt"},
		},
		{
			name:   "the object form holding a wait that is too short",
			body:   `{"minimumDependencyAge": {"age": 120, "exclude": ["npm:a", "jsr:@b/c"]}}`,
			status: StatusWeak,
			says:   []string{"2 packages are exempt", "in minutes"},
		},
		{
			// Deno reads the key as written, and so does this: an "Age" the tool
			// ignores must not be read as one it honors.
			name:   "an object whose key is not the one Deno reads",
			body:   `{"minimumDependencyAge": {"Age": "P3D"}}`,
			status: StatusWeak,
			says:   []string{"states no age"},
		},
		{
			name:   "a spelling Deno does not read at all",
			body:   `{"minimumDependencyAge": "3d"}`,
			status: StatusWrong,
			says:   []string{"is not a spelling Deno reads", "P3D", "4320"},
		},
		{
			name:   "a list, which Deno will refuse outright",
			body:   `{"minimumDependencyAge": ["P3D"]}`,
			status: StatusWrong,
			says:   []string{"a list is not a value"},
		},
		{
			// A number too large for a duration is still a number Deno takes, and it
			// is longer than any policy asks for, so it is not a wait of no time.
			name:   "a number of minutes larger than a duration can hold",
			body:   `{"minimumDependencyAge": 100000000000000}`,
			status: StatusSet,
			says:   []string{"in minutes"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, detail := rule.Judge(denoValue(t, tt.body), params())
			if status != tt.status {
				t.Fatalf("status = %s, want %s (%s)", status, tt.status, detail)
			}
			for _, want := range tt.says {
				if !strings.Contains(detail, want) {
					t.Errorf("detail does not say %q:\n%s", want, detail)
				}
			}
		})
	}
}

// The key the file does not have is the one thing --fix writes, so the object form
// is safe by construction: there is nothing to judge missing when it is there.
// This is the half of F12 that principle two settled, pinned so it stays settled.
func TestDenoFixLeavesTheObjectFormAlone(t *testing.T) {
	root := t.TempDir()
	const body = `{
  "tasks": { "dev": "deno run -A main.ts" },
  "minimumDependencyAge": { "age": "PT1H", "exclude": ["npm:internal-cli"] }
}
`
	write(t, root, "deno.json", body)
	managers := []Manager{{
		ID: Deno, Root: ".", Version: "2.9.1", VersionExact: true,
		VersionSource: "deno --version", Files: []string{"deno.json"},
	}}
	card, err := Evaluate(root, managers, Options{
		Params: Params{Cooldown: threeDays, Version: "2.9.1", Now: fixedNow()},
		Fix:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// An hour is less than the three days the policy asks for, and Deno waits it.
	if got := resultFor(t, card, "DR040"); got.Status != StatusWeak {
		t.Errorf("DR040 = %s (%s), want weak", got.Status, got.Detail)
	}
	after := readFile(t, root, "deno.json")
	for _, keep := range []string{`"age": "PT1H"`, `"exclude": ["npm:internal-cli"]`, `"dev": "deno run -A main.ts"`} {
		if !strings.Contains(after, keep) {
			t.Errorf("--fix lost %s:\n%s", keep, after)
		}
	}
}
