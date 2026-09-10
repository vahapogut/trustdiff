package doctor

import (
	"strings"
	"testing"

	"github.com/vahapogut/trustdiff/internal/configfile"
)

// uvValue reads exclude-newer out of a uv.toml body through the real codec, so a
// bare TOML datetime and a boolean arrive in the shape the reader produces rather
// than one built to suit the judge.
func uvValue(t *testing.T, body string) *configfile.Value {
	t.Helper()
	doc := configfile.NewDoc("uv.toml", configfile.FormatTOML, []byte(body))
	v, err := configfile.Get(doc, configfile.Key{"exclude-newer"})
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	return &v
}

// uv takes four spellings of exclude-newer and the rule read one of them. The
// timestamp form is the strongest thing a project can write here, a fixed point
// every resolution is measured against, and it was the one most likely to be
// reported as a mistake. Finding F13 of docs/review-2026-09-10.md.
func TestUvExcludeNewerReadsEverySpellingUvTakes(t *testing.T) {
	rule := UvExcludeNewer{}
	params := func() *Params {
		return &Params{Cooldown: threeDays, Now: fixedNow(), Version: "0.9.20", VersionExact: true}
	}

	tests := []struct {
		name   string
		body   string
		status Status
		says   []string
	}{
		{
			name:   "a duration in words, which is the spelling a fix writes",
			body:   `exclude-newer = "3 days"`,
			status: StatusSet,
		},
		{
			name:   "a duration in words that is shorter than the policy asks for",
			body:   `exclude-newer = "24 hours"`,
			status: StatusWeak,
			says:   []string{"1 day", "3 days"},
		},
		{
			name:   "an ISO 8601 duration, which uv documents beside the words",
			body:   `exclude-newer = "P3D"`,
			status: StatusSet,
		},
		{
			name:   "the abbreviated duration uv's parser also reads",
			body:   `exclude-newer = "3d"`,
			status: StatusSet,
		},
		{
			// The value F13 is named for: a deliberate point-in-time pin, stronger
			// than any rolling wait, reported as a mistake by a reader that knew
			// only durations.
			name:   "an RFC 3339 timestamp, quoted",
			body:   `exclude-newer = "2026-06-01T00:00:00Z"`,
			status: StatusSet,
			says:   []string{"2026-06-01"},
		},
		{
			// TOML has its own datetime, so this key is as likely to be written
			// without quotes as with them.
			name:   "an RFC 3339 timestamp TOML parsed as a datetime of its own",
			body:   `exclude-newer = 2026-06-01T00:00:00Z`,
			status: StatusSet,
			says:   []string{"2026-06-01"},
		},
		{
			name:   "a local date far enough back",
			body:   `exclude-newer = "2026-08-01"`,
			status: StatusSet,
			says:   []string{"counted from the cutoff 2026-08-01"},
		},
		{
			name:   "a local date so recent that it waits for almost nothing",
			body:   `exclude-newer = "2026-09-08"`,
			status: StatusWeak,
			says:   []string{"counted from the cutoff 2026-09-08"},
		},
		{
			name:   "a cutoff in the future, which excludes nothing at all",
			body:   `exclude-newer = "2027-01-01"`,
			status: StatusWeak,
			says:   []string{"is in the future"},
		},
		{
			name:   "false, which uv documents as turning the wait off",
			body:   `exclude-newer = false`,
			status: StatusWeak,
			says:   []string{"turns the wait off"},
		},
		{
			name:   "a longer unit than the policy asks for",
			body:   `exclude-newer = "1 week"`,
			status: StatusSet,
		},
		{
			name:   "a spelling uv does not read at all",
			body:   `exclude-newer = "last tuesday"`,
			status: StatusWrong,
			says:   []string{"is not a spelling uv reads", "3 days", "P3D"},
		},
		{
			name:   "a bare number, which uv reads as no duration at all",
			body:   `exclude-newer = 3`,
			status: StatusWrong,
			says:   []string{"is not a spelling uv reads"},
		},
		{
			name:   "a list, which uv will refuse outright",
			body:   `exclude-newer = ["3 days"]`,
			status: StatusWrong,
			says:   []string{"a list is not a value"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, detail := rule.Judge(uvValue(t, tt.body+"\n"), params())
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

// The pin a project wrote to hold a resolution still, which is the strongest thing
// this key takes, survives a run of --fix. It follows from writing only a key the
// file does not state, and F13 is the finding that would have destroyed one, so it
// is pinned here on the value the finding named.
func TestUvFixLeavesAnAbsoluteTimestampAlone(t *testing.T) {
	root := t.TempDir()
	const body = `[project]
name = "demo"

[tool.uv]
exclude-newer = "2026-06-01T00:00:00Z"
`
	write(t, root, "pyproject.toml", body)
	managers := []Manager{{
		ID: UV, Root: ".", Version: "0.9.20", VersionExact: true,
		VersionSource: "uv --version", Files: []string{"pyproject.toml"},
	}}
	card, err := Evaluate(root, managers, Options{
		Params: Params{Cooldown: threeDays, Version: "0.9.20", Now: fixedNow()},
		Fix:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Three months back is more of a wait than three days, so it passes on its own
	// terms rather than by being left alone.
	if got := resultFor(t, card, "DR050"); got.Status != StatusSet {
		t.Errorf("DR050 = %s (%s), want set", got.Status, got.Detail)
	}
	if after := readFile(t, root, "pyproject.toml"); !strings.Contains(after, `exclude-newer = "2026-06-01T00:00:00Z"`) {
		t.Errorf("--fix rewrote the pin:\n%s", after)
	}
}
