package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
)

// yarnValue reads npmMinimalAgeGate out of a .yarnrc.yml body through the real
// codec, so a bare 3d arrives as the string YAML makes of it.
func yarnValue(t *testing.T, body string) *configfile.Value {
	t.Helper()
	doc := configfile.NewDoc(".yarnrc.yml", configfile.FormatYAML, []byte(body))
	v, err := configfile.Get(doc, configfile.Key{"npmMinimalAgeGate"})
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	return &v
}

// Yarn changed what this setting is between 4.10 and 4.11: a plain number of
// minutes became a duration, and 4.15 made 1d the default. The rule read minutes
// only, so "3d", which is the spelling Yarn's own documentation and its own default
// use, was reported as a mistake on every version. It is a mistake on exactly one
// of them, and there it is a worse one than the rule said. Finding F14 of
// docs/review-2026-09-10.md.
func TestYarnMinimalAgeGateIsJudgedByTheVersionThatReadsIt(t *testing.T) {
	rule := YarnMinimalAgeGate{Default: 24 * time.Hour, DefaultSince: "4.15.0", DurationSince: "4.11.0"}
	params := func(version string, exact bool) *Params {
		return &Params{Cooldown: threeDays, Now: fixedNow(), Version: version, VersionExact: exact}
	}

	tests := []struct {
		name    string
		body    string
		version string
		exact   bool
		status  Status
		says    []string
	}{
		{
			name:    "a number of minutes, which every version reads",
			body:    "npmMinimalAgeGate: 4320",
			version: "4.11.0", exact: true,
			status: StatusSet,
		},
		{
			name:    "a number of minutes that is not enough",
			body:    "npmMinimalAgeGate: 120",
			version: "4.16.0", exact: true,
			status: StatusWeak,
			says:   []string{"2 hours", "4320"},
		},
		{
			// The value F14 is named for, on a version that reads it.
			name:    "a duration string on the version that reads durations",
			body:    "npmMinimalAgeGate: 3d",
			version: "4.11.0", exact: true,
			status: StatusSet,
			says:   []string{"3 days"},
		},
		{
			name:    "the duration Yarn itself defaults to since 4.15",
			body:    `npmMinimalAgeGate: "1d"`,
			version: "4.15.0", exact: true,
			status: StatusWeak,
			says:   []string{"1 day", "3 days"},
		},
		{
			name:    "a week, written the way Yarn's own examples write it",
			body:    "npmMinimalAgeGate: 1w",
			version: "4.18.0", exact: true,
			status: StatusSet,
			says:   []string{"1 week"},
		},
		{
			name:    "a fraction, which Yarn's pattern allows",
			body:    `npmMinimalAgeGate: "1.5d"`,
			version: "4.18.0", exact: true,
			status: StatusWeak,
			says:   []string{"36 hours"},
		},
		{
			// No unit means the setting's own unit, which is minutes, so this is
			// three minutes on every version rather than three of anything else.
			name:    "a string of digits with no unit",
			body:    `npmMinimalAgeGate: "3"`,
			version: "4.18.0", exact: true,
			status: StatusWeak,
			says:   []string{"3 minutes"},
		},
		{
			// Yarn 4.10 reads this setting with parseInt, and parseInt("3d") is 3.
			// The file says three days, the install waits three minutes, and nothing
			// anywhere says so.
			name:    "a duration string on the version that reads it with parseInt",
			body:    "npmMinimalAgeGate: 3d",
			version: "4.10.3", exact: true,
			status: StatusWrong,
			says:   []string{"3 minutes", "4.11", "4320"},
		},
		{
			name:    "a number of minutes on that same old version, which it does read",
			body:    "npmMinimalAgeGate: 4320",
			version: "4.10.3", exact: true,
			status: StatusSet,
		},
		{
			// Neither reading can be ruled out, and crediting the longer one would
			// tell a 4.10 project it waits three days when it waits three minutes.
			name:    "a duration string where the version could not be established",
			body:    "npmMinimalAgeGate: 3d",
			version: "", exact: false,
			status: StatusWeak,
			says:   []string{"3 minutes", "could not establish"},
		},
		{
			name:    "a number where the version could not be established",
			body:    "npmMinimalAgeGate: 4320",
			version: "", exact: false,
			status: StatusSet,
		},
		{
			name:    "zero, which turns the wait off",
			body:    "npmMinimalAgeGate: 0",
			version: "4.18.0", exact: true,
			status: StatusWeak,
			says:   []string{"turns the wait off"},
		},
		{
			name:    "a spelling Yarn's duration pattern does not match",
			body:    `npmMinimalAgeGate: "3 days"`,
			version: "4.18.0", exact: true,
			status: StatusWrong,
			says:   []string{"is not a spelling Yarn reads", "3d", "4320"},
		},
		{
			name:    "a list, which Yarn will refuse outright",
			body:    "npmMinimalAgeGate:\n  - 3d\n",
			version: "4.18.0", exact: true,
			status: StatusWrong,
			says:   []string{"a list is not a value"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, detail := rule.Judge(yarnValue(t, tt.body+"\n"), params(tt.version, tt.exact))
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

// Yarn's own default arrived in 4.15 and is one day, so it answers a policy of one
// day and not one of three. The rule credited it the same way before this change
// and still does; the version it is credited from is the half that matters.
func TestYarnDefaultIsCreditedToTheVersionThatHasIt(t *testing.T) {
	rule := YarnMinimalAgeGate{Default: 24 * time.Hour, DefaultSince: "4.15.0", DurationSince: "4.11.0"}
	absent := &configfile.Value{}

	if status, _ := rule.Judge(absent, &Params{Cooldown: 24 * time.Hour, Now: fixedNow(), Version: "4.15.0", VersionExact: true}); status != StatusSet {
		t.Errorf("a one day policy on 4.15 = %s, want set", status)
	}
	if status, _ := rule.Judge(absent, &Params{Cooldown: 24 * time.Hour, Now: fixedNow(), Version: "4.14.1", VersionExact: true}); status != StatusMissing {
		t.Errorf("a one day policy on 4.14 = %s, want missing", status)
	}
	if status, _ := rule.Judge(absent, &Params{Cooldown: threeDays, Now: fixedNow(), Version: "4.18.0", VersionExact: true}); status != StatusMissing {
		t.Errorf("a three day policy on 4.18 = %s, want missing", status)
	}
}

// What --fix writes has to be a value every version reads, because the fix cannot
// know which one the next machine will run. That is the number.
func TestYarnFixWritesTheNumberEveryVersionReads(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".yarnrc.yml", "nodeLinker: node-modules\n")
	managers := []Manager{{
		ID: Yarn, Root: ".", Version: "4.18.0", VersionExact: true,
		VersionSource: "the packageManager field", Files: []string{".yarnrc.yml"},
	}}
	card, err := Evaluate(root, managers, Options{
		Params: Params{Cooldown: threeDays, Version: "4.18.0", Now: fixedNow()},
		Fix:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resultFor(t, card, "DR020"); got.Status != StatusSet {
		t.Errorf("DR020 = %s (%s), want set after the fix", got.Status, got.Detail)
	}
	if after := readFile(t, root, ".yarnrc.yml"); !strings.Contains(after, "npmMinimalAgeGate: 4320") {
		t.Errorf("--fix did not write the number:\n%s", after)
	}
}
