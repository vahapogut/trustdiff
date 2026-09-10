package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/model"
)

const (
	day       = 24 * time.Hour
	threeDays = 3 * day
)

// The same three days, written the way each manager counts. Getting one of these
// wrong is the bug this whole package exists to prevent, so they are spelled out
// rather than computed.
func TestUnitsWriteTheSameDurationEachManagersWay(t *testing.T) {
	tests := []struct {
		unit Unit
		want string
	}{
		{Days, "3"},
		{Minutes, "4320"},
		{Seconds, "259200"},
		{ISO8601, "P3D"},
		{Words, "3 days"},
	}
	for _, tt := range tests {
		t.Run(tt.unit.Name(), func(t *testing.T) {
			if got := tt.unit.Format(threeDays); got != tt.want {
				t.Errorf("Format(3 days) = %q, want %q", got, tt.want)
			}
			back, err := tt.unit.Parse(tt.want)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.want, err)
			}
			if back != threeDays {
				t.Errorf("Parse(%q) = %s, want 72h", tt.want, back)
			}
		})
	}
}

// A conversion always rounds up, because rounding down would hand back a weaker
// setting than the one the project chose.
func TestUnitsRoundUp(t *testing.T) {
	half := 3*day + 12*time.Hour
	if got := Days.Format(half); got != "4" {
		t.Errorf("3 days and a half in days = %q, want 4", got)
	}
	if got := ISO8601.Format(90 * time.Minute); got != "PT2H" {
		t.Errorf("90 minutes as ISO 8601 = %q, want PT2H", got)
	}
	if got := Minutes.Format(90 * time.Second); got != "2" {
		t.Errorf("90 seconds in minutes = %q, want 2", got)
	}
}

// A value in a unit the file does not use is an error, not a reading. Accepting
// "3d" where a number of minutes belongs would call a value correct that the
// package manager itself rejects.
func TestUnitsRefuseTheOtherSpellings(t *testing.T) {
	if _, err := Minutes.Parse("3d"); err == nil {
		t.Error("3d parsed as a number of minutes")
	}
	if _, err := ISO8601.Parse("3d"); err == nil {
		t.Error("3d parsed as an ISO 8601 duration")
	}
	if _, err := Words.Parse("4320"); err == nil {
		t.Error("a bare number parsed as a duration in words")
	}
	// A month is read, because a file that already says "1 month" asks for a longer
	// wait than any cooldown, and never written, because no month has a fixed
	// length.
	if d, err := Words.Parse("2 months"); err != nil || d != 60*day {
		t.Errorf("2 months = %s, %v, want 1440h", d, err)
	}
	if got := Words.Format(60 * day); got != "8 weeks" && got != "60 days" {
		t.Errorf("Format writes %q, which is a unit nothing should write", got)
	}
}

// The unit confusion sentence is the one thing a scorecard can say that a person
// staring at their own config cannot: 10080 in bunfig.toml is a week counted the
// way pnpm counts, and Bun reads it as under three hours.
func TestMinimumAgeNamesTheUnitConfusion(t *testing.T) {
	rule := MinimumAge{Unit: Seconds}
	value := configfile.Value{Kind: configfile.KindInt, Text: "10080", Raw: "10080", Line: 3}
	status, detail := rule.Judge(&value, &Params{Cooldown: threeDays})
	// Bun does read 10080, and waits the 168 minutes it says, so it is weak rather
	// than wrong. The sentence is what tells the writer they meant another unit.
	if status != StatusWeak {
		t.Fatalf("status = %s, want weak", status)
	}
	for _, want := range []string{"168 minutes", "1 week in minutes", "pnpm and Yarn count"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail does not mention %q:\n%s", want, detail)
		}
	}
}

// A manager whose own default already waits long enough is not missing anything,
// and a project pinned to an older version does not get the benefit of a default
// that version does not have.
func TestMinimumAgeCreditsTheDefaultOnlyFromTheVersionThatHasIt(t *testing.T) {
	rule := MinimumAge{Unit: Minutes, Default: day, DefaultSince: "11"}
	if status, _ := rule.Judge(&configfile.Value{}, &Params{Cooldown: day, Version: "11.2.0", VersionExact: true}); status != StatusSet {
		t.Errorf("pnpm 11 with a one day policy = %s, want set", status)
	}
	if status, _ := rule.Judge(&configfile.Value{}, &Params{Cooldown: day, Version: "10.20.0", VersionExact: true}); status != StatusMissing {
		t.Errorf("pnpm 10 with a one day policy = %s, want missing", status)
	}
	if status, _ := rule.Judge(&configfile.Value{}, &Params{Cooldown: day}); status != StatusMissing {
		t.Errorf("an unknown version = %s, want missing: a default nobody confirmed is not protection", status)
	}
	if status, _ := rule.Judge(&configfile.Value{}, &Params{Cooldown: threeDays, Version: "11.2.0", VersionExact: true}); status != StatusMissing {
		t.Errorf("pnpm 11 with a three day policy = %s, want missing: the default is only one day", status)
	}
}

// A value that is present and too small is worse than one that is missing,
// because somebody set it and believes they are protected, and the detail says
// what it really means. It is weak rather than wrong: the manager waits exactly
// the hour the file asks for.
func TestMinimumAgeReportsATooSmallValue(t *testing.T) {
	rule := MinimumAge{Unit: Minutes}
	value := configfile.Value{Kind: configfile.KindInt, Text: "60", Raw: "60"}
	status, detail := rule.Judge(&value, &Params{Cooldown: threeDays})
	if status != StatusWeak {
		t.Fatalf("status = %s, want weak", status)
	}
	if !strings.Contains(detail, "1 hour") || !strings.Contains(detail, "4320") {
		t.Errorf("detail should say what 60 means and what to write instead:\n%s", detail)
	}
}

// The version comparison decides which rules apply, so the pairs that matter are
// pinned here rather than left to a reader's confidence.
func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"11", "11.0.0", 0},
		{"10.16.0", "10.16", 0},
		{"11.0.0-beta.2", "11.0.0", 0},
		{"10.26.0", "11.0.0", -1},
		{"4.15.0", "4.9.2", 1},
		{"v1.3.0", "1.3", 0},
		{"", "1.0.0", -1},
		{"not-a-version", "1.0.0", -1},
	}
	for _, tt := range tests {
		if got := CompareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// A rule that a newer version replaced must not be reported as missing: telling
// somebody to write onlyBuiltDependencies into pnpm 11 is telling them to write a
// key their pnpm refuses.
func TestRuleAppliesFollowsTheManagerVersion(t *testing.T) {
	if ok, _ := pnpmOnlyBuiltDependencies.Applies(pinned(PNPM, "11.2.0")); ok {
		t.Error("the pnpm 10 key still applies on pnpm 11")
	}
	if ok, _ := pnpmOnlyBuiltDependencies.Applies(pinned(PNPM, "10.20.0")); !ok {
		t.Error("the pnpm 10 key does not apply on pnpm 10")
	}
	if ok, why := npmMinReleaseAge.Applies(pinned(NPM, "11.9.0")); ok || why == "" {
		t.Errorf("npm 11.9 is older than the setting: ok = %v, why = %q", ok, why)
	}
	if ok, _ := npmMinReleaseAge.Applies(pinned(NPM, "12.0.2")); !ok {
		t.Error("npm 12 does not get the min-release-age rule")
	}
}

// A lockfile format marker says only that the manager is no older than a version,
// and pnpm 10 and 11 both write lockfileVersion 9.0. Reading that floor as the
// version this project runs would report every setting added later as not
// applicable, which is the shape of most repositories and would leave the
// scorecard with nothing on it.
func TestRuleAppliesTreatsALockfileFloorAsUnknown(t *testing.T) {
	floor := &Manager{ID: PNPM, Version: "9.0.0", VersionSource: "lockfileVersion 9.0 of pnpm-lock.yaml"}
	ok, why := pnpmMinimumReleaseAge.Applies(floor)
	if !ok {
		t.Fatalf("a pnpm project with only a lockfile gets no rules: %s", why)
	}
	if !strings.Contains(why, "at least 9.0.0") {
		t.Errorf("the caveat does not say what is known: %q", why)
	}
	// A floor that already reaches the setting needs no caveat at all.
	if ok, why := pnpmStrictDepBuilds.Applies(&Manager{ID: PNPM, Version: "10.5.0"}); !ok || why != "" {
		t.Errorf("a floor above the setting's own version = %v, %q, want it to apply plainly", ok, why)
	}
	// A default is not credited against a floor: pnpm 11 waits a day and pnpm 10
	// does not, and a lockfile cannot tell them apart.
	status, _ := MinimumAge{Unit: Minutes, Default: day, DefaultSince: "11"}.
		Judge(&configfile.Value{}, &Params{Cooldown: day, Version: "11.0.0"})
	if status != StatusMissing {
		t.Errorf("a floor of 11.0.0 was credited with pnpm 11's default: %s", status)
	}
}

// pinned is a manager whose version is the one it runs, which is what a
// packageManager field or the binary itself answers.
func pinned(id ManagerID, version string) *Manager {
	return &Manager{ID: id, Version: version, VersionExact: true}
}

// Every rule is a row somebody has to be able to check: an id, a name, a level, a
// documentation link and the date that link was last read.
func TestEveryRuleIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules() {
		if seen[r.ID] {
			t.Errorf("%s: duplicate rule id", r.ID)
		}
		seen[r.ID] = true
		switch {
		case r.Name == "":
			t.Errorf("%s: no policy name", r.ID)
		case r.Manager == "":
			t.Errorf("%s: no manager", r.ID)
		case r.Summary == "":
			t.Errorf("%s: no summary", r.ID)
		case r.Docs == "":
			t.Errorf("%s: no documentation link", r.ID)
		case r.Verified == "":
			t.Errorf("%s: no date saying when the documentation was read", r.ID)
		case r.Desired == nil:
			t.Errorf("%s: nothing to judge with", r.ID)
		case r.Level == model.LevelOff:
			t.Errorf("%s: a rule that is off by default is not a rule", r.ID)
		case len(r.Targets) == 0 && r.Scan == nil && !isAdvice(r.Desired):
			// A rule with nothing to read is only honest for advice, which is what
			// the Cargo row is: there is no setting to look at yet.
			t.Errorf("%s: neither a file to read nor a scanner", r.ID)
		}
		if _, err := time.Parse(time.DateOnly, r.Verified); err != nil {
			t.Errorf("%s: verified %q is not a date", r.ID, r.Verified)
		}
		if r.Fixable && r.Scan != nil {
			t.Errorf("%s: a scanner rule cannot be written automatically", r.ID)
		}
		for _, target := range r.Targets {
			if len(target.Key) == 0 {
				t.Errorf("%s: %s has no key", r.ID, target.Name)
			}
			if _, ok := configfile.For(target.Format); !ok {
				t.Errorf("%s: no codec reads %s", r.ID, target.Format)
			}
		}
	}
}

// isAdvice reports whether a rule only tells the reader something, which is the
// one shape that needs no file and no scanner.
func isAdvice(d Desired) bool {
	_, ok := d.(Advice)
	return ok
}
