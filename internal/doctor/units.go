package doctor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/policy"
)

// The units the package managers count a minimum release age in. They disagree,
// which is the whole reason this file exists: the same three days is 3 for npm,
// 4320 for pnpm and Yarn, 259200 for Bun, "P3D" for Deno and pip, and "3 days" for
// uv and Renovate. Deno and pip share a spelling and not a unit: Deno documents
// the whole of ISO 8601 and pip documents days. A number alone therefore says nothing, and a scorecard that
// compared numbers would call 10080 seconds in bunfig.toml a week when it is under
// three hours.
//
// Every conversion rounds up. A project whose policy says three days and whose
// package manager counts days keeps three; one that counts days and a policy of
// three and a half gets four. Rounding down would hand back a weaker setting than
// the one the project chose, which is the one thing a hardening tool must not do.
var (
	// Days is npm's unit, and Poetry's and Dependabot's.
	Days Unit = countUnit{name: "days", per: 24 * time.Hour}
	// Minutes is pnpm's unit and Yarn's, and the one Deno uses for a bare number.
	Minutes Unit = countUnit{name: "minutes", per: time.Minute}
	// Seconds is Bun's unit.
	Seconds Unit = countUnit{name: "seconds", per: time.Second}
	// ISO8601 is Deno's, written P3D or PT72H.
	ISO8601 Unit = isoUnit{}
	// ISO8601Days is pip's: the same spelling in whole days. pip documents the
	// relative form as "a duration in days (e.g., 'P3D')" and names no finer unit,
	// read from its install reference on 2026-09-12, so a wait written for pip is
	// rounded up to a whole day rather than spelled in hours.
	ISO8601Days Unit = isoDaysUnit{}
	// Words is what uv and Renovate write: "3 days", "24 hours", "1 week".
	Words Unit = wordUnit{}
)

// countUnit is a plain count of one fixed unit of time.
type countUnit struct {
	name string
	per  time.Duration
}

func (u countUnit) Name() string { return u.name }

// Parse reads a count. A value with a unit in it, "3d" where the file wants a
// number of minutes, is an error rather than a reading, because the manager itself
// will not accept it and reporting it as three days would hide the real problem.
func (u countUnit) Parse(text string) (time.Duration, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, errors.New("empty value")
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("want a number of %s, got %q", u.name, text)
	}
	if n < 0 {
		return 0, fmt.Errorf("want a number of %s, got %q", u.name, text)
	}
	return time.Duration(n) * u.per, nil
}

// Format writes the count, rounded up so the setting is never weaker than the
// duration asked for.
func (u countUnit) Format(d time.Duration) string {
	return strconv.FormatInt(ceilDiv(d, u.per), 10)
}

// isoUnit is an ISO 8601 duration, which is what Deno and pip accept.
type isoUnit struct{}

func (isoUnit) Name() string { return "an ISO 8601 duration" }

// Parse accepts the ISO 8601 spelling only. The policy parser also reads 3d and
// 12h, and accepting those here would call a value correct that the manager will
// reject, which is the opposite of what a scorecard is for.
func (isoUnit) Parse(text string) (time.Duration, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "P") && !strings.HasPrefix(text, "p") {
		return 0, fmt.Errorf("want an ISO 8601 duration such as P3D, got %q", text)
	}
	d, err := policy.ParseDuration(strings.ToUpper(text))
	if err != nil {
		return 0, fmt.Errorf("want an ISO 8601 duration such as P3D, got %q", text)
	}
	return d, nil
}

// Format writes whole days as P<n>D and anything finer as hours, which is the
// spelling every one of these managers documents.
func (isoUnit) Format(d time.Duration) string {
	if d%(24*time.Hour) == 0 && d > 0 {
		return fmt.Sprintf("P%dD", d/(24*time.Hour))
	}
	return fmt.Sprintf("PT%dH", ceilDiv(d, time.Hour))
}

// isoDaysUnit is an ISO 8601 duration in whole days, which is the form pip
// documents. Reading is wider than writing on purpose: a file that already says
// PT12H is read as twelve hours and judged against the policy, because reporting a
// value as unreadable is a claim about pip this tool cannot make from a reference
// that simply does not mention the form.
type isoDaysUnit struct{}

func (isoDaysUnit) Name() string { return "an ISO 8601 duration in days" }

// Parse reads any ISO 8601 duration, the way Deno's unit does.
func (isoDaysUnit) Parse(text string) (time.Duration, error) { return ISO8601.Parse(text) }

// Format writes whole days, rounded up: three days and a half is P4D and ninety
// minutes is P1D, since a day is the shortest wait pip documents.
func (isoDaysUnit) Format(d time.Duration) string {
	return fmt.Sprintf("P%dD", ceilDiv(d, 24*time.Hour))
}

// wordUnit is the "3 days" spelling uv and Renovate take.
type wordUnit struct{}

func (wordUnit) Name() string { return "a duration in words" }

// Parse reads "<number> <unit>", the spelling both documents use, and also accepts
// the ISO 8601 form, which uv takes as well. A bare number is not accepted: uv
// would reject it and Renovate reads it as milliseconds, so calling it correct
// would be wrong in both directions.
func (wordUnit) Parse(text string) (time.Duration, error) {
	text = strings.ToLower(strings.TrimSpace(text))
	if strings.HasPrefix(text, "p") {
		return ISO8601.Parse(text)
	}
	number, unit, ok := strings.Cut(text, " ")
	if !ok {
		return 0, fmt.Errorf("want a duration such as \"3 days\", got %q", text)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(number), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("want a duration such as \"3 days\", got %q", text)
	}
	per, err := wordUnitLength(strings.TrimSpace(unit))
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * per, nil
}

// wordUnitLength turns the unit word into its length. Months and years are
// refused for the reason the policy parser refuses them: neither has a fixed
// length, and a cooldown that means something different in February is not a
// cooldown anyone can reason about.
func wordUnitLength(unit string) (time.Duration, error) {
	switch strings.TrimSuffix(unit, "s") {
	case "second", "sec":
		return time.Second, nil
	case "minute", "min":
		return time.Minute, nil
	case "hour", "hr":
		return time.Hour, nil
	case "day":
		return 24 * time.Hour, nil
	case "week":
		return 7 * 24 * time.Hour, nil
	case "month":
		// Reading is not writing. No month has a fixed length, which is why nothing
		// here ever writes one, but a file that already says "1 month" is asking for
		// a longer wait than any cooldown and calling that wrong would be absurd.
		// Thirty days is the shortest month, so it is the honest reading.
		return 30 * 24 * time.Hour, nil
	case "year":
		return 365 * 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("unknown unit %q; use hours, days or weeks", unit)
}

// Format writes the largest whole unit that divides the duration, so three days
// reads "3 days" rather than "72 hours".
func (wordUnit) Format(d time.Duration) string { return Humanize(d) }

// Humanize writes a duration the way these files and the scorecard spell it: the
// largest unit that divides it evenly, rounded up otherwise.
func Humanize(d time.Duration) string {
	switch {
	case d <= 0:
		return "0 days"
	case d%(7*24*time.Hour) == 0:
		return plural(int64(d/(7*24*time.Hour)), "week")
	case d%(24*time.Hour) == 0:
		return plural(int64(d/(24*time.Hour)), "day")
	case d%time.Hour == 0:
		return plural(int64(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return plural(int64(d/time.Minute), "minute")
	default:
		return plural(ceilDiv(d, time.Second), "second")
	}
}

// plural writes a count with its unit, in words.
func plural(n int64, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.FormatInt(n, 10) + " " + unit + "s"
}

// ceilDiv divides and rounds up, which is how every conversion here rounds.
func ceilDiv(d, per time.Duration) int64 {
	if per <= 0 || d <= 0 {
		return 0
	}
	n := int64(d / per)
	if d%per != 0 {
		n++
	}
	return n
}
