package doctor

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
)

// YarnMinimalAgeGate judges Yarn's npmMinimalAgeGate, which changed what it is
// between two minor releases.
//
// Yarn 4.10 declared it SettingsType.NUMBER with the description "Minimum age of a
// package version according to the publish date on the npm registry in minutes",
// and that release reads a NUMBER setting with `return parseInt(value)`. Yarn 4.11
// changed it to SettingsType.DURATION with `unit: DurationUnit.MINUTES`, and 4.15
// changed its default from `0m` to `1d`. A DURATION is read by miscUtils
// parseDuration against `^(\d*\.?\d+)(ms|s|m|h|d|w)?$`: a value with no unit is a
// count of the setting's own unit, one with a unit is converted into it, and
// anything else throws. Read on 2026-09-11 from the plugin's own source at the
// 4.10.3, 4.11.0 and 4.12.0 tags, the release notes for 4.10.0 (PR 6901), 4.11.0
// (PR 6942) and 4.15.0 (PR 7135), and the yarnrc schema the documentation site
// publishes, which gives the default as "1d" and the examples as 1w, 1d, 3h, 30m.
//
// So "3d" is what Yarn's own documentation writes and what Yarn itself defaults to,
// and reporting it as a mistake told correct files they were wrong. On 4.10 it is a
// mistake, and a worse one than a wrong unit: parseInt("3d") is 3, so a file asking
// for three days waits three minutes and nothing anywhere says so.
type YarnMinimalAgeGate struct {
	// Default is what Yarn waits when the key is absent, and DefaultSince the
	// version that arrived in.
	Default      time.Duration
	DefaultSince string
	// DurationSince is the version that reads a duration string. Before it the
	// setting was a plain number and a unit suffix was truncated away.
	DurationSince string
}

// Want is what a fix writes: the number of minutes, which every version reads the
// same way. A fix cannot know which Yarn the next machine will run.
func (YarnMinimalAgeGate) Want(p *Params) configfile.Literal {
	return configfile.Literal{Kind: configfile.KindInt, Text: Minutes.Format(p.Cooldown)}
}

// Describe says what the setting should hold, with the number translated, since a
// count of minutes says nothing on its own.
func (YarnMinimalAgeGate) Describe(p *Params) string {
	return fmt.Sprintf("%s, which is %s", Minutes.Format(p.Cooldown), Humanize(p.Cooldown))
}

// readsDurations reports whether the version this run found reads a duration
// string. A version nobody could establish is not one of them: crediting a reading
// this run cannot confirm is how a 4.10 project gets told it waits three days.
func (y YarnMinimalAgeGate) readsDurations(p *Params) bool {
	return p.VersionExact && p.Version != "" && CompareVersions(p.Version, y.DurationSince) >= 0
}

// defaulted reports whether this run may credit Yarn's own default.
func (y YarnMinimalAgeGate) defaulted(p *Params) bool {
	if y.Default <= 0 {
		return false
	}
	if y.DefaultSince == "" {
		return true
	}
	return p.VersionExact && p.Version != "" && CompareVersions(p.Version, y.DefaultSince) >= 0
}

// Judge reads the value against the version that will read it.
func (y YarnMinimalAgeGate) Judge(v *configfile.Value, p *Params) (Status, string) {
	if !v.Found() {
		if y.defaulted(p) && y.Default >= p.Cooldown {
			return StatusSet, fmt.Sprintf("not set, and this version waits %s by default, which is at least the %s the policy asks for",
				Humanize(y.Default), Humanize(p.Cooldown))
		}
		return StatusMissing, ""
	}
	switch v.Kind {
	case configfile.KindList:
		return StatusWrong, "a list is not a value npmMinimalAgeGate takes; the packages that skip the wait go in npmPreapprovedPackages"
	case configfile.KindMap:
		return StatusWrong, "a map is not a value npmMinimalAgeGate takes; the per scope form is a key of the same name under npmScopes"
	case configfile.KindBool:
		return StatusWrong, fmt.Sprintf("%s is not a value npmMinimalAgeGate takes; it wants a duration such as 3d, or a count of minutes such as %s", quote(strings.TrimSpace(v.Text)), Minutes.Format(p.Cooldown))
	}
	text := strings.TrimSpace(v.Text)
	have, unit, err := yarnDuration(text)
	if err != nil {
		return StatusWrong, fmt.Sprintf("%s is not a spelling Yarn reads, so the install fails on the configuration rather than waiting. It takes a duration such as 3d or 12h, or a count of minutes such as %s",
			quote(text), Minutes.Format(p.Cooldown))
	}
	// A value with no unit is a count of minutes, which every version reads the
	// same way. Only a unit suffix depends on the version.
	if unit != "" && !y.readsDurations(p) {
		return y.judgeTruncated(text, have, p)
	}
	switch {
	case have == 0:
		return StatusWeak, fmt.Sprintf("%s turns the wait off", quote(text))
	case have < p.Cooldown:
		return StatusWeak, fmt.Sprintf("%s is %s, and the policy asks for %s (%s here)",
			quote(text), Humanize(have), Humanize(p.Cooldown), Minutes.Format(p.Cooldown))
	default:
		return StatusSet, fmt.Sprintf("%s is %s", quote(text), Humanize(have))
	}
}

// judgeTruncated is the case Yarn 4.10 creates: a duration string read by parseInt,
// which keeps the leading digits and drops the unit. The file says one thing and
// the install does another, so the sentence leads with what it really waits.
func (y YarnMinimalAgeGate) judgeTruncated(text string, meant time.Duration, p *Params) (Status, string) {
	truncated := yarnParseInt(text)
	if !p.VersionExact || p.Version == "" {
		return StatusWeak, fmt.Sprintf("%s is %s on Yarn %s and later, but this run could not establish the version, and anything before %s reads it with parseInt, which keeps the digits and drops the unit: %s. Write %s, the count of minutes every version reads the same way",
			quote(text), Humanize(meant), y.DurationSince, y.DurationSince, Humanize(truncated), Minutes.Format(p.Cooldown))
	}
	return StatusWrong, fmt.Sprintf("Yarn %s reads this setting with parseInt, which keeps the digits and drops the unit, so %s is %s rather than the %s it reads as. Yarn %s and later read the duration; on this version write %s, the count of minutes",
		p.Version, quote(text), Humanize(truncated), Humanize(meant), y.DurationSince, Minutes.Format(p.Cooldown))
}

// yarnDurationPattern is Yarn's own, from miscUtils: a number, optionally
// fractional, with an optional unit. The alternation is ordered as Yarn orders it,
// so ms is matched before m.
var yarnDurationPattern = regexp.MustCompile(`^([0-9]*\.?[0-9]+)(ms|s|m|h|d|w)?$`)

// yarnDuration reads the value the way Yarn 4.11 and later read it, and returns the
// unit it found so the caller can tell a version-dependent value from one that is
// not. A value with no unit is a count of minutes, which is this setting's unit.
func yarnDuration(text string) (time.Duration, string, error) {
	m := yarnDurationPattern.FindStringSubmatch(text)
	if m == nil {
		return 0, "", fmt.Errorf("not a duration Yarn reads")
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, "", fmt.Errorf("not a duration Yarn reads")
	}
	per := time.Minute
	switch m[2] {
	case "ms":
		per = time.Millisecond
	case "s":
		per = time.Second
	case "m", "":
		per = time.Minute
	case "h":
		per = time.Hour
	case "d":
		per = 24 * time.Hour
	case "w":
		per = 7 * 24 * time.Hour
	}
	return time.Duration(n * float64(per)), m[2], nil
}

// yarnParseInt is JavaScript's parseInt over the leading digits, which is what the
// versions before the duration type do with a value that has a unit on it.
func yarnParseInt(text string) time.Duration {
	end := 0
	for end < len(text) && text[end] >= '0' && text[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.ParseInt(text[:end], 10, 64)
	if err != nil {
		return 0
	}
	return time.Duration(n) * time.Minute
}
