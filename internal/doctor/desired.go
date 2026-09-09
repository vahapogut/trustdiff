package doctor

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
)

// MinimumAge is a setting that says how long a release must have been public
// before the manager will install it. It is the same idea as the young-version
// check, enforced by the package manager itself, and the reason doctor exists: it
// is the one setting that stops a compromised release before anything is fetched.
//
// The value asked for is the project's own cooldown, converted into the unit the
// manager counts in, so a project that decided three days is never told to
// configure seven.
type MinimumAge struct {
	// Unit is how this manager writes the value.
	Unit Unit
	// Quoted is true when the format needs the value in quotes even though it is a
	// number, which is how Deno and pip write an ISO 8601 duration.
	Quoted bool
	// Default is what the manager does when the key is absent, zero when it does
	// nothing. pnpm 11 and Deno 2.9 both have one, and a project that relies on it
	// is protected until somebody pins an older version.
	Default time.Duration
	// DefaultSince is the version the default arrived in. An older version has no
	// default, and a version nobody could detect is credited with none either: a
	// scorecard that assumed the newest release would tell a project pinned to an
	// older one that it is protected when it is not.
	DefaultSince string
}

// defaulted reports whether this run may credit the manager's own default.
func (m MinimumAge) defaulted(p Params) bool {
	if m.Default <= 0 {
		return false
	}
	if m.DefaultSince == "" {
		return true
	}
	return p.VersionExact && p.Version != "" && CompareVersions(p.Version, m.DefaultSince) >= 0
}

// Want is the project's cooldown in this manager's unit.
func (m MinimumAge) Want(p Params) configfile.Literal {
	text := m.Unit.Format(p.Cooldown)
	if m.Quoted {
		return configfile.String(text)
	}
	if _, err := strconv.ParseInt(text, 10, 64); err == nil {
		return configfile.Literal{Kind: configfile.KindInt, Text: text}
	}
	return configfile.String(text)
}

// Describe says what the setting should hold, for a scorecard line about a value
// that is not there.
func (m MinimumAge) Describe(p Params) string {
	text := m.Unit.Format(p.Cooldown)
	if words := Humanize(p.Cooldown); text != words {
		// A number alone says nothing, so the value is followed by what it means.
		// The unit that writes the duration in words needs no such translation.
		return fmt.Sprintf("%s, which is %s", text, words)
	}
	return text
}

// Judge reads what the file holds and decides. A value that is present and too
// small is worse than one that is missing, because somebody set it and believes
// they are protected, so the detail says what it really means and, when the number
// would be right in another manager's unit, says that too.
func (m MinimumAge) Judge(v *configfile.Value, p Params) (Status, string) {
	if !v.Found() {
		if m.defaulted(p) && m.Default >= p.Cooldown {
			return StatusSet, fmt.Sprintf("not set, and this version waits %s by default, which is at least the %s the policy asks for",
				Humanize(m.Default), Humanize(p.Cooldown))
		}
		return StatusMissing, ""
	}
	text := strings.TrimSpace(v.Text)
	have, err := m.Unit.Parse(text)
	if err != nil {
		return StatusWrong, fmt.Sprintf("%s: %v%s", quote(text), err, m.unitConfusion(text))
	}
	switch {
	case have == 0:
		return StatusWrong, fmt.Sprintf("%s turns the wait off", quote(text))
	case have < p.Cooldown:
		return StatusWrong, fmt.Sprintf("%s is %s, and the policy asks for %s (%s here)%s",
			quote(text), Humanize(have), Humanize(p.Cooldown), m.Unit.Format(p.Cooldown), m.unitConfusion(text))
	default:
		return StatusSet, fmt.Sprintf("%s is %s", quote(text), Humanize(have))
	}
}

// unitConfusion is the sentence that turns a number nobody can read into the
// mistake it probably is. 10080 in bunfig.toml is a week counted in minutes, which
// is pnpm's unit, and Bun reads it as under three hours. Saying so is the whole
// difference between a scorecard and a linter.
func (m MinimumAge) unitConfusion(text string) string {
	n, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	for _, other := range []struct {
		unit    Unit
		writers string
	}{
		{Days, "npm and Poetry count"},
		{Minutes, "pnpm and Yarn count"},
		{Seconds, "Bun counts"},
	} {
		if other.unit.Name() == m.Unit.Name() {
			continue
		}
		d, err := other.unit.Parse(text)
		if err != nil || !roundDuration(d) {
			continue
		}
		return fmt.Sprintf(". %d is %s in %s, the unit %s in",
			n, Humanize(d), other.unit.Name(), other.writers)
	}
	return ""
}

// commonWaits are the cooldowns people actually write: a day, a few days, a week,
// a fortnight, a month. The sentence above fires only when the number reads as one
// of these in another manager's unit, because every number reads as something in
// some unit and a tool that said so every time would be ignored. 60 in a file that
// counts minutes is sixty days in npm's unit, and nobody meant that; 10080 in a
// file that counts seconds is a week in pnpm's, and somebody certainly did.
var commonWaits = []time.Duration{
	24 * time.Hour,
	2 * 24 * time.Hour,
	3 * 24 * time.Hour,
	5 * 24 * time.Hour,
	7 * 24 * time.Hour,
	10 * 24 * time.Hour,
	14 * 24 * time.Hour,
	30 * 24 * time.Hour,
}

// roundDuration reports whether a duration is one of the waits people write.
func roundDuration(d time.Duration) bool {
	for _, want := range commonWaits {
		if d == want {
			return true
		}
	}
	return false
}

// BoolSetting is a setting that is either on or off, such as pnpm's
// strictDepBuilds or Deno's frozen lockfile.
type BoolSetting struct {
	// On is the value that hardens the project.
	On bool
	// Default is what the manager does when the key is absent, and Defaulted says
	// whether there is one at all.
	Default   bool
	Defaulted bool
	// DefaultSince is the version the default arrived in, empty when the manager
	// has always behaved this way. An older version, and a version nobody could
	// detect, are credited with no default.
	DefaultSince string
}

// defaulted reports whether this run may credit the manager's own default.
func (b BoolSetting) defaulted(p Params) bool {
	if !b.Defaulted {
		return false
	}
	if b.DefaultSince == "" {
		return true
	}
	return p.VersionExact && p.Version != "" && CompareVersions(p.Version, b.DefaultSince) >= 0
}

// Want is the hardened value.
func (b BoolSetting) Want(Params) configfile.Literal { return configfile.Bool(b.On) }

// Describe says which value the rule asks for.
func (b BoolSetting) Describe(Params) string { return strconv.FormatBool(b.On) }

// Judge accepts the boolean the file holds, and the strings "true" and "false",
// which is how an ini file and a quoted YAML value spell one.
func (b BoolSetting) Judge(v *configfile.Value, p Params) (Status, string) {
	if !v.Found() {
		if b.defaulted(p) && b.Default == b.On {
			return StatusSet, fmt.Sprintf("not set, and this version defaults to %t", b.Default)
		}
		return StatusMissing, ""
	}
	text := strings.ToLower(strings.TrimSpace(v.Text))
	switch text {
	case "true", "yes", "1":
		if b.On {
			return StatusSet, ""
		}
		return StatusWrong, "set to true, and this should be false"
	case "false", "no", "0":
		if !b.On {
			return StatusSet, ""
		}
		return StatusWrong, "set to false, and this should be true"
	}
	return StatusWrong, fmt.Sprintf("%s is not true or false", quote(v.Text))
}

// EnumSetting is a setting whose value comes from a fixed set, such as pnpm's
// trustPolicy or Yarn's checksumBehavior.
type EnumSetting struct {
	// Want is the value the rule asks for.
	Value string
	// Accepted are the other values the manager takes, so a value outside the set
	// can be reported as a typo rather than as a weaker choice.
	Accepted []string
	// Weaker explains, in one clause, what the values other than Want give up.
	Weaker string
	// Default is what the manager does when the key is absent, empty when it does
	// nothing, and DefaultSince is the version that default arrived in. Yarn
	// already throws on a checksum mismatch and npm 12 already refuses a git
	// dependency, and telling those projects to write a line that changes nothing
	// is how a scorecard loses a reader.
	Default      string
	DefaultSince string
}

// defaulted reports whether this run may credit the manager's own default.
func (e EnumSetting) defaulted(p Params) bool {
	if e.Default == "" {
		return false
	}
	if e.DefaultSince == "" {
		return true
	}
	return p.VersionExact && p.Version != "" && CompareVersions(p.Version, e.DefaultSince) >= 0
}

// Want is the value to write.
func (e EnumSetting) Want(Params) configfile.Literal { return configfile.String(e.Value) }

// Describe names the value the rule asks for.
func (e EnumSetting) Describe(Params) string { return e.Value }

// Judge compares the text, and says whether an unexpected value is one of the
// manager's own or a spelling mistake.
func (e EnumSetting) Judge(v *configfile.Value, p Params) (Status, string) {
	if !v.Found() {
		if e.defaulted(p) && e.Default == e.Value {
			return StatusSet, fmt.Sprintf("not set, and this version defaults to %s", e.Default)
		}
		return StatusMissing, ""
	}
	text := strings.TrimSpace(v.Text)
	if text == e.Value {
		return StatusSet, ""
	}
	for _, accepted := range e.Accepted {
		if text == accepted {
			detail := fmt.Sprintf("set to %s", quote(text))
			if e.Weaker != "" {
				detail += ", which " + e.Weaker
			}
			return StatusWrong, detail
		}
	}
	return StatusWrong, fmt.Sprintf("%s is not a value %s accepts", quote(text), strings.Join(append([]string{e.Value}, e.Accepted...), ", "))
}

// Advice is a rule with nothing to write: a manager that has no such setting yet,
// or a recommendation that is a human decision. It always reports not applicable,
// and the scorecard prints the rule's note.
type Advice struct{}

// Want is nothing, because an advisory rule writes nothing.
func (Advice) Want(Params) configfile.Literal { return configfile.Literal{} }

// Describe says there is nothing to set.
func (Advice) Describe(Params) string { return "nothing to set" }

// Judge always reports advice, whatever the file holds: there is no value to
// compare against, and the rule's note is what the reader is here for.
func (Advice) Judge(*configfile.Value, Params) (Status, string) { return StatusAdvice, "" }

// quote writes a value the way a message should show it, so an empty string and a
// string of spaces are visible.
func quote(s string) string {
	if strings.TrimSpace(s) == "" {
		return strconv.Quote(s)
	}
	return s
}
