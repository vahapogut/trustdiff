package doctor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
)

// DenoMinimumAge judges deno.json's minimumDependencyAge, which takes more
// spellings than anything else this package reads. Deno's own reference lists
// them: "The value accepts an ISO-8601 duration such as P3D or PT72H, a number of
// minutes (120), an absolute cutoff date (2025-09-16) or RFC3339 timestamp, or 0
// to disable", and the value may instead be an object with an age and an exclude
// list of packages the wait does not apply to
// (https://docs.deno.com/runtime/reference/deno_json/, read 2026-09-10).
//
// One unit cannot read five spellings, and MinimumAge has one. Reading them with
// the ISO 8601 unit alone reported four values Deno accepts and acts on as
// mistakes, and told a writer who had correctly used Deno's own minutes that they
// had written pnpm's unit by accident.
//
// The absolute spellings are read by cutoff.go, which uv's rule shares.
type DenoMinimumAge struct {
	// Default is what Deno waits when the key is absent, and DefaultSince the
	// version that arrived in, read the same way MinimumAge reads them.
	Default      time.Duration
	DefaultSince string
}

// Want is the spelling a fix writes: the ISO 8601 one, which the documentation
// leads with and which cannot be mistaken for another manager's unit.
func (DenoMinimumAge) Want(p *Params) configfile.Literal {
	return configfile.String(ISO8601.Format(p.Cooldown))
}

// Describe says what the setting should hold.
func (DenoMinimumAge) Describe(p *Params) string {
	return ISO8601.Format(p.Cooldown)
}

// defaulted reports whether this run may credit Deno's own default.
func (d DenoMinimumAge) defaulted(p *Params) bool {
	if d.Default <= 0 {
		return false
	}
	if d.DefaultSince == "" {
		return true
	}
	return p.VersionExact && p.Version != "" && CompareVersions(p.Version, d.DefaultSince) >= 0
}

// Judge reads whichever spelling the file used.
func (d DenoMinimumAge) Judge(v *configfile.Value, p *Params) (Status, string) {
	if !v.Found() {
		if d.defaulted(p) && d.Default >= p.Cooldown {
			return StatusSet, fmt.Sprintf("not set, and this version waits %s by default, which is at least the %s the policy asks for",
				Humanize(d.Default), Humanize(p.Cooldown))
		}
		return StatusMissing, ""
	}
	if v.Kind == configfile.KindMap {
		return d.judgeObject(v, p)
	}
	if v.Kind == configfile.KindList {
		// Deno reads a scalar or an object here and nothing else, so a list is a
		// file Deno will refuse rather than a wait of any length.
		return StatusWrong, "a list is not a value minimumDependencyAge takes, so Deno will not read this configuration"
	}
	return d.judgeScalar(strings.TrimSpace(v.Text), p, "")
}

// judgeObject reads the age out of the object form. The exclude list beside it is
// not this rule's business: it names the packages a project decided to let
// through, which is a judgment, and the scorecard says how many rather than
// arguing with them.
func (d DenoMinimumAge) judgeObject(v *configfile.Value, p *Params) (Status, string) {
	// The keys are read as written, because Deno reads them as written and Go's
	// json decoder does not: it matches a field name case-insensitively, so a
	// decode into a struct would accept an "Age" that Deno ignores.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(v.Raw), &raw); err != nil {
		return StatusUnreadable, fmt.Sprintf("minimumDependencyAge is an object this reader could not parse: %v", err)
	}
	suffix := ""
	if excluded, ok := raw["exclude"]; ok {
		var names []string
		if err := json.Unmarshal(excluded, &names); err == nil && len(names) > 0 {
			word := "packages are"
			if len(names) == 1 {
				word = "package is"
			}
			suffix = fmt.Sprintf(". %d %s exempt from the wait", len(names), word)
		}
	}
	age, ok := raw["age"]
	if !ok {
		if d.defaulted(p) && d.Default >= p.Cooldown {
			return StatusSet, fmt.Sprintf("the object states no age, and this version waits %s by default, which is at least the %s the policy asks for%s",
				Humanize(d.Default), Humanize(p.Cooldown), suffix)
		}
		return StatusWeak, "the object states no age, so nothing sets the wait" + suffix
	}
	var text string
	if err := json.Unmarshal(age, &text); err != nil {
		var minutes json.Number
		if err := json.Unmarshal(age, &minutes); err != nil {
			return StatusWrong, fmt.Sprintf("the object's age is neither a string nor a number, so Deno will not read it%s", suffix)
		}
		text = minutes.String()
	}
	return d.judgeScalar(strings.TrimSpace(text), p, suffix)
}

// judgeScalar reads one of the four scalar spellings and compares what it buys
// with the policy's cooldown.
func (d DenoMinimumAge) judgeScalar(text string, p *Params, suffix string) (Status, string) {
	if text == "" {
		return StatusWrong, "the value is empty, so Deno has no wait to read" + suffix
	}
	have, spelling, err := denoWait(text, p.Now)
	if err != nil {
		return StatusWrong, fmt.Sprintf("%s is not a spelling Deno reads, so nothing waits. It takes an ISO 8601 duration such as %s, a number of minutes such as %s, a date or an RFC 3339 timestamp, or 0 to turn the wait off%s",
			quote(text), ISO8601.Format(p.Cooldown), Minutes.Format(p.Cooldown), suffix)
	}
	switch {
	case have == 0:
		return StatusWeak, fmt.Sprintf("%s turns the wait off%s", quote(text), suffix)
	case have < p.Cooldown:
		return StatusWeak, fmt.Sprintf("%s is %s%s, and the policy asks for %s (%s here)%s",
			quote(text), Humanize(have), spelling, Humanize(p.Cooldown), ISO8601.Format(p.Cooldown), suffix)
	default:
		return StatusSet, fmt.Sprintf("%s is %s%s%s", quote(text), Humanize(have), spelling, suffix)
	}
}

// denoWait reads one scalar spelling and returns what it makes an install wait,
// with a clause naming the spelling where the number alone would not say.
//
// now is the run clock, which an absolute cutoff needs and the other spellings do
// not. A zero clock can only come from a caller inside this package that built
// Params by hand; the command always sets it.
func denoWait(text string, now time.Time) (wait time.Duration, spelling string, err error) {
	if minutes, err := strconv.ParseInt(text, 10, 64); err == nil {
		if minutes < 0 {
			return 0, "", fmt.Errorf("negative")
		}
		// A number large enough to overflow a duration is still a value Deno takes
		// and is longer than any policy asks for, so it is what it says rather than
		// the negative a multiplication would produce.
		if minutes > int64(maxDuration/time.Minute) {
			return maxDuration, " in minutes", nil
		}
		return time.Duration(minutes) * time.Minute, " in minutes", nil
	}
	if d, err := ISO8601.Parse(text); err == nil {
		return d, "", nil
	}
	wait, cutoff, err := cutoffWait(text, now)
	if err != nil {
		return 0, "", err
	}
	if wait < 0 {
		// A cutoff nothing has reached yet excludes nothing, which is a wait of no
		// time rather than a negative one.
		wait = 0
	}
	return wait, cutoffSpelling(cutoff), nil
}

// maxDuration is the longest time.Duration, about 292 years.
const maxDuration = time.Duration(1<<63 - 1)
