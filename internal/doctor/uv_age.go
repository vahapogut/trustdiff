package doctor

import (
	"fmt"
	"strings"
	"time"

	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/policy"
)

// UvExcludeNewer judges uv's exclude-newer, which takes a length of time or a point
// in one. uv's own reference for the option lists all of it: "Accepts RFC 3339
// timestamps (e.g., 2006-12-02T02:07:43Z), local dates in the same format (e.g.,
// 2006-12-02) resolved based on your system's configured time zone, a "friendly"
// duration (e.g., 24 hours, 1 week, 30 days), or an ISO 8601 duration (e.g., PT24H,
// P7D, P30D)", and the settings page adds "Set to false to disable exclude-newer"
// (https://docs.astral.sh/uv/reference/settings/#exclude-newer and
// https://docs.astral.sh/uv/reference/cli/, both read 2026-09-10).
//
// The rule read the friendly duration and nothing else, so the timestamp form was
// reported as a mistake. That is the strongest thing this key takes: a fixed point
// every resolution is measured against, which is what a project writes when it
// wants the resolution to hold still instead of rolling forward with the clock.
// Telling such a project to replace it with "3 days" is advice that undoes the
// reason the line is there.
type UvExcludeNewer struct{}

// Want is the spelling a fix writes: the words, which is what uv's own
// documentation leads with and what it records into uv.lock.
func (UvExcludeNewer) Want(p *Params) configfile.Literal {
	return configfile.String(Words.Format(p.Cooldown))
}

// Describe says what the setting should hold.
func (UvExcludeNewer) Describe(p *Params) string { return Words.Format(p.Cooldown) }

// Judge reads whichever spelling the file used.
func (u UvExcludeNewer) Judge(v *configfile.Value, p *Params) (Status, string) {
	if !v.Found() {
		return StatusMissing, ""
	}
	switch v.Kind {
	case configfile.KindList:
		return StatusWrong, "a list is not a value exclude-newer takes, so uv will not read this configuration"
	case configfile.KindMap:
		return StatusWrong, "a table is not a value exclude-newer takes; the per package form is a table under exclude-newer-package, which is a key of its own"
	case configfile.KindBool:
		if strings.EqualFold(strings.TrimSpace(v.Text), "false") {
			return StatusWeak, "false turns the wait off, which uv documents as the way to disable exclude-newer"
		}
		return StatusWrong, "true is not a value exclude-newer takes; it wants a duration such as \"3 days\", or a date to hold the resolution at"
	}
	return u.judgeScalar(strings.TrimSpace(v.Text), p)
}

// judgeScalar reads one spelling and compares what it buys with the cooldown.
func (u UvExcludeNewer) judgeScalar(text string, p *Params) (Status, string) {
	if text == "" {
		return StatusWrong, "the value is empty, so uv has no cutoff to read"
	}
	have, spelling, future, err := uvWait(text, p.Now)
	if err != nil {
		return StatusWrong, fmt.Sprintf("%s is not a spelling uv reads, so nothing is excluded. It takes a duration such as %s or %s, an RFC 3339 timestamp, or a date such as %s",
			quote(text), quote(Words.Format(p.Cooldown)), quote(ISO8601.Format(p.Cooldown)), quote(exampleCutoff))
	}
	switch {
	case future:
		return StatusWeak, fmt.Sprintf("the cutoff %s is in the future, so it excludes nothing: every release published up to it resolves, including one published a minute ago", quote(text))
	case have == 0:
		return StatusWeak, fmt.Sprintf("%s turns the wait off", quote(text))
	case have < p.Cooldown:
		return StatusWeak, fmt.Sprintf("%s is %s%s, and the policy asks for %s (%s here)",
			quote(text), Humanize(have), spelling, Humanize(p.Cooldown), Words.Format(p.Cooldown))
	default:
		return StatusSet, fmt.Sprintf("%s is %s%s", quote(text), Humanize(have), spelling)
	}
}

// exampleCutoff is the date uv's own documentation writes, so the sentence that
// tells somebody what to write quotes the source rather than inventing a shape.
const exampleCutoff = "2006-12-02"

// uvWait reads one scalar spelling and returns what it excludes. future is true
// where the value is a cutoff nothing has reached yet, which is not the same as a
// wait of no time: the setting is doing nothing today and will do something later.
//
// The cutoff spellings are tried first because they cannot be read as a duration,
// while a duration parser given a date can produce a number that means nothing.
func uvWait(text string, now time.Time) (wait time.Duration, spelling string, future bool, err error) {
	if wait, cutoff, err := cutoffWait(text, now); err == nil {
		if wait < 0 {
			return 0, "", true, nil
		}
		return wait, cutoffSpelling(cutoff), false, nil
	}
	// The words and the ISO 8601 form, which is what uv's documentation lists.
	if d, err := Words.Parse(text); err == nil {
		return d, "", false, nil
	}
	// uv reads its durations with jiff, whose friendly format also takes the
	// abbreviated spellings, 3d and 12h, so this reads them too. A value uv accepts
	// and acts on is not a mistake because the documentation's examples are longer.
	if d, err := policy.ParseDuration(text); err == nil {
		return d, "", false, nil
	}
	return 0, "", false, fmt.Errorf("not a duration, a date or a timestamp")
}
