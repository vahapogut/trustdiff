package doctor

import (
	"fmt"
	"time"
)

// A cutoff is the other way these settings are written. Deno's
// minimumDependencyAge and uv's exclude-newer both take a length of time or a point
// in it, and a point is what a project writes when it wants a resolution to hold
// still rather than to roll forward with the clock.
//
// A policy asks for a length, so the two have to be compared through the clock the
// run started on: a cutoff blocks everything published after it, so what it buys
// today is at least now minus the cutoff. That understates it, because it also
// blocks a release older than the wait but newer than the cutoff, and understating
// in the direction of asking for more is the side to err on.

// cutoffWait reads the two absolute spellings both managers document, an RFC 3339
// timestamp and a plain date, and says how much wait the cutoff buys by now. The
// answer is signed: a cutoff in the future excludes nothing, and the caller says so
// in its own words rather than being handed a zero it cannot tell from a real one.
func cutoffWait(text string, now time.Time) (wait time.Duration, cutoff time.Time, err error) {
	cutoff, err = parseCutoff(text)
	if err != nil {
		return 0, time.Time{}, err
	}
	if now.IsZero() {
		return 0, cutoff, fmt.Errorf("no run clock to compare a cutoff with")
	}
	return now.Sub(cutoff), cutoff, nil
}

// parseCutoff reads a point in time in either spelling. A plain date is read as
// UTC although both managers resolve it in the machine's own zone, because the
// machine that runs this tool is not necessarily the one that runs the install. The
// gap is under a day and it falls the safe way: a zone ahead of UTC puts the real
// cutoff earlier, so the wait it buys is longer than the one reported here.
func parseCutoff(text string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, text); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("not a date or an RFC 3339 timestamp")
}

// cutoffSpelling is the clause that turns a length of time back into the date it
// was read from, so a scorecard line about a cutoff says which cutoff.
func cutoffSpelling(cutoff time.Time) string {
	return fmt.Sprintf(" of waiting, counted from the cutoff %s", cutoff.UTC().Format("2006-01-02"))
}
