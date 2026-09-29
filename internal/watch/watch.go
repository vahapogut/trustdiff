// Package watch schedules repeated evaluations and reports changes in their
// findings and coverage. It never reads or writes a project's approved baseline.
package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/report"
)

const (
	// SchemaID identifies the newline-delimited watch event format.
	SchemaID = "trustdiff.watch/1"
	// MinInterval bounds the shortest delay between completed evaluations.
	MinInterval = time.Minute
	// MaxInterval bounds the longest delay between completed evaluations.
	MaxInterval = 24 * time.Hour
	// DefaultInterval is the delay when the user supplies none.
	DefaultInterval = time.Hour
)

// Event contains a complete current report and the changes since the preceding
// evaluation. An initial event has no predecessor and an empty Changes array.
type Event struct {
	Schema     string         `json:"schema"`
	Kind       string         `json:"kind"`
	ObservedAt time.Time      `json:"observed_at"`
	Changes    []Change       `json:"changes"`
	Report     *report.Report `json:"report"`
}

// Change names a changed check. Cleared means a completed check no longer has
// findings; coverage_lost means its current result is unknown, never resolved.
type Change struct {
	Ref   model.PackageRef `json:"ref"`
	Check string           `json:"check"`
	Kind  string           `json:"kind"`
}

// Loop controls a serial monitor. Now and Wait may be supplied by deterministic
// tests; production uses the wall clock and a context-aware timer.
type Loop struct {
	Interval time.Duration
	Once     bool
	Now      func() time.Time
	Wait     func(context.Context, time.Duration) error
}

// Run emits the first evaluation and subsequent changes. It waits only after an
// evaluation completes, so slow requests never create overlapping runs or a
// backlog. Once returns the report's exit code. A continuous run ends on a
// context, evaluation or output error, leaving the caller to choose its exit code.
func (l Loop) Run(ctx context.Context, evaluate func(context.Context) (*report.Report, error), emit func(Event) error) (int, error) {
	if l.Interval < MinInterval || l.Interval > MaxInterval {
		return 0, fmt.Errorf("watch interval must be between 1m and 24h")
	}
	now, wait := l.Now, l.Wait
	if now == nil {
		now = time.Now
	}
	if wait == nil {
		wait = waitInterval
	}
	var previous map[checkKey]checkState
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		rep, err := evaluate(ctx)
		if err != nil {
			return 0, err
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if rep == nil {
			return 0, fmt.Errorf("watch evaluation returned no report")
		}
		current, err := snapshot(rep)
		if err != nil {
			return 0, err
		}
		changes := compare(previous, current)
		if previous == nil || len(changes) > 0 {
			kind := "changed"
			if previous == nil {
				kind = "initial"
			}
			if err := emit(Event{Schema: SchemaID, Kind: kind, ObservedAt: now().UTC(), Changes: changes, Report: rep}); err != nil {
				return 0, err
			}
		}
		if l.Once {
			return rep.Summary.ExitCode, nil
		}
		previous = current
		if err := wait(ctx, l.Interval); err != nil {
			return 0, err
		}
	}
}

func waitInterval(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type checkKey struct {
	ref model.PackageRef
	id  string
}

type checkState struct {
	skipped  bool
	reason   string
	findings []string
}

// snapshot compares facts rather than rendered prose. Age counters and their
// prose change while the evidence is the same; a check leaving cooldown still
// changes its finding set and therefore emits a change.
func snapshot(rep *report.Report) (map[checkKey]checkState, error) {
	out := make(map[checkKey]checkState)
	for i := range rep.Subjects {
		s := &rep.Subjects[i]
		for _, id := range s.Evaluated {
			out[checkKey{s.Ref, id}] = checkState{}
		}
		for _, skipped := range s.Skipped {
			out[checkKey{s.Ref, skipped.Check}] = checkState{skipped: true, reason: skipped.Reason}
		}
		for j := range s.Findings {
			f := &s.Findings[j]
			facts := make(map[string]any, len(f.Evidence))
			for key, value := range f.Evidence {
				if key == "baseline_age_days" || (f.ID == "TD001" && (key == "age" || key == "age_seconds")) {
					continue
				}
				facts[key] = value
			}
			encoded, err := json.Marshal(struct {
				Level    model.Level    `json:"level"`
				Evidence map[string]any `json:"evidence"`
			}{f.Level, facts})
			if err != nil {
				return nil, fmt.Errorf("watch finding %s for %s: %w", f.ID, s.Ref, err)
			}
			key := checkKey{s.Ref, f.ID}
			state := out[key]
			state.findings = append(state.findings, string(encoded))
			out[key] = state
		}
	}
	for key, state := range out {
		slices.Sort(state.findings)
		out[key] = state
	}
	for i := range rep.GuardDog {
		analysis := &rep.GuardDog[i]
		encoded, err := json.Marshal(analysis)
		if err != nil {
			return nil, fmt.Errorf("watch GuardDog analysis for %s: %w", analysis.Ref, err)
		}
		// Canonicalize nested RawMessage objects from the external tool too.
		var facts any
		if err := json.Unmarshal(encoded, &facts); err != nil {
			return nil, fmt.Errorf("watch GuardDog evidence for %s: %w", analysis.Ref, err)
		}
		encoded, err = json.Marshal(facts)
		if err != nil {
			return nil, fmt.Errorf("watch GuardDog facts for %s: %w", analysis.Ref, err)
		}
		out[checkKey{analysis.Ref, "guarddog"}] = checkState{
			skipped: analysis.Status != "completed", findings: []string{string(encoded)},
		}
	}
	return out, nil
}

func compare(previous, current map[checkKey]checkState) []Change {
	out := []Change{}
	if previous == nil {
		return out
	}
	keys := make(map[checkKey]bool, len(previous)+len(current))
	for key := range previous {
		keys[key] = true
	}
	for key := range current {
		keys[key] = true
	}
	for key := range keys {
		before, had := previous[key]
		after, have := current[key]
		kind := ""
		switch {
		case key.id == "guarddog":
			kind = analysisChange(before, after, had, have)
		case !have || (after.skipped && had && !before.skipped):
			kind = "coverage_lost"
		case !had || (before.skipped && !after.skipped):
			kind = "coverage_restored"
		case before.skipped && after.skipped && before.reason != after.reason:
			kind = "skip_changed"
		case !before.skipped && !after.skipped && !slices.Equal(before.findings, after.findings):
			kind = "findings_changed"
			if len(before.findings) == 0 {
				kind = "findings_added"
			} else if len(after.findings) == 0 {
				kind = "findings_cleared"
			}
		}
		if kind != "" {
			out = append(out, Change{Ref: key.ref, Check: key.id, Kind: kind})
		}
	}
	slices.SortFunc(out, func(a, b Change) int {
		if a.Ref.String() < b.Ref.String() {
			return -1
		}
		if a.Ref.String() > b.Ref.String() {
			return 1
		}
		if a.Check < b.Check {
			return -1
		}
		if a.Check > b.Check {
			return 1
		}
		return 0
	})
	return out
}

func analysisChange(before, after checkState, had, have bool) string {
	switch {
	case !have:
		return "analysis_not_requested"
	case !had:
		return "analysis_added"
	case after.skipped && !before.skipped:
		return "coverage_lost"
	case before.skipped && !after.skipped:
		return "coverage_restored"
	case !slices.Equal(before.findings, after.findings):
		return "analysis_changed"
	default:
		return ""
	}
}
