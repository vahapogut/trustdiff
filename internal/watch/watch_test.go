package watch

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/report"
)

var testRef = model.MustParseRef("npm:example@1.0.0")

func observation(findings []model.Finding, skipped ...model.Skipped) *report.Report {
	evaluated := []string{"TD001", "TD003", "TD009"}
	for _, skip := range skipped {
		for i, id := range evaluated {
			if id == skip.Check {
				evaluated = append(evaluated[:i], evaluated[i+1:]...)
				break
			}
		}
	}
	return report.Build([]report.Subject{{Ref: testRef, Evaluated: evaluated, Findings: findings, Skipped: skipped}},
		report.Tool{}, report.Policy{}, model.LevelWarn)
}

func finding(id string, evidence map[string]any) model.Finding {
	return model.Finding{ID: id, Ref: testRef, Level: model.LevelBlock, Evidence: evidence}
}

func runObservations(t *testing.T, reports ...*report.Report) []Event {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	index, waits := 0, 0
	events := []Event{}
	clock := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	loop := Loop{
		Interval: time.Hour, Now: func() time.Time { return clock.Add(time.Duration(index) * time.Hour) },
		Wait: func(ctx context.Context, d time.Duration) error {
			if index != waits+1 || d != time.Hour {
				t.Fatalf("wait before completed evaluation: index=%d waits=%d duration=%s", index, waits, d)
			}
			waits++
			if index == len(reports) {
				cancel()
				return ctx.Err()
			}
			return nil
		},
	}
	_, err := loop.Run(ctx, func(context.Context) (*report.Report, error) {
		if index >= len(reports) {
			t.Fatal("evaluation after canceled wait")
		}
		r := reports[index]
		index++
		return r, nil
	}, func(e Event) error { events = append(events, e); return nil })
	if !errors.Is(err, context.Canceled) || waits != len(reports) {
		t.Fatalf("err=%v waits=%d", err, waits)
	}
	return events
}

func TestRepeatedEvaluationDetectsAdvisoryAndCoverageChanges(t *testing.T) {
	malicious := finding("TD009", map[string]any{"advisories": []string{"MAL-2026-1"}})
	down := model.Skipped{Check: "TD009", Reason: "osv: connection refused"}
	events := runObservations(t,
		observation(nil), observation(nil), observation([]model.Finding{malicious}),
		observation(nil, down), observation(nil, down), observation([]model.Finding{malicious}), observation(nil))
	var got []string
	for _, e := range events {
		if e.Schema != SchemaID || e.Report == nil || e.ObservedAt.IsZero() || e.Changes == nil {
			t.Fatalf("incomplete event: %+v", e)
		}
		got = append(got, e.Kind)
		for _, change := range e.Changes {
			got = append(got, change.Kind)
		}
	}
	want := []string{"initial", "changed", "findings_added", "changed", "coverage_lost", "changed", "coverage_restored", "changed", "findings_cleared"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events=%v, want %v", got, want)
	}
}

func TestElapsedTimeAndOrderingDoNotEmitChanges(t *testing.T) {
	young := func(age int) model.Finding {
		f := finding("TD001", map[string]any{"age": age, "age_seconds": age, "cooldown_seconds": 259200, "published_at": "2026-09-28T12:00:00Z"})
		f.Title = time.Duration(age).String()
		return f
	}
	owners := func(age int, reversed bool) model.Finding {
		evidence := map[string]any{}
		if reversed {
			evidence["baseline_age_days"] = age
			evidence["added"] = []string{"bob"}
		} else {
			evidence["added"] = []string{"bob"}
			evidence["baseline_age_days"] = age
		}
		return finding("TD003", evidence)
	}
	events := runObservations(t,
		observation([]model.Finding{young(3600), owners(1, false)}),
		observation([]model.Finding{owners(2, true), young(7200)}),
		observation([]model.Finding{owners(3, true)}))
	if len(events) != 2 || len(events[1].Changes) != 1 || events[1].Changes[0].Check != "TD001" || events[1].Changes[0].Kind != "findings_cleared" {
		t.Fatalf("elapsed age or order produced a change, or cooldown was not cleared: %+v", events)
	}
}

func TestChangesHaveDeterministicPackageAndCheckOrder(t *testing.T) {
	refs := []model.PackageRef{model.MustParseRef("npm:zulu@1.0.0"), model.MustParseRef("cargo:alpha@1.0.0")}
	build := func(changed bool, reverse bool) *report.Report {
		subjects := make([]report.Subject, 0, len(refs))
		for _, ref := range refs {
			s := report.Subject{Ref: ref, Evaluated: []string{"TD009", "TD003"}}
			if changed {
				s.Findings = []model.Finding{finding("TD009", nil), finding("TD003", nil)}
			}
			subjects = append(subjects, s)
		}
		if reverse {
			subjects[0], subjects[1] = subjects[1], subjects[0]
		}
		return report.Build(subjects, report.Tool{}, report.Policy{}, model.LevelBlock)
	}
	first := runObservations(t, build(false, false), build(true, false))
	second := runObservations(t, build(false, true), build(true, true))
	if !reflect.DeepEqual(first[1].Changes, second[1].Changes) {
		t.Fatal("changes depend on subject order")
	}
	got := first[1].Changes
	if len(got) != 4 || got[0].Ref.Ecosystem != model.Cargo || got[0].Check != "TD003" || got[1].Check != "TD009" {
		t.Fatalf("not sorted by package then check: %+v", got)
	}
}

func TestOnceReturnsFindingsAndUnavailableStatusWithoutWaiting(t *testing.T) {
	for _, code := range []int{0, 1, 3} {
		t.Run(report.ExitMeaning(code), func(t *testing.T) {
			rep := observation(nil)
			rep.SetExitCode(code)
			calls, emitted := 0, 0
			loop := Loop{Once: true, Interval: MinInterval, Wait: func(context.Context, time.Duration) error {
				t.Fatal("once waited")
				return nil
			}}
			got, err := loop.Run(context.Background(), func(context.Context) (*report.Report, error) {
				calls++
				return rep, nil
			}, func(Event) error { emitted++; return nil })
			if err != nil || got != code || calls != 1 || emitted != 1 {
				t.Fatalf("code=%d err=%v calls=%d emitted=%d", got, err, calls, emitted)
			}
		})
	}
}

func TestIntervalValidationBeforeEvaluation(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Hour, time.Second, MaxInterval + 1} {
		loop := Loop{Once: true, Interval: interval}
		if _, err := loop.Run(context.Background(), func(context.Context) (*report.Report, error) {
			t.Fatal("invalid interval evaluated")
			return nil, nil
		}, func(Event) error { t.Fatal("invalid interval emitted"); return nil }); err == nil {
			t.Fatalf("accepted %s", interval)
		}
	}
}

func TestCancelDuringEvaluationEmitsNoIncompleteReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loop := Loop{Interval: MinInterval}
	_, err := loop.Run(ctx, func(context.Context) (*report.Report, error) {
		cancel()
		return observation(nil), nil
	}, func(Event) error { t.Fatal("canceled evaluation emitted"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestCancelInterruptsWaitingAndOutputErrorStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loop := Loop{Interval: MaxInterval}
	calls := 0
	_, err := loop.Run(ctx, func(context.Context) (*report.Report, error) {
		calls++
		return observation(nil), nil
	}, func(Event) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancellation after output: calls=%d err=%v", calls, err)
	}
	want := errors.New("broken output")
	_, err = loop.Run(context.Background(), func(context.Context) (*report.Report, error) {
		return observation(nil), nil
	}, func(Event) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("output error lost: %v", err)
	}
}

func TestGuardDogSupplementChangesRemainAttributedAndCoverageAware(t *testing.T) {
	analyzed := func(status, evidence string) *report.Report {
		rep := observation(nil)
		rep.GuardDogRequested = true
		rep.GuardDog = []model.Analysis{{
			Ref: testRef, Source: "https://github.com/DataDog/guarddog", Status: status,
			Results: map[string]json.RawMessage{"rule": json.RawMessage(evidence)},
		}}
		return rep
	}
	events := runObservations(t,
		analyzed("completed", `{"a":1,"b":2}`), analyzed("completed", `{"b":2,"a":1}`),
		analyzed("partial", `{"a":1}`), analyzed("partial", `{"a":2}`),
		analyzed("completed", `{"a":2}`), observation(nil))
	if len(events) != 5 {
		t.Fatalf("events=%+v", events)
	}
	want := []string{"coverage_lost", "analysis_changed", "coverage_restored", "analysis_not_requested"}
	for i, kind := range want {
		changes := events[i+1].Changes
		if len(changes) != 1 || changes[0].Check != "guarddog" || changes[0].Kind != kind {
			t.Fatalf("event %d changes=%+v want=%s", i+1, changes, kind)
		}
	}
}
