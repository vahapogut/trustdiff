package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/baseline"
	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/guarddog"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/report"
	"github.com/vahapogut/trustdiff/internal/watch"
)

// Both releases retain alice in their publication metadata even after current
// ownership has changed. A comparison of releases would miss this takeover.
type watchTestLoader struct {
	*fakeLoader
	owners   []model.Publisher
	ownerErr error
	malware  bool
}

func (w *watchTestLoader) VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	v, err := w.fakeLoader.VersionInfo(ctx, ref)
	if err == nil {
		v.Maintainers = []model.Publisher{{Name: "alice"}}
	}
	return v, err
}

func (w *watchTestLoader) Owners(context.Context, model.Ecosystem, string) ([]model.Publisher, error) {
	return w.owners, w.ownerErr
}

func (w *watchTestLoader) Advisories(context.Context, model.PackageRef) ([]advisory.Advisory, error) {
	if w.malware {
		return []advisory.Advisory{{ID: "MAL-2026-9001", Malicious: true, Severity: advisory.SeverityCritical}}, nil
	}
	return nil, nil
}

func installWatchLoader(t *testing.T, factory func(*App, time.Time) (checks.Loader, error)) {
	t.Helper()
	old := loaderFactory
	loaderFactory = factory
	t.Cleanup(func() { loaderFactory = old })
}

func watchFixture(t *testing.T, ref string) (string, []byte) {
	t.Helper()
	fixtureClock(t)
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	writeBaselineFile(t, dir, recorded(ref, "alice"))
	data, err := os.ReadFile(baseline.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	return dir, data
}

func decodeWatchEvents(t *testing.T, output string) []watch.Event {
	t.Helper()
	var events []watch.Event
	decoder := json.NewDecoder(strings.NewReader(output))
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		var e watch.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Report json.RawMessage `json:"report"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		decodeReport(t, string(envelope.Report))
		if e.Schema != watch.SchemaID || e.Changes == nil || e.ObservedAt.IsZero() {
			t.Fatalf("bad event: %s", raw)
		}
		events = append(events, e)
	}
	return events
}

func assertWatchBaselineUnchanged(t *testing.T, dir string, before []byte) {
	t.Helper()
	after, err := os.ReadFile(baseline.Path(dir))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("watch changed its baseline: err=%v\nbefore=%s\nafter=%s", err, before, after)
	}
	entries, err := os.ReadDir(filepath.Join(dir, baseline.DirName))
	if err != nil || len(entries) != 1 || entries[0].Name() != baseline.FileName {
		t.Fatalf("watch wrote unexpected state: entries=%v err=%v", entries, err)
	}
}

func TestWatchOnceDetectsCurrentOwnersOfUnchangedRelease(t *testing.T) {
	dir, before := watchFixture(t, "npm:trustdiff-fixture-lib@2.0.0")
	// Keep the test focused on owner changes; both releases' npm maintainer
	// lists remain alice, while current ownership is mallory.
	writePolicy(t, "version: 1\nchecks:\n  publisher-changed: off\n  young-version: off\n")
	installWatchLoader(t, func(a *App, now time.Time) (checks.Loader, error) {
		if !a.Opts.NoCache || a.Opts.Offline {
			t.Fatal("online watch reused persistent cache")
		}
		return &watchTestLoader{fakeLoader: &fakeLoader{now: now}, owners: []model.Publisher{{Name: "mallory"}}}, nil
	})
	code, stdout, stderr := run(t, "watch", "--once", "--format", "json", "--fail-on", "warn")
	if code != ExitFindings {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	events := decodeWatchEvents(t, stdout)
	if len(events) != 1 || events[0].Kind != "initial" || len(events[0].Changes) != 0 {
		t.Fatalf("events=%+v", events)
	}
	found := false
	for _, f := range events[0].Report.Subjects[0].Findings {
		if f.ID == "TD003" {
			found = true
			if f.Evidence["baseline_version"] != "2.0.0" || !strings.Contains(f.Explanation, "locked version did not move") {
				t.Fatalf("not compared with the baseline: %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("current-owner takeover was hidden by unchanged release metadata")
	}
	assertWatchBaselineUnchanged(t, dir, before)
}

func TestWatchHonorsPolicyAndFailureThreshold(t *testing.T) {
	for _, tc := range []struct {
		name, policy, threshold string
		code, count             int
	}{
		{"warn", "version: 1\n", "warn", ExitFindings, 1},
		{"block threshold", "version: 1\n", "block", ExitOK, 1},
		{"off", "version: 1\nchecks:\n  maintainers-changed: off\n", "warn", ExitOK, 0},
		{"allow", "version: 1\nallow:\n  - check: maintainers-changed\n    package: npm:trustdiff-fixture-lib\n    reason: reviewed owner transfer\n", "warn", ExitOK, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, before := watchFixture(t, "npm:trustdiff-fixture-lib@1.0.0")
			writePolicy(t, tc.policy)
			installWatchLoader(t, func(_ *App, now time.Time) (checks.Loader, error) {
				return &watchTestLoader{fakeLoader: &fakeLoader{now: now}, owners: []model.Publisher{{Name: "bob"}}}, nil
			})
			code, stdout, stderr := run(t, "watch", "--once", "--format", "json", "--fail-on", tc.threshold)
			if code != tc.code {
				t.Fatalf("code=%d want=%d stderr=%s stdout=%s", code, tc.code, stderr, stdout)
			}
			count := 0
			for _, f := range decodeWatchEvents(t, stdout)[0].Report.Subjects[0].Findings {
				if f.ID == "TD003" {
					count++
				}
			}
			if count != tc.count {
				t.Fatalf("TD003 findings=%d want=%d", count, tc.count)
			}
			assertWatchBaselineUnchanged(t, dir, before)
		})
	}
}

func TestWatchOfflineUsesRealEmptyCacheAndReportsUnavailable(t *testing.T) {
	dir, before := watchFixture(t, "npm:trustdiff-fixture-lib@1.0.0")
	t.Setenv(httpcache.EnvDir, t.TempDir())
	writePolicy(t, "version: 1\non_data_unavailable: fail\n")
	code, stdout, stderr := run(t, "watch", "--once", "--offline", "--format", "json")
	if code != ExitUnavailable || !strings.Contains(stderr, "offline caches cannot reveal new remote data") {
		t.Fatalf("exit=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	events := decodeWatchEvents(t, stdout)
	if len(events) != 1 || events[0].Report.Summary.ExitCode != ExitUnavailable || len(events[0].Report.Subjects[0].Skipped) == 0 {
		t.Fatalf("offline miss was not reported: %+v", events)
	}
	assertWatchBaselineUnchanged(t, dir, before)
}

func TestWatchOwnerOutageHonorsUnavailablePolicy(t *testing.T) {
	watchFixture(t, "npm:trustdiff-fixture-lib@1.0.0")
	writePolicy(t, "version: 1\non_data_unavailable: fail\n")
	installWatchLoader(t, func(_ *App, now time.Time) (checks.Loader, error) {
		return &watchTestLoader{fakeLoader: &fakeLoader{now: now}, ownerErr: errRegistryDown}, nil
	})
	code, stdout, stderr := run(t, "watch", "--once", "--format", "json")
	if code != ExitUnavailable {
		t.Fatalf("owner outage exit=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	subject := decodeWatchEvents(t, stdout)[0].Report.Subjects[0]
	if !slices.ContainsFunc(subject.Skipped, func(s model.Skipped) bool { return s.Check == "TD003" && strings.Contains(s.Reason, "owners") }) {
		t.Fatalf("owner outage hidden: %+v", subject)
	}
}

func TestWatchRejectsMissingEmptyMalformedBaselineAndBadFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
		args []string
	}{
		{"missing", "", nil},
		{"empty", `{"schema":"trustdiff.baseline/1","updated_at":"2026-09-09T12:00:00Z","packages":[]}`, nil},
		{"malformed", `{`, nil},
		{"interval too short", "", []string{"--interval", "59s"}},
		{"interval too long", "", []string{"--interval", "24h1s"}},
		{"sarif", "", []string{"--format", "sarif"}},
		{"markdown", "", []string{"--format", "markdown"}},
		{"no approval flag", "", []string{"--update-baseline"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixtureClock(t)
			if tc.file != "" {
				writeFile(t, ".", filepath.Join(baseline.DirName, baseline.FileName), tc.file)
			}
			installWatchLoader(t, func(*App, time.Time) (checks.Loader, error) {
				t.Fatal("invalid watch invocation reached a data source")
				return nil, errors.New("unexpected loader")
			})
			code, stdout, stderr := run(t, append([]string{"watch", "--once"}, tc.args...)...)
			if code != ExitUsage || stdout != "" || stderr == "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestWatchRepeatedEvaluationsUseFreshLoaderAndFrozenBaseline(t *testing.T) {
	dir, _ := watchFixture(t, "npm:trustdiff-fixture-lib@1.0.0")
	recordedFile := readBaselineFile(t, dir)
	app, _, _ := baselineApp(t, "json")
	st, err := app.settle()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cycles := 0
	installWatchLoader(t, func(a *App, now time.Time) (checks.Loader, error) {
		cycles++
		if !a.Opts.NoCache {
			t.Fatal("online cycle did not request fresh data")
		}
		owners := []model.Publisher{{Name: "alice"}}
		if cycles >= 2 {
			owners = []model.Publisher{{Name: "mallory"}}
		}
		return &watchTestLoader{fakeLoader: &fakeLoader{now: now}, owners: owners, malware: cycles >= 3}, nil
	})
	var events []watch.Event
	var externalEdit []byte
	loop := watch.Loop{Interval: time.Minute, Wait: func(ctx context.Context, _ time.Duration) error {
		if cycles == 1 {
			// An unrelated process approves a different version while watch runs.
			// The session must retain the original reviewed version and owners.
			writeBaselineFile(t, dir, recorded("npm:trustdiff-fixture-lib@2.0.0", "mallory"))
			var readErr error
			externalEdit, readErr = os.ReadFile(baseline.Path(dir))
			if readErr != nil {
				t.Fatal(readErr)
			}
		}
		if cycles == 4 {
			cancel()
			return ctx.Err()
		}
		return nil
	}}
	inputs := []checks.Input{{Ref: recordedFile.Packages[0].Ref()}}
	_, err = loop.Run(ctx, func(ctx context.Context) (*report.Report, error) {
		return app.evaluateWatch(ctx, st, inputs, recordedFile)
	}, func(e watch.Event) error { events = append(events, e); return nil })
	if !errors.Is(err, context.Canceled) || cycles != 4 || len(events) != 3 {
		t.Fatalf("err=%v cycles=%d events=%+v", err, cycles, events)
	}
	for _, event := range events {
		if event.Report.Subjects[0].Ref.Version != "1.0.0" {
			t.Fatal("watch followed an unreviewed baseline edit")
		}
	}
	if events[1].Changes[0].Check != "TD003" || !slices.ContainsFunc(events[2].Changes, func(c watch.Change) bool { return c.Check == "TD009" }) {
		t.Fatalf("owner/advisory changes missing: %+v", events)
	}
	if app.Opts.NoCache {
		t.Fatal("watch changed the caller's global cache setting")
	}
	assertWatchBaselineUnchanged(t, dir, externalEdit)
}

type watchCancelWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
}

func (w *watchCancelWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	w.cancel()
	return n, err
}

func TestWatchCancellationAfterFirstEventExitsThree(t *testing.T) {
	dir, before := watchFixture(t, "npm:trustdiff-fixture-lib@1.0.0")
	installWatchLoader(t, func(_ *App, now time.Time) (checks.Loader, error) {
		return &watchTestLoader{fakeLoader: &fakeLoader{now: now}, owners: []model.Publisher{{Name: "alice"}}}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &watchCancelWriter{cancel: cancel}
	var stderr bytes.Buffer
	code := MainContext(ctx, []string{"watch", "--format", "json", "--interval", "24h"}, out, &stderr)
	if code != ExitUnavailable || !strings.Contains(stderr.String(), "context canceled") || len(decodeWatchEvents(t, out.String())) != 1 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, &stderr, out.String())
	}
	assertWatchBaselineUnchanged(t, dir, before)
}

func TestWatchFindsBaselineUpwardAndRendersHumanReport(t *testing.T) {
	dir, before := watchFixture(t, "npm:trustdiff-fixture-lib@1.0.0")
	child := filepath.Join(dir, "nested")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	installWatchLoader(t, func(_ *App, now time.Time) (checks.Loader, error) {
		return &watchTestLoader{fakeLoader: &fakeLoader{now: now}, owners: []model.Publisher{{Name: "alice"}}}, nil
	})
	code, stdout, stderr := run(t, "watch", child, "--once", "--no-color")
	if code != ExitOK || !strings.Contains(stdout, "watch initial at "+fixtureNow.Format(time.RFC3339)) || !strings.Contains(stdout, "npm:trustdiff-fixture-lib@1.0.0") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	assertWatchBaselineUnchanged(t, dir, before)
}

type watchUnavailableScanner struct{}

func (watchUnavailableScanner) Scan(_ context.Context, ref model.PackageRef) (guarddog.Result, error) {
	return model.Analysis{Ref: ref, Source: guarddog.SourceURL, Status: "unavailable", Message: "offline test scanner"}, errors.New("offline test scanner")
}

func TestWatchGuardDogSupplementIsIncludedBeforeEventAndExit(t *testing.T) {
	watchFixture(t, "npm:trustdiff-fixture-lib@1.0.0")
	installWatchLoader(t, func(_ *App, now time.Time) (checks.Loader, error) {
		return &watchTestLoader{fakeLoader: &fakeLoader{now: now}, owners: []model.Publisher{{Name: "bob"}}}, nil
	})
	old := guardDogFactory
	guardDogFactory = func(*App) (codeScanner, error) { return watchUnavailableScanner{}, nil }
	t.Cleanup(func() { guardDogFactory = old })
	code, stdout, stderr := run(t, "watch", "--once", "--guarddog", "--fail-on", "never", "--format", "json")
	if code != ExitUnavailable {
		t.Fatalf("incomplete requested analysis exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	events := decodeWatchEvents(t, stdout)
	if len(events) != 1 || !events[0].Report.GuardDogRequested || len(events[0].Report.GuardDog) != 1 || events[0].Report.Summary.ExitCode != ExitUnavailable {
		t.Fatalf("analysis supplement omitted: %+v", events)
	}
}
