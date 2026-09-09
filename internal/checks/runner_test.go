package checks

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/advisory/osv"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/report"
)

// newRunnerR builds a runner with a short timeout and the test clock.
func newRunnerR(loader Loader, checks ...Check) *Runner {
	return &Runner{Loader: loader, Checks: checks, Jobs: 4, Timeout: 5 * time.Second, Now: nowR}
}

// libLoaderR returns a fake loader that knows npm:lib at 1.0.0, 1.1.0 and 2.0.0.
func libLoaderR() *fakeLoaderR {
	l := newFakeLoaderR()
	l.add(stableListR(model.NPM, "lib", "1.0.0", "1.1.0", "2.0.0"))
	return l
}

func skippedReasonsR(s *report.Subject) map[string]string {
	out := map[string]string{}
	for _, sk := range s.Skipped {
		out[sk.Check] = sk.Reason
	}
	return out
}

func findingIDsR(s *report.Subject) []string {
	out := make([]string, 0, len(s.Findings))
	for i := range s.Findings {
		out = append(out, s.Findings[i].ID)
	}
	return out
}

func TestRunResolvesLatestStable(t *testing.T) {
	loader := libLoaderR()
	prerelease := stableListR(model.NPM, "pre", "1.0.0", "1.1.0")
	prerelease.Versions = append(prerelease.Versions, model.VersionInfo{
		Ref: model.MustParseRef("npm:pre@2.0.0-rc.1"), PublishedAt: dayR(0), Prerelease: true,
	})
	prerelease.Latest = "2.0.0-rc.1"
	loader.add(prerelease)
	// A package whose only version is the prerelease the registry names as latest
	// still resolves: that is what installing the bare name fetches, and it is the
	// shape of an npm security holding placeholder, whose note must reach the checks.
	onlyPre := stableListR(model.NPM, "only-pre")
	onlyPre.Versions = []model.VersionInfo{{Ref: model.MustParseRef("npm:only-pre@1.0.0-beta"), PublishedAt: dayR(1), Prerelease: true}}
	onlyPre.Latest = "1.0.0-beta"
	loader.add(onlyPre)
	// Without a latest to fall back on there is nothing to resolve to.
	noLatest := stableListR(model.NPM, "no-latest")
	noLatest.Versions = []model.VersionInfo{{Ref: model.MustParseRef("npm:no-latest@1.0.0-beta"), PublishedAt: dayR(1), Prerelease: true}}
	noLatest.Latest = ""
	loader.add(noLatest)

	var seen sync.Map
	check := fakeCheckR{id: "TD001", name: "young-version", run: func(_ context.Context, s *Subject) Result {
		seen.Store(s.Ref.String(), s.ResolvedLatest)
		return Result{}
	}}
	other := passCheckR("TD006", "install-script-present")

	tests := []struct {
		name        string
		input       string
		wantRef     string
		wantLatest  bool
		wantSkipped string
	}{
		{name: "versioned ref passes through", input: "npm:lib@1.0.0", wantRef: "npm:lib@1.0.0"},
		{name: "bare ref resolves to the registry latest", input: "npm:lib", wantRef: "npm:lib@2.0.0", wantLatest: true},
		{name: "prerelease latest falls back to the highest stable", input: "npm:pre", wantRef: "npm:pre@1.1.0", wantLatest: true},
		{name: "prerelease latest resolves when there is no stable version", input: "npm:only-pre", wantRef: "npm:only-pre@1.0.0-beta", wantLatest: true},
		{name: "no version to resolve to skips every check", input: "npm:no-latest", wantRef: "npm:no-latest", wantSkipped: "no stable version"},
		{name: "unknown package skips every check", input: "npm:missing", wantRef: "npm:missing", wantSkipped: "registry: not found in the registry"},
		// A package the registry has never heard of leaves nothing to evaluate.
		// A version it no longer lists is different, see
		// TestRunUnknownVersionStillRunsAdvisoryChecks.
		{name: "unknown package with a version skips every check", input: "npm:missing@1.0.0", wantRef: "npm:missing@1.0.0", wantSkipped: "registry: not found in the registry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := newRunnerR(loader, check, other).Run(context.Background(), inputsR(tt.input))
			if len(out) != 1 {
				t.Fatalf("Run returned %d subjects, want 1", len(out))
			}
			s := &out[0]
			if s.Ref.String() != tt.wantRef {
				t.Errorf("ref = %s, want %s", s.Ref, tt.wantRef)
			}
			if tt.wantSkipped != "" {
				want := map[string]string{"TD001": tt.wantSkipped, "TD006": tt.wantSkipped}
				if got := skippedReasonsR(s); fmt.Sprint(got) != fmt.Sprint(want) {
					t.Errorf("skipped = %v, want %v", got, want)
				}
				if len(s.Evaluated) != 0 || len(s.Findings) != 0 {
					t.Errorf("evaluated = %v, findings = %v, want none", s.Evaluated, s.Findings)
				}
				return
			}
			if !slices.Equal(s.Evaluated, []string{"TD001", "TD006"}) {
				t.Errorf("evaluated = %v, want TD001 and TD006", s.Evaluated)
			}
			got, ok := seen.Load(tt.wantRef)
			if !ok || got.(bool) != tt.wantLatest {
				t.Errorf("Subject.ResolvedLatest = %v (seen %v), want %v", got, ok, tt.wantLatest)
			}
		})
	}
}

// Taking a malicious release down is how a registry reacts to it: npm left a
// security holding placeholder where flatmap-stream 0.1.1 was, so the version is
// gone from the packument while OSV and deps.dev keep the advisory. The checks
// that read the registry skip themselves, the ones that read the advisories must
// still run and report, or the most important case of all would pass silently.
func TestRunUnknownVersionStillRunsAdvisoryChecks(t *testing.T) {
	loader := libLoaderR()
	registryCheck := skipsOn(SourceRegistry) // TD001, the shape every registry-reading check has
	var sawAdvisories bool
	advisoryCheck := fakeCheckR{id: "TD009", name: "malicious-advisory", run: func(_ context.Context, s *Subject) Result {
		sawAdvisories = true
		if _, down := s.Skipped(SourceOSV); down {
			return Skip("TD009", "osv unavailable")
		}
		return Result{Findings: []model.Finding{NewFinding(fakeCheckR{id: "TD009", name: "malicious-advisory"}, s, "malicious", "advisory found", nil)}}
	}}

	out := newRunnerR(loader, registryCheck, advisoryCheck).Run(context.Background(), inputsR("npm:lib@9.9.9"))
	if len(out) != 1 {
		t.Fatalf("Run returned %d subjects, want 1", len(out))
	}
	s := &out[0]
	if !sawAdvisories {
		t.Fatal("the advisory check never ran for a version the registry does not list")
	}
	if got := skippedReasonsR(s)["TD001"]; got != "registry: not found in the registry" {
		t.Errorf("TD001 skipped with %q, want the registry reason", got)
	}
	if !slices.Equal(findingIDsR(s), []string{"TD009"}) {
		t.Errorf("findings = %v, want the advisory finding", findingIDsR(s))
	}
	if !slices.Equal(s.Evaluated, []string{"TD009"}) {
		t.Errorf("evaluated = %v, want TD009 only", s.Evaluated)
	}
}

func TestRunPrefetchesOnceWithResolvedRefs(t *testing.T) {
	loader := libLoaderR()
	out := newRunnerR(loader, passCheckR("TD001", "young-version")).Run(context.Background(), inputsR("npm:lib", "npm:lib@1.0.0", "npm:missing"))
	if len(out) != 3 {
		t.Fatalf("Run returned %d subjects, want 3", len(out))
	}
	if loader.prefetchCalls() != 1 {
		t.Fatalf("Prefetch called %d times, want 1", loader.prefetchCalls())
	}
	want := []model.PackageRef{model.MustParseRef("npm:lib@2.0.0"), model.MustParseRef("npm:lib@1.0.0")}
	if !slices.Equal(loader.prefetched[0], want) {
		t.Errorf("Prefetch refs = %v, want %v (resolved versions only, unresolvable input left out)", loader.prefetched[0], want)
	}

	if got := newRunnerR(loader).Run(context.Background(), nil); len(got) != 0 {
		t.Errorf("Run(nil) = %v, want empty", got)
	}
	if loader.prefetchCalls() != 2 {
		t.Errorf("Prefetch called %d times over two runs, want 2", loader.prefetchCalls())
	}
}

func TestRunMemoizesAcrossChecksAndSubjects(t *testing.T) {
	src := newFakeSourceR(model.NPM)
	src.add(stableListR(model.NPM, "lib", "1.0.0", "1.1.0"))
	src.add(stableListR(model.NPM, "dep", "0.1.0"))
	loader := newDataLoader(registry.Registry{model.NPM: src}, newFakeAdvisoriesR(), newFakeDepsDevR(), nil)

	// Every check asks the loader for the subject's package and for a dependency.
	asks := func(_ context.Context, s *Subject) Result {
		if _, err := s.Loader.Versions(context.Background(), model.NPM, "lib"); err != nil {
			return Skip("", err.Error())
		}
		if _, err := s.Loader.VersionInfo(context.Background(), model.MustParseRef("npm:dep@0.1.0")); err != nil {
			return Skip("", err.Error())
		}
		return Result{}
	}
	checks := []Check{
		fakeCheckR{id: "TD001", name: "young-version", run: asks},
		fakeCheckR{id: "TD002", name: "publisher-changed", run: asks},
		fakeCheckR{id: "TD007", name: "new-dependency-introduced", run: asks},
	}
	out := newRunnerR(loader, checks...).Run(context.Background(), inputsR("npm:lib@1.0.0", "npm:lib@1.1.0", "npm:lib"))
	for i := range out {
		if len(out[i].Skipped) != 0 {
			t.Fatalf("subject %s skipped %v", out[i].Ref, out[i].Skipped)
		}
	}
	if got := src.count("versions"); got != 1 {
		t.Errorf("Versions fetched %d times for one package over three subjects and three checks, want 1", got)
	}
	// Two subject versions plus the dependency version.
	if got := src.count("info"); got != 3 {
		t.Errorf("VersionInfo fetched %d times, want 3 (1.0.0, 1.1.0 and dep@0.1.0)", got)
	}
	if got := src.count("owners"); got != 1 {
		t.Errorf("Owners fetched %d times, want 1", got)
	}
}

func TestRunBoundsConcurrency(t *testing.T) {
	tests := []struct {
		jobs int
	}{{jobs: 1}, {jobs: 2}, {jobs: 3}}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("jobs=%d", tt.jobs), func(t *testing.T) {
			var inFlight, peak atomic.Int32
			check := fakeCheckR{id: "TD001", name: "young-version", run: func(_ context.Context, _ *Subject) Result {
				n := inFlight.Add(1)
				for {
					old := peak.Load()
					if n <= old || peak.CompareAndSwap(old, n) {
						break
					}
				}
				time.Sleep(15 * time.Millisecond)
				inFlight.Add(-1)
				return Result{}
			}}
			loader := libLoaderR()
			refs := make([]string, 0, 8)
			for range 8 {
				refs = append(refs, "npm:lib@1.0.0")
			}
			r := newRunnerR(loader, check)
			r.Jobs = tt.jobs
			r.Run(context.Background(), inputsR(refs...))
			if got := int(peak.Load()); got > tt.jobs {
				t.Errorf("peak concurrency = %d, want at most %d", got, tt.jobs)
			}
			if tt.jobs == 1 && peak.Load() != 1 {
				t.Errorf("peak concurrency = %d with one job, want exactly 1", peak.Load())
			}
		})
	}
}

func TestRunAllowEntrySuppressesFindings(t *testing.T) {
	p := &policy.Policy{Version: 1, Allow: []policy.AllowEntry{
		{Check: "install-script-present", Package: policy.MustParsePattern("npm:lib"), Reason: "reviewed"},
		{Check: "low-usage", Package: policy.MustParsePattern("npm:lib@1.0.*"), Reason: "pinned"},
		{Check: "vulnerability", Package: policy.MustParsePattern("npm:lib"), Reason: "expired", Expires: policy.Date{Year: 2026, Month: time.January, Day: 1}},
	}}
	checks := []Check{
		findingCheckR("TD006", "install-script-present", "runs postinstall"),
		findingCheckR("TD012", "low-usage", "few downloads"),
		findingCheckR("TD010", "vulnerability", "CVE"),
	}
	tests := []struct {
		name string
		ref  string
		want []string
	}{
		// The expired vulnerability entry no longer suppresses TD010 and is itself
		// reported as TD000.
		{name: "matching entries drop the findings, the expired one does not", ref: "npm:lib@1.0.0", want: []string{"TD000", "TD010"}},
		{name: "version glob does not match another version", ref: "npm:lib@1.1.0", want: []string{"TD000", "TD010", "TD012"}},
		{name: "another package keeps every finding", ref: "npm:other@1.0.0", want: []string{"TD006", "TD010", "TD012"}},
	}
	loader := libLoaderR()
	loader.add(stableListR(model.NPM, "other", "1.0.0"))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRunnerR(loader, checks...)
			r.Policy = p
			out := r.Run(context.Background(), inputsR(tt.ref))
			if got := findingIDsR(&out[0]); !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
			if !slices.Equal(out[0].Evaluated, []string{"TD006", "TD010", "TD012"}) {
				t.Errorf("evaluated = %v, want every check (a suppressed check still ran)", out[0].Evaluated)
			}
		})
	}
}

func TestRunCooldownExclude(t *testing.T) {
	p := &policy.Policy{Version: 1, CooldownExclude: []policy.Pattern{policy.MustParsePattern("npm:@myorg/*")}}
	loader := libLoaderR()
	loader.add(stableListR(model.NPM, "@myorg/tool", "1.0.0"))
	young := findingCheckR("TD001", "young-version", "published today")
	other := findingCheckR("TD006", "install-script-present", "runs postinstall")
	tests := []struct {
		name          string
		ref           string
		wantSkipped   map[string]string
		wantEvaluated []string
		wantFindings  []string
	}{
		{
			name:          "excluded package skips young-version only",
			ref:           "npm:@myorg/tool@1.0.0",
			wantSkipped:   map[string]string{"TD001": "excluded by cooldown_exclude"},
			wantEvaluated: []string{"TD006"},
			wantFindings:  []string{"TD006"},
		},
		{
			name:          "other packages run young-version",
			ref:           "npm:lib@1.0.0",
			wantSkipped:   map[string]string{},
			wantEvaluated: []string{"TD001", "TD006"},
			wantFindings:  []string{"TD001", "TD006"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRunnerR(loader, young, other)
			r.Policy = p
			out := r.Run(context.Background(), inputsR(tt.ref))
			if got := skippedReasonsR(&out[0]); fmt.Sprint(got) != fmt.Sprint(tt.wantSkipped) {
				t.Errorf("skipped = %v, want %v", got, tt.wantSkipped)
			}
			if !slices.Equal(out[0].Evaluated, tt.wantEvaluated) {
				t.Errorf("evaluated = %v, want %v", out[0].Evaluated, tt.wantEvaluated)
			}
			if got := findingIDsR(&out[0]); !slices.Equal(got, tt.wantFindings) {
				t.Errorf("findings = %v, want %v", got, tt.wantFindings)
			}
		})
	}
}

func TestRunExpiredAllowFinding(t *testing.T) {
	p := &policy.Policy{Version: 1, Allow: []policy.AllowEntry{
		{Check: "install-script-present", Package: policy.MustParsePattern("npm:lib"), Reason: "reviewed", Expires: policy.Date{Year: 2026, Month: time.September, Day: 1}},
		{Check: "low-usage", Package: policy.MustParsePattern("npm:lib@1.0.0"), Reason: "pinned", Expires: policy.Date{Year: 2026, Month: time.September, Day: 1}},
		{Check: "vulnerability", Package: policy.MustParsePattern("npm:lib"), Reason: "still valid", Expires: policy.Date{Year: 2027, Month: time.January, Day: 1}},
	}}
	loader := libLoaderR()
	loader.add(stableListR(model.NPM, "other", "1.0.0"))
	loc := &model.Location{Path: "package-lock.json", Line: 12}
	tests := []struct {
		name  string
		input Input
		want  []string
	}{
		{name: "both expired entries match 1.0.0", input: Input{Ref: model.MustParseRef("npm:lib@1.0.0"), Location: loc}, want: []string{"TD000", "TD000"}},
		{name: "only the versionless entry matches 1.1.0", input: Input{Ref: model.MustParseRef("npm:lib@1.1.0")}, want: []string{"TD000"}},
		{name: "another package gets none", input: Input{Ref: model.MustParseRef("npm:other@1.0.0")}, want: []string{}},
		{name: "a subject that cannot be evaluated gets none", input: Input{Ref: model.MustParseRef("npm:missing")}, want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRunnerR(loader, passCheckR("TD001", "young-version"), passCheckR("TD006", "install-script-present"))
			r.Policy = p
			out := r.Run(context.Background(), []Input{tt.input})
			if got := findingIDsR(&out[0]); !slices.Equal(got, tt.want) {
				t.Fatalf("findings = %v, want %v", got, tt.want)
			}
			for i := range out[0].Findings {
				f := &out[0].Findings[i]
				if f.Name != policy.ExpiredAllowName || f.Level != model.LevelWarn || f.Ref != tt.input.Ref || f.Location != tt.input.Location {
					t.Errorf("finding %d = %+v, want expired-allow warn on %s at %v", i, f, tt.input.Ref, tt.input.Location)
				}
			}
		})
	}
}

func TestRunUnavailableSourceIsSkippedNotPass(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		source string
	}{{SourceRegistry}, {SourceOwners}, {SourceOSV}, {SourceDepsDev}, {SourceDownloads}}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			loader := libLoaderR()
			loader.fail[tt.source] = boom
			var downloads int64
			needs := fakeCheckR{id: "TD001", name: "young-version", run: func(_ context.Context, s *Subject) Result {
				downloads = s.Downloads
				if reason, skip := s.Skipped(tt.source); skip {
					return Skip("TD001", reason)
				}
				return Result{Findings: []model.Finding{{ID: "TD001", Title: "ran"}}}
			}}
			independent := passCheckR("TD006", "install-script-present")
			out := newRunnerR(loader, needs, independent).Run(context.Background(), inputsR("npm:lib@1.0.0"))
			want := map[string]string{"TD001": tt.source + " unavailable: boom"}
			if got := skippedReasonsR(&out[0]); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("skipped = %v, want %v", got, want)
			}
			if !slices.Equal(out[0].Evaluated, []string{"TD006"}) {
				t.Errorf("evaluated = %v, want TD006 only", out[0].Evaluated)
			}
			if len(out[0].Findings) != 0 {
				t.Errorf("findings = %v, want none", out[0].Findings)
			}
			if tt.source == SourceDownloads && downloads != -1 {
				t.Errorf("Subject.Downloads = %d with downloads unavailable, want -1", downloads)
			}
		})
	}
}

func TestRunUnsupportedDownloadsIsRecorded(t *testing.T) {
	loader := libLoaderR()
	var reason string
	var ok bool
	check := fakeCheckR{id: "TD012", name: "low-usage", run: func(_ context.Context, s *Subject) Result {
		reason, ok = s.Skipped(SourceDownloads)
		return Result{}
	}}
	newRunnerR(loader, check).Run(context.Background(), inputsR("npm:lib@1.0.0"))
	if !ok || !strings.Contains(reason, registry.ErrUnsupported.Error()) {
		t.Errorf("Skipped(downloads) = %q, %v; want the registry's unsupported error", reason, ok)
	}
}

// The previous version must carry its full detail: the version list only has
// what the package-level response offered, while the comparisons (dependencies,
// install scripts, provenance) need the per-version answer.
func TestRunFillsPreviousVersionDetails(t *testing.T) {
	loader := libLoaderR()
	prev := model.MustParseRef("npm:lib@1.1.0")
	detailed := *loader.infos[prev]
	detailed.Dependencies = map[string]string{"left-pad": "^1.0.0"}
	detailed.Scripts = map[string]string{"postinstall": "node setup.js"}
	loader.infos[prev] = &detailed

	var got *model.VersionInfo
	check := fakeCheckR{id: "TD007", name: "new-dependency-introduced", run: func(_ context.Context, s *Subject) Result {
		got = s.Previous
		return Result{}
	}}
	newRunnerR(loader, check).Run(context.Background(), inputsR("npm:lib@2.0.0"))
	if got == nil || got.Ref != prev {
		t.Fatalf("Previous = %+v, want the 1.1.0 entry", got)
	}
	if got.Dependencies["left-pad"] != "^1.0.0" || got.Scripts["postinstall"] == "" {
		t.Fatalf("Previous carries the list entry, not the detailed version: %+v", got)
	}
	// The detailed entry is shared through the memoizing loader; the runner must not hand out the loader's pointer.
	if got == loader.infos[prev] {
		t.Fatal("Previous points at the loader's memoized entry")
	}

	// When the detail request fails, the list entry still serves as the previous
	// version for its publish time and publisher, and the failure is recorded
	// under SourcePrevious: a check comparing the two versions' detail skips on
	// it instead of reading dependencies the list entry does not carry.
	tests := []struct {
		name            string
		err             error
		wantReason      string
		wantUnavailable bool
	}{
		{name: "outage", err: errors.New("503"), wantReason: "previous unavailable: 503", wantUnavailable: true},
		{name: "not found", err: registry.ErrNotFound, wantReason: "previous: not found in the registry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader.failInfo[prev] = tt.err
			got = nil
			var reason string
			var recorded bool
			comparing := fakeCheckR{id: "TD007", name: "new-dependency-introduced", run: func(_ context.Context, s *Subject) Result {
				got = s.Previous
				reason, recorded = s.Skipped(SourcePrevious)
				if recorded {
					return Skip("TD007", reason)
				}
				return Result{}
			}}
			out := newRunnerR(loader, comparing).Evaluate(context.Background(), inputsR("npm:lib@2.0.0"))
			if got == nil || got.Ref != prev || got.Dependencies != nil || got.PublishedAt.IsZero() || got.Publisher == nil {
				t.Fatalf("fallback Previous = %+v, want the plain list entry for 1.1.0 with its publish time and publisher", got)
			}
			if !recorded || reason != tt.wantReason {
				t.Errorf("Skipped(previous) = %q, %v; want %q", reason, recorded, tt.wantReason)
			}
			if want := map[string]string{"TD007": tt.wantReason}; fmt.Sprint(skippedReasonsR(&out[0].Subject)) != fmt.Sprint(want) {
				t.Errorf("skipped = %v, want %v", out[0].Subject.Skipped, want)
			}
			if out[0].Unavailable != tt.wantUnavailable {
				t.Errorf("Outcome.Unavailable = %v, want %v", out[0].Unavailable, tt.wantUnavailable)
			}
		})
	}
}

// The real TD007 must not report every dependency of the evaluated version as
// new when the previous version's detail could not be fetched: the list entry
// it falls back to says nothing about dependencies.
func TestRunPreviousDetailFailureSkipsTD007(t *testing.T) {
	td007, ok := Lookup("TD007")
	if !ok {
		t.Fatal("TD007 is not registered")
	}
	loader := libLoaderR()
	prev := model.MustParseRef("npm:lib@1.1.0")
	cur := model.MustParseRef("npm:lib@2.0.0")
	for _, ref := range []model.PackageRef{prev, cur} {
		detailed := *loader.infos[ref]
		detailed.Dependencies = map[string]string{"a": "^1.0.0"}
		loader.infos[ref] = &detailed
	}
	loader.failInfo[prev] = errors.New("503")
	out := newRunnerR(loader, td007).Run(context.Background(), inputsR("npm:lib@2.0.0"))
	if got := findingIDsR(&out[0]); len(got) != 0 {
		t.Errorf("findings = %v, want none: 1.1.0 declared the same dependency, its detail just could not be fetched", got)
	}
	want := map[string]string{"TD007": "previous unavailable: 503"}
	if got := skippedReasonsR(&out[0]); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("skipped = %v, want %v", got, want)
	}
}

func TestRunTimeout(t *testing.T) {
	slow := fakeCheckR{id: "TD001", name: "young-version", run: func(ctx context.Context, _ *Subject) Result {
		<-ctx.Done()
		return Result{Findings: []model.Finding{{ID: "TD001", Title: "too late"}}}
	}}
	quick := passCheckR("TD006", "install-script-present")
	r := newRunnerR(libLoaderR(), slow, quick)
	r.Timeout = 20 * time.Millisecond
	start := time.Now()
	out := r.Run(context.Background(), inputsR("npm:lib@1.0.0"))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Run took %s, the timeout did not cut the slow check short", elapsed)
	}
	want := map[string]string{"TD001": "timed out after 20ms"}
	if got := skippedReasonsR(&out[0]); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("skipped = %v, want %v", got, want)
	}
	if !slices.Equal(out[0].Evaluated, []string{"TD006"}) || len(out[0].Findings) != 0 {
		t.Errorf("evaluated = %v, findings = %v; want TD006 evaluated and no finding from the timed out check", out[0].Evaluated, out[0].Findings)
	}
}

func TestRunCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waits := fakeCheckR{id: "TD001", name: "young-version", run: func(ctx context.Context, _ *Subject) Result {
		<-ctx.Done()
		return Result{}
	}}
	out := newRunnerR(libLoaderR(), waits).Run(ctx, inputsR("npm:lib@1.0.0"))
	got := skippedReasonsR(&out[0])
	if got["TD001"] != "run canceled: context canceled" {
		t.Errorf("skipped = %v, want TD001 skipped as canceled", got)
	}
}

func TestRunRecoversPanic(t *testing.T) {
	panics := fakeCheckR{id: "TD001", name: "young-version", run: func(_ context.Context, _ *Subject) Result {
		panic("boom")
	}}
	fine := findingCheckR("TD006", "install-script-present", "runs postinstall")
	out := newRunnerR(libLoaderR(), panics, fine).Run(context.Background(), inputsR("npm:lib@1.0.0"))
	want := map[string]string{"TD001": "check panicked: boom"}
	if got := skippedReasonsR(&out[0]); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("skipped = %v, want %v", got, want)
	}
	if !slices.Equal(out[0].Evaluated, []string{"TD006"}) || !slices.Equal(findingIDsR(&out[0]), []string{"TD006"}) {
		t.Errorf("evaluated = %v, findings = %v; want the other check unaffected", out[0].Evaluated, out[0].Findings)
	}
}

func TestRunOrdering(t *testing.T) {
	loader := libLoaderR()
	loader.add(stableListR(model.NPM, "a", "1.0.0"))
	loader.add(stableListR(model.NPM, "b", "1.0.0"))
	// Earlier subjects sleep longer, so completion order is the reverse of input order.
	delays := map[string]time.Duration{"a": 30 * time.Millisecond, "lib": 15 * time.Millisecond, "b": 0}
	check := fakeCheckR{id: "TD002", name: "publisher-changed", run: func(_ context.Context, s *Subject) Result {
		time.Sleep(delays[s.Ref.Name])
		return Result{Findings: []model.Finding{
			NewFinding(fakeCheckR{id: "TD009", name: "malicious-advisory"}, s, "z", "", nil),
			NewFinding(fakeCheckR{id: "TD002", name: "publisher-changed"}, s, "b", "", nil),
			NewFinding(fakeCheckR{id: "TD002", name: "publisher-changed"}, s, "a", "", nil),
		}}
	}}
	out := newRunnerR(loader, check, passCheckR("TD001", "young-version")).Run(context.Background(), inputsR("npm:a@1.0.0", "npm:lib@1.0.0", "npm:b@1.0.0"))
	refs := make([]string, 0, len(out))
	for i := range out {
		refs = append(refs, out[i].Ref.String())
	}
	if want := []string{"npm:a@1.0.0", "npm:lib@1.0.0", "npm:b@1.0.0"}; !slices.Equal(refs, want) {
		t.Errorf("subject order = %v, want input order %v", refs, want)
	}
	for i := range out {
		var titles []string
		for j := range out[i].Findings {
			titles = append(titles, out[i].Findings[j].ID+":"+out[i].Findings[j].Title)
		}
		if want := []string{"TD002:a", "TD002:b", "TD009:z"}; !slices.Equal(titles, want) {
			t.Errorf("%s findings = %v, want sorted by id then title %v", out[i].Ref, titles, want)
		}
		if !slices.Equal(out[i].Evaluated, []string{"TD001", "TD002"}) {
			t.Errorf("%s evaluated = %v, want sorted ids", out[i].Ref, out[i].Evaluated)
		}
	}
}

func TestRunOffAndEcosystemFilter(t *testing.T) {
	off := model.LevelOff
	p := &policy.Policy{Version: 1, Checks: map[string]policy.CheckConfig{"young-version": {Level: &off}}}
	loader := libLoaderR()
	loader.add(stableListR(model.PyPI, "requests", "2.32.0"))
	young := findingCheckR("TD001", "young-version", "published today")
	npmOnly := findingCheckR("TD005", "install-script-introduced", "postinstall added")
	npmOnly.ecos = []model.Ecosystem{model.NPM}
	all := findingCheckR("TD006", "install-script-present", "runs postinstall")
	tests := []struct {
		name          string
		ref           string
		wantEvaluated []string
	}{
		{name: "off check and npm-only check are absent for pypi", ref: "pypi:requests@2.32.0", wantEvaluated: []string{"TD006"}},
		{name: "off check is absent for npm", ref: "npm:lib@1.0.0", wantEvaluated: []string{"TD005", "TD006"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRunnerR(loader, young, npmOnly, all)
			r.Policy = p
			out := r.Run(context.Background(), inputsR(tt.ref))
			if !slices.Equal(out[0].Evaluated, tt.wantEvaluated) {
				t.Errorf("evaluated = %v, want %v", out[0].Evaluated, tt.wantEvaluated)
			}
			if len(out[0].Skipped) != 0 {
				t.Errorf("skipped = %v, want none: a check that does not apply is neither evaluated nor skipped", out[0].Skipped)
			}
			if got := findingIDsR(&out[0]); !slices.Equal(got, tt.wantEvaluated) {
				t.Errorf("findings = %v, want %v", got, tt.wantEvaluated)
			}
		})
	}
}

func TestRunAssemblesSubject(t *testing.T) {
	base := newFakeLoaderR()
	base.add(stableListR(model.NPM, "lib", "1.0.0", "1.1.0", "2.0.0"))
	base.owners[pkgR(model.NPM, "lib")] = []model.Publisher{{Name: "alice"}, {Name: "bob"}}
	base.downloads[pkgR(model.NPM, "lib")] = 1234
	ref := model.MustParseRef("npm:lib@1.1.0")
	base.advisories[ref] = []advisory.Advisory{{ID: "GHSA-1", Severity: advisory.SeverityHigh}}
	base.facts[ref] = &depsdev.VersionFacts{Found: true, IsDeprecated: true}
	base.findings[ref] = []depsdev.Finding{{Type: "LOW_USAGE", Risk: "RISK_LOW"}}
	loader := &fakeFindingsLoaderR{fakeLoaderR: base}
	loc := &model.Location{Path: "package-lock.json", Line: 3}
	cargo := policy.Duration(7 * 24 * time.Hour)
	p := &policy.Policy{Version: 1, Ecosystems: map[model.Ecosystem]policy.EcosystemOverride{model.Cargo: {Cooldown: cargo}}}

	var got *Subject
	capture := fakeCheckR{id: "TD001", name: "young-version", run: func(_ context.Context, s *Subject) Result {
		got = s
		return Result{}
	}}
	r := newRunnerR(loader, capture)
	r.Policy = p
	out := r.Run(context.Background(), []Input{{Ref: ref, Location: loc, Direct: true}})
	if got == nil {
		t.Fatal("check did not run")
	}
	if out[0].Location != loc || !out[0].Direct {
		t.Errorf("report subject = %+v, want the input location and direct flag", out[0])
	}
	if got.Ref != ref || got.Location != loc || !got.Direct || !got.Now.Equal(nowR) || got.ResolvedLatest {
		t.Errorf("Subject identity = ref %s loc %v direct %v now %s resolved %v", got.Ref, got.Location, got.Direct, got.Now, got.ResolvedLatest)
	}
	if got.Settings.Ecosystem != model.NPM || got.Settings.Cooldown != policy.DefaultCooldown {
		t.Errorf("Settings = %+v, want npm with the default cooldown", got.Settings)
	}
	if got.Loader != Loader(loader) {
		t.Error("Subject.Loader is not the runner's loader")
	}
	if got.Package == nil || got.Package.Name != "lib" {
		t.Errorf("Package = %+v, want the lib list", got.Package)
	}
	if got.Version == nil || got.Version.Ref != ref {
		t.Fatalf("Version = %+v, want 1.1.0", got.Version)
	}
	if got.Version == base.infos[ref] {
		t.Error("Subject.Version is the loader's pointer; want a copy so provenance updates do not leak")
	}
	if got.Previous == nil || got.Previous.Ref.Version != "1.0.0" {
		t.Errorf("Previous = %+v, want 1.0.0", got.Previous)
	}
	if len(got.Owners) != 2 || got.Owners[1].Name != "bob" {
		t.Errorf("Owners = %v, want alice and bob", got.Owners)
	}
	if len(got.Advisories) != 1 || got.Advisories[0].ID != "GHSA-1" {
		t.Errorf("Advisories = %v, want GHSA-1", got.Advisories)
	}
	if got.DepsDev == nil || !got.DepsDev.IsDeprecated {
		t.Errorf("DepsDev = %+v, want the deprecated facts", got.DepsDev)
	}
	if len(got.DepsDevFindings) != 1 || got.DepsDevFindings[0].Type != "LOW_USAGE" {
		t.Errorf("DepsDevFindings = %v, want LOW_USAGE", got.DepsDevFindings)
	}
	if got.Downloads != 1234 {
		t.Errorf("Downloads = %d, want 1234", got.Downloads)
	}
	if len(got.Unavailable) != 0 {
		t.Errorf("Unavailable = %v, want empty", got.Unavailable)
	}
}

func TestRunWithoutFindingsLoader(t *testing.T) {
	loader := libLoaderR()
	var got *Subject
	capture := fakeCheckR{id: "TD001", name: "young-version", run: func(_ context.Context, s *Subject) Result {
		got = s
		return Result{}
	}}
	newRunnerR(loader, capture).Run(context.Background(), inputsR("npm:lib@1.0.0"))
	if got == nil {
		t.Fatal("check did not run")
	}
	if got.DepsDevFindings != nil {
		t.Errorf("DepsDevFindings = %v, want nil from a loader without the optional method", got.DepsDevFindings)
	}
	if _, unavailable := got.Unavailable[SourceDepsDev]; unavailable {
		t.Error("deps.dev reported unavailable although the facts loaded")
	}
	if got.Previous != nil {
		t.Errorf("Previous = %+v for the first release, want nil", got.Previous)
	}
}

func TestRunFindingsErrorMarksDepsDevUnavailable(t *testing.T) {
	loader := &fakeFindingsLoaderR{fakeLoaderR: libLoaderR(), findingsErr: errors.New("findings down")}
	var got *Subject
	capture := fakeCheckR{id: "TD001", name: "young-version", run: func(_ context.Context, s *Subject) Result {
		got = s
		return Result{}
	}}
	newRunnerR(loader, capture).Run(context.Background(), inputsR("npm:lib@1.0.0"))
	if got == nil {
		t.Fatal("check did not run")
	}
	if reason, ok := got.Skipped(SourceDepsDev); !ok || reason != "deps.dev unavailable: findings down" {
		t.Errorf("Skipped(deps.dev) = %q, %v; want the findings error", reason, ok)
	}
}

// The runner hands the provenance to the checks as the registry reported it. A
// deps.dev verification is TD004's to merge, for both versions it compares, so
// that the finding can say who verified; a runner that upgraded the evaluated
// version beforehand made every verification look like the registry's own.
func TestRunLeavesProvenanceVerificationToTD004(t *testing.T) {
	loader := newFakeLoaderR()
	list := stableListR(model.NPM, "lib", "1.0.0")
	list.Versions[0].Provenance = model.Provenance{Kind: model.ProvenanceAttestation}
	loader.add(list)
	ref := model.MustParseRef("npm:lib@1.0.0")
	loader.facts[ref] = &depsdev.VersionFacts{Found: true, AttestationVerified: true, SLSAVerified: true}
	var got *Subject
	capture := fakeCheckR{id: "TD004", name: "trust-downgrade", run: func(_ context.Context, s *Subject) Result {
		got = s
		return Result{}
	}}
	newRunnerR(loader, capture).Run(context.Background(), inputsR("npm:lib@1.0.0"))
	if got == nil || got.Version == nil || got.DepsDev == nil {
		t.Fatalf("subject = %+v, want a loaded version with deps.dev facts", got)
	}
	if got.Version.Provenance.Verified {
		t.Error("Provenance.Verified = true: the runner merged the deps.dev verification, which is TD004's job")
	}
	if !got.DepsDev.AttestationVerified {
		t.Error("the deps.dev facts did not reach the subject")
	}
}

// Outcome.Unavailable is what on_data_unavailable: fail reacts to. It must be
// set for a source that could not be consulted and for a check that did not
// finish, and stay unset for a definite answer, however a check words its skip.
// skipsOn returns a check that skips with the joined reasons of the sources that
// failed, the way the checks in this package do.
func skipsOn(sources ...string) fakeCheckR {
	return fakeCheckR{id: "TD001", name: "young-version", run: func(_ context.Context, s *Subject) Result {
		var reasons []string
		for _, source := range sources {
			if reason, down := s.Skipped(source); down {
				reasons = append(reasons, reason)
			}
		}
		if len(reasons) > 0 {
			return Skip("TD001", strings.Join(reasons, "; "))
		}
		return Result{}
	}}
}

func TestEvaluateReportsUnavailable(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name       string
		input      string
		fail       map[string]error
		check      fakeCheckR
		timeout    time.Duration
		cancel     bool
		wantReason string
		want       bool
	}{
		{name: "registry outage", input: "npm:lib@1.0.0", fail: map[string]error{SourceRegistry: boom}, check: skipsOn(SourceRegistry), wantReason: "registry unavailable: boom", want: true},
		{name: "downloads not provided", input: "npm:lib@1.0.0", check: skipsOn(SourceDownloads), wantReason: "downloads: not provided by this registry"},
		{name: "deps.dev does not index the ecosystem", input: "npm:lib@1.0.0", fail: map[string]error{SourceDepsDev: fmt.Errorf("deno: %w", depsdev.ErrUnsupported)}, check: skipsOn(SourceDepsDev), wantReason: "deps.dev: deno: ecosystem not indexed by deps.dev"},
		{name: "osv does not index the ecosystem", input: "npm:lib@1.0.0", fail: map[string]error{SourceOSV: fmt.Errorf("jsr: %w", osv.ErrUnsupported)}, check: skipsOn(SourceOSV), wantReason: "osv: jsr: ecosystem not indexed by OSV"},
		{name: "osv not configured", input: "npm:lib@1.0.0", fail: map[string]error{SourceOSV: fmt.Errorf("osv: %w", ErrNotConfigured)}, check: skipsOn(SourceOSV), wantReason: "osv: osv: data source not configured"},
		{name: "one outage among joined reasons", input: "npm:lib@1.0.0", fail: map[string]error{SourceOSV: fmt.Errorf("jsr: %w", osv.ErrUnsupported), SourceDepsDev: boom}, check: skipsOn(SourceOSV, SourceDepsDev), wantReason: "osv: jsr: ecosystem not indexed by OSV; deps.dev unavailable: boom", want: true},
		{name: "a check's own wording does not count", input: "npm:lib@1.0.0", check: fakeCheckR{id: "TD001", name: "young-version", run: func(context.Context, *Subject) Result {
			return Skip("TD001", "baseline unavailable for comparison")
		}}, wantReason: "baseline unavailable for comparison"},
		// The unfinished checks return a while after ctx ends, so the runner's
		// select sees the context first and the outcome does not depend on scheduling.
		{name: "timed out check", input: "npm:lib@1.0.0", timeout: 20 * time.Millisecond, check: fakeCheckR{id: "TD001", name: "young-version", run: func(ctx context.Context, _ *Subject) Result {
			<-ctx.Done()
			time.Sleep(50 * time.Millisecond)
			return Result{}
		}}, wantReason: "timed out after 20ms", want: true},
		{name: "canceled run", input: "npm:lib@1.0.0", cancel: true, check: fakeCheckR{id: "TD001", name: "young-version", run: func(ctx context.Context, _ *Subject) Result {
			<-ctx.Done()
			time.Sleep(50 * time.Millisecond)
			return Result{}
		}}, wantReason: "run canceled: context canceled", want: true},
		{name: "panic is a bug, not an outage", input: "npm:lib@1.0.0", check: fakeCheckR{id: "TD001", name: "young-version", run: func(context.Context, *Subject) Result {
			panic("boom")
		}}, wantReason: "check panicked: boom"},
		{name: "bare ref with a registry outage", input: "npm:lib", fail: map[string]error{SourceRegistry: boom}, check: passCheckR("TD001", "young-version"), wantReason: "registry unavailable: boom", want: true},
		{name: "bare ref of an unknown package", input: "npm:missing", check: passCheckR("TD001", "young-version"), wantReason: "registry: not found in the registry"},
		{name: "unknown version", input: "npm:lib@9.9.9", check: skipsOn(SourceRegistry), wantReason: "registry: not found in the registry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := libLoaderR()
			for source, err := range tt.fail {
				loader.fail[source] = err
			}
			r := newRunnerR(loader, tt.check, passCheckR("TD006", "install-script-present"))
			if tt.timeout > 0 {
				r.Timeout = tt.timeout
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}
			out := r.Evaluate(ctx, inputsR(tt.input))
			if got := skippedReasonsR(&out[0].Subject)["TD001"]; got != tt.wantReason {
				t.Errorf("TD001 skipped with %q, want %q", got, tt.wantReason)
			}
			if out[0].Unavailable != tt.want {
				t.Errorf("Outcome.Unavailable = %v, want %v (skipped: %v)", out[0].Unavailable, tt.want, out[0].Subject.Skipped)
			}
		})
	}
}

func TestRunSubjectsMatchEvaluate(t *testing.T) {
	loader := libLoaderR()
	loader.fail[SourceOSV] = errors.New("osv down")
	check := fakeCheckR{id: "TD010", name: "vulnerability", run: func(_ context.Context, s *Subject) Result {
		if reason, down := s.Skipped(SourceOSV); down {
			return Skip("TD010", reason)
		}
		return Result{}
	}}
	inputs := inputsR("npm:lib@1.0.0", "npm:missing")
	outcomes := newRunnerR(loader, check).Evaluate(context.Background(), inputs)
	subjects := newRunnerR(loader, check).Run(context.Background(), inputs)
	if fmt.Sprint(Subjects(outcomes)) != fmt.Sprint(subjects) {
		t.Errorf("Run = %v\nEvaluate subjects = %v", subjects, Subjects(outcomes))
	}
	if !outcomes[0].Unavailable || outcomes[1].Unavailable {
		t.Errorf("Unavailable = %v, %v; want true for the OSV outage and false for the unknown package", outcomes[0].Unavailable, outcomes[1].Unavailable)
	}
}

func TestSourceProblemWording(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "not found", err: fmt.Errorf("versions of npm:x: %w", registry.ErrNotFound), want: "registry: versions of npm:x: not found in the registry"},
		{name: "not provided", err: registry.ErrUnsupported, want: "registry: not provided by this registry"},
		{name: "osv does not index", err: fmt.Errorf("jsr: %w", osv.ErrUnsupported), want: "registry: jsr: ecosystem not indexed by OSV"},
		{name: "deps.dev does not index", err: fmt.Errorf("deno: %w", depsdev.ErrUnsupported), want: "registry: deno: ecosystem not indexed by deps.dev"},
		{name: "not configured", err: ErrNotConfigured, want: "registry: data source not configured"},
		{name: "outage", err: errors.New("503 after 3 attempts"), want: "registry unavailable: 503 after 3 attempts"},
		{name: "context deadline", err: context.DeadlineExceeded, want: "registry unavailable: context deadline exceeded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sourceProblem(SourceRegistry, tt.err); got != tt.want {
				t.Errorf("sourceProblem = %q, want %q", got, tt.want)
			}
			s := &Subject{Unavailable: map[string]error{SourceRegistry: tt.err}}
			wantOutage := strings.Contains(tt.want, "unavailable")
			if got := s.outageReasons(); (len(got) == 1) != wantOutage {
				t.Errorf("outageReasons = %v, want an entry: %v", got, wantOutage)
			}
		})
	}
}

func TestRunFillsSkippedCheckID(t *testing.T) {
	anonymous := fakeCheckR{id: "TD003", name: "maintainers-changed", run: func(_ context.Context, _ *Subject) Result {
		return Result{Skipped: &model.Skipped{Reason: "baseline required"}}
	}}
	out := newRunnerR(libLoaderR(), anonymous).Run(context.Background(), inputsR("npm:lib@1.0.0"))
	want := map[string]string{"TD003": "baseline required"}
	if got := skippedReasonsR(&out[0]); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("skipped = %v, want %v", got, want)
	}
}

func TestRunDefaults(t *testing.T) {
	var got *Subject
	capture := fakeCheckR{id: "TD001", name: "young-version", run: func(_ context.Context, s *Subject) Result {
		got = s
		return Result{}
	}}
	before := time.Now()
	r := &Runner{Loader: libLoaderR(), Checks: []Check{capture}}
	r.Run(context.Background(), inputsR("npm:lib@1.0.0"))
	if got == nil {
		t.Fatal("check did not run")
	}
	if got.Now.Before(before) || got.Now.After(time.Now()) {
		t.Errorf("Subject.Now = %s, want the wall clock when Now is zero", got.Now)
	}
	if got.Settings.Ecosystem != model.NPM {
		t.Errorf("Settings.Ecosystem = %s with a nil policy, want npm defaults", got.Settings.Ecosystem)
	}
	rn := r.prepare()
	if rn.jobs != DefaultJobs || rn.timeout != DefaultTimeout || rn.log == nil {
		t.Errorf("defaults = jobs %d timeout %s log %v", rn.jobs, rn.timeout, rn.log)
	}
	if (&Runner{Loader: libLoaderR()}).prepare().checks == nil {
		t.Error("nil Checks did not resolve to All()")
	}
}

func TestRunNilLoaderPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Run with a nil Loader did not panic")
		}
	}()
	(&Runner{}).Run(context.Background(), inputsR("npm:lib@1.0.0"))
}

func TestRunOutputFeedsReportBuild(t *testing.T) {
	loader := libLoaderR()
	// Nothing to resolve to: no stable version and no latest to fall back on.
	noLatest := stableListR(model.NPM, "no-latest")
	noLatest.Versions = []model.VersionInfo{{Ref: model.MustParseRef("npm:no-latest@1.0.0-beta"), PublishedAt: dayR(1), Prerelease: true}}
	noLatest.Latest = ""
	loader.add(noLatest)
	out := newRunnerR(loader, passCheckR("TD001", "young-version"), findingCheckR("TD006", "install-script-present", "runs postinstall")).
		Run(context.Background(), inputsR("npm:lib@1.0.0", "npm:no-latest"))
	r := report.Build(out, report.Tool{}, report.Policy{}, model.LevelBlock)
	if len(r.Subjects) != 2 {
		t.Fatalf("report has %d subjects, want 2", len(r.Subjects))
	}
	if r.Subjects[0].Verdict != report.VerdictWarn {
		t.Errorf("lib verdict = %s, want warn", r.Subjects[0].Verdict)
	}
	if r.Subjects[1].Verdict != report.VerdictSkipped || r.Summary.Skipped != 2 {
		t.Errorf("no-latest verdict = %s with %d skipped, want skipped with 2", r.Subjects[1].Verdict, r.Summary.Skipped)
	}
	if r.Summary.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0 for a warn finding under fail-on block", r.Summary.ExitCode)
	}
}
