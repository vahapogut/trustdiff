package checks

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vahapogut/trustdiff/internal/lockfile"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/report"
)

// Defaults for the Runner fields left at zero.
const (
	// DefaultJobs bounds the subjects evaluated concurrently, matching --jobs.
	DefaultJobs = 8
	// DefaultTimeout bounds one check for one subject. It is generous because a
	// check that consults the loader (TD007 looks at introduced dependencies) can
	// sit behind the HTTP client's own retries.
	DefaultTimeout = 60 * time.Second
)

// cooldownExcludedCheck is the policy name of the check that cooldown_exclude
// turns off per package.
const cooldownExcludedCheck = "young-version"

// Input is one subject as the caller names it: a ref with or without a version,
// the lockfile location it came from, whether it is a direct dependency, and the
// lockfile entry itself when the subject was read from a lockfile.
type Input struct {
	Ref      model.PackageRef
	Location *model.Location
	Direct   bool
	// Lock is the lockfile entry the subject came from, nil for a ref named on
	// the command line. The runner puts it on Subject.Lock, where the checks that
	// judge the lockfile rather than the registry (TD013, TD014) read it.
	Lock *lockfile.Entry
	// BaseVersion is the version the base lockfile locked, when diff evaluates an
	// entry whose version moved. It is the version the project actually had,
	// which is not always the release the registry calls previous: upgrading
	// across several releases makes them differ, and brief section 4.1 asks for
	// both. The runner loads it into Subject.PreviousInBase when it differs.
	BaseVersion string
}

// Runner evaluates subjects. Evaluate resolves bare refs to their latest stable
// version, asks the Loader to prefetch the batch sources once, assembles a
// Subject per input with bounded concurrency, runs every applicable check under a
// timeout and applies the policy. It returns one Outcome per input, in input
// order, whose report.Subject has the findings sorted by id then title;
// report.Build adds the verdicts. A ref that had no version comes back with the
// resolved one, which is how the caller tells that resolution happened. A package
// or version the registry does not have gets every check skipped with that
// answer: the advisory and deps.dev checks must not vouch for a version that does
// not exist.
//
// How a check plugs in. A check is one file in this package named after its
// policy name (young_version.go for young-version) that defines a type
// implementing Check and registers it from init:
//
//	func init() { Register(youngVersion{}) }
//
// ID returns the stable TDnnn id, Name the policy name that policy.CheckNames
// lists, Ecosystems the ecosystems it applies to (nil for all). Run receives the
// assembled Subject and must:
//
//   - read what it needs from the Subject and never fetch on its own; a check
//     that needs another package goes through s.Loader, which memoizes per run;
//   - return Skip(id, reason) when a source it needs is unavailable, taking the
//     reason from s.Skipped(SourceRegistry) and its siblings verbatim (a reason
//     may join several, as TD009 does, but must contain them: that is how the
//     runner tells an outage from a definite answer for on_data_unavailable),
//     never an empty Result: an unavailable source is reported as skipped, not
//     as a pass;
//   - build findings with NewFinding so the id, name, effective level, ref and
//     location are set, with an Evidence map whose keys docs/checks.md documents;
//   - honor ctx: the runner cancels it at the per-check timeout and reports the
//     check as skipped, and a check that ignores ctx keeps running in the
//     background until it returns on its own;
//   - not panic; the runner recovers a panic and reports the check as skipped
//     with the message, but whatever the check found is lost.
//
// The runner handles the rest: it skips checks that do not apply to the
// ecosystem or whose effective level is off, drops findings covered by an allow
// entry, skips young-version for packages under cooldown_exclude, and emits the
// expired-allow finding for stale entries. It does not merge deps.dev's
// verification into the provenance it loads: TD004 does that for the versions it
// compares, so the finding can say who verified. Tests build a Subject by hand
// or run a fake Loader through the Runner.
type Runner struct {
	// Loader supplies the data; NewLoader builds the real one. It is required.
	Loader Loader
	// Policy is the loaded policy; nil means the built-in defaults.
	Policy *policy.Policy
	// Checks are the checks to run; nil means All().
	Checks []Check
	// Jobs bounds the subjects evaluated concurrently; values below 1 mean DefaultJobs.
	Jobs int
	// Timeout bounds one check for one subject; zero means DefaultTimeout.
	Timeout time.Duration
	// Now is the run's clock, given to every Subject; zero means time.Now(). The
	// caller applies the TRUSTDIFF_NOW override before it gets here.
	Now time.Time
	// Log receives diagnostics; nil discards them.
	Log *slog.Logger
}

// run is a Runner with its defaults resolved, so Run and its helpers never
// consult the zero values again.
type run struct {
	loader  Loader
	policy  *policy.Policy
	checks  []Check
	jobs    int
	timeout time.Duration
	now     time.Time
	log     *slog.Logger
}

// Outcome is what Evaluate produced for one input: the report subject, and the
// one fact the report schema does not carry.
type Outcome struct {
	Subject report.Subject
	// Unavailable is true when a check was skipped because a data source could
	// not be consulted (a failed request, a timeout, a canceled run) rather than
	// because the source gave a definite answer (not found, not indexed, not
	// provided). It is the condition on_data_unavailable: fail reacts to; the
	// skipped reasons in the report word the two cases differently, but they are
	// prose.
	Unavailable bool
}

// Subjects extracts the report subjects of outcomes, in the same order.
func Subjects(outcomes []Outcome) []report.Subject {
	out := make([]report.Subject, len(outcomes))
	for i := range outcomes {
		out[i] = outcomes[i].Subject
	}
	return out
}

// resolution is what the first phase of Evaluate decided for one input.
type resolution struct {
	ref model.PackageRef
	// latest is true when the input had no version and ref carries the resolved one.
	latest bool
	// skip is the reason nothing can be evaluated; empty when evaluation proceeds.
	skip string
	// unavailable is true when skip stems from a source that could not be
	// consulted rather than from a definite answer.
	unavailable bool
}

// Evaluate evaluates every input and returns one Outcome per input, in the same
// order. It never returns an error: whatever could not be fetched or run is
// reported inside the subjects as skipped checks. A canceled ctx ends the run
// early with the remaining checks skipped.
func (r *Runner) Evaluate(ctx context.Context, inputs []Input) []Outcome {
	rn := r.prepare()
	resolved := make([]resolution, len(inputs))
	rn.forEach(len(inputs), func(i int) {
		resolved[i] = rn.resolve(ctx, &inputs[i])
	})

	refs := make([]model.PackageRef, 0, len(resolved))
	for i := range resolved {
		if resolved[i].skip == "" {
			refs = append(refs, resolved[i].ref)
		}
	}
	rn.loader.Prefetch(ctx, refs)

	out := make([]Outcome, len(inputs))
	rn.forEach(len(inputs), func(i int) {
		out[i] = rn.evaluate(ctx, &inputs[i], &resolved[i])
	})
	return out
}

// Run is Evaluate for a caller that wants the report subjects only.
func (r *Runner) Run(ctx context.Context, inputs []Input) []report.Subject {
	return Subjects(r.Evaluate(ctx, inputs))
}

func (r *Runner) prepare() *run {
	if r.Loader == nil {
		panic("checks: Runner.Loader is nil")
	}
	rn := &run{
		loader:  r.Loader,
		policy:  r.Policy,
		checks:  r.Checks,
		jobs:    r.Jobs,
		timeout: r.Timeout,
		now:     r.Now,
		log:     r.Log,
	}
	if rn.checks == nil {
		rn.checks = All()
	}
	if rn.jobs < 1 {
		rn.jobs = DefaultJobs
	}
	if rn.timeout <= 0 {
		rn.timeout = DefaultTimeout
	}
	if rn.now.IsZero() {
		rn.now = time.Now()
	}
	if rn.log == nil {
		rn.log = slog.New(slog.DiscardHandler)
	}
	return rn
}

// forEach calls fn for every index with at most jobs calls in flight, using a
// buffered channel as the semaphore, and returns when all have finished.
func (rn *run) forEach(n int, fn func(i int)) {
	sem := make(chan struct{}, rn.jobs)
	var wg sync.WaitGroup
	for i := range n {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}()
	}
	wg.Wait()
}

// resolve turns a bare ref into the latest stable version of the package. A ref
// that already carries a version passes through untouched.
func (rn *run) resolve(ctx context.Context, in *Input) resolution {
	ref := in.Ref
	if ref.Version != "" {
		return resolution{ref: ref}
	}
	list, err := rn.loader.Versions(ctx, ref.Ecosystem, ref.Name)
	if err != nil {
		rn.log.Debug("cannot resolve latest version", "package", ref.String(), "error", err)
		return resolution{ref: ref, skip: sourceProblem(SourceRegistry, err), unavailable: !definite(err)}
	}
	latest := registry.LatestStable(list)
	if latest == nil {
		rn.log.Debug("no stable version to resolve", "package", ref.String())
		return resolution{ref: ref, skip: "no stable version"}
	}
	rn.log.Debug("resolved latest stable version", "package", ref.String(), "version", latest.Ref.Version)
	return resolution{ref: ref.WithVersion(latest.Ref.Version), latest: true}
}

// evaluate assembles the Subject for one input and runs the checks over it.
func (rn *run) evaluate(ctx context.Context, in *Input, res *resolution) Outcome {
	out := Outcome{Subject: report.Subject{Ref: res.ref, Location: in.Location, Direct: in.Direct}}
	s := &Subject{
		Ref:            res.ref,
		Location:       in.Location,
		Direct:         in.Direct,
		Lock:           in.Lock,
		Now:            rn.now,
		Settings:       rn.policy.Effective(res.ref.Ecosystem),
		ResolvedLatest: res.latest,
		Downloads:      -1,
		Unavailable:    map[string]error{},
		Loader:         rn.loader,
	}
	applicable := rn.applicable(s)
	if res.skip != "" {
		return skipAll(&out, applicable, res.skip, res.unavailable)
	}
	if reason := rn.load(ctx, s); reason != "" {
		return skipAll(&out, applicable, reason, false)
	}
	rn.loadBase(ctx, s, in.BaseVersion)

	outages := s.outageReasons()
	out.Subject.Findings = append(out.Subject.Findings, rn.expiredAllows(s)...)
	for _, c := range applicable {
		if c.Name() == cooldownExcludedCheck && rn.policy.CooldownExcluded(s.Ref) {
			out.Subject.Skipped = append(out.Subject.Skipped, model.Skipped{Check: c.ID(), Reason: "excluded by cooldown_exclude"})
			continue
		}
		result, unfinished := rn.runCheck(ctx, c, s)
		if result.Skipped != nil {
			skipped := *result.Skipped
			// The report schema wants the TD id, whatever the check wrote.
			skipped.Check = c.ID()
			out.Subject.Skipped = append(out.Subject.Skipped, skipped)
			if unfinished || namesOutage(skipped.Reason, outages) {
				out.Unavailable = true
			}
			continue
		}
		out.Subject.Evaluated = append(out.Subject.Evaluated, c.ID())
		if len(result.Findings) == 0 {
			continue
		}
		if entry, ok := rn.policy.Allowed(c.Name(), s.Ref, rn.now); ok {
			rn.log.Debug("findings suppressed by allow entry",
				"check", c.ID(), "ref", s.Ref.String(), "findings", len(result.Findings),
				"package", entry.Package.String(), "reason", entry.Reason, "expires", entry.Expires.String())
			continue
		}
		out.Subject.Findings = append(out.Subject.Findings, result.Findings...)
	}
	finish(&out.Subject)
	return out
}

// skipAll marks every applicable check skipped with one reason, for a subject
// nothing can be evaluated for. The outcome counts as unavailable only when the
// reason is an outage and a check was actually skipped for it.
func skipAll(out *Outcome, applicable []Check, reason string, unavailable bool) Outcome {
	for _, c := range applicable {
		out.Subject.Skipped = append(out.Subject.Skipped, model.Skipped{Check: c.ID(), Reason: reason})
	}
	out.Unavailable = unavailable && len(applicable) > 0
	finish(&out.Subject)
	return *out
}

// namesOutage reports whether a check's skip reason carries the wording
// Subject.Skipped gave for a source that could not be consulted. Checks build
// their reasons from those strings (see the Runner doc), so the match is exact:
// a reason that merely uses the word "unavailable" does not count, and a
// definite answer such as not found never does.
func namesOutage(reason string, outages []string) bool {
	for _, outage := range outages {
		if strings.Contains(reason, outage) {
			return true
		}
	}
	return false
}

// applicable returns the checks that apply to the subject's ecosystem and whose
// effective level is not off, in id order.
func (rn *run) applicable(s *Subject) []Check {
	out := make([]Check, 0, len(rn.checks))
	for _, c := range rn.checks {
		if !AppliesTo(c, s.Ref.Ecosystem) {
			continue
		}
		if s.Setting(c.Name()).Level == model.LevelOff {
			rn.log.Debug("check is off", "check", c.ID(), "ref", s.Ref.String())
			continue
		}
		out = append(out, c)
	}
	slices.SortStableFunc(out, func(a, b Check) int { return cmp.Compare(a.ID(), b.ID()) })
	return out
}

// load fetches everything the checks may need, recording per source what could
// not be fetched. It returns a reason when the registry has no such package or
// version, in which case nothing else is fetched: the caller skips every check
// with it. Sources are loaded one after the other; the batch sources were
// prefetched, so most of these are memo hits.
func (rn *run) load(ctx context.Context, s *Subject) string {
	ref := s.Ref
	if list, err := rn.loader.Versions(ctx, ref.Ecosystem, ref.Name); err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return sourceProblem(SourceRegistry, err)
		}
		s.Unavailable[SourceRegistry] = err
	} else {
		s.Package = list
		s.Previous = registry.Previous(list, ref)
		rn.loadPrevious(ctx, s)
	}
	if info, err := rn.loader.VersionInfo(ctx, ref); err != nil {
		// A version the registry does not have is not a reason to skip the checks
		// that do not read the registry. Removing a malicious release is how a
		// registry reacts to it (npm leaves a security holding placeholder where
		// flatmap-stream 0.1.1 was), while OSV and deps.dev keep the advisory, so
		// the checks that read them must still run and report it. The checks that
		// need the version skip themselves on the reason recorded here.
		if _, seen := s.Unavailable[SourceRegistry]; !seen {
			s.Unavailable[SourceRegistry] = err
		}
	} else {
		// The loader hands the same pointer to every subject; copy it so that a
		// check writing to the subject's version cannot reach the memo entry.
		copied := *info
		s.Version = &copied
	}
	if owners, err := rn.loader.Owners(ctx, ref.Ecosystem, ref.Name); err != nil {
		s.Unavailable[SourceOwners] = err
	} else {
		s.Owners = owners
	}
	if advisories, err := rn.loader.Advisories(ctx, ref); err != nil {
		s.Unavailable[SourceOSV] = err
	} else {
		s.Advisories = advisories
	}
	if facts, err := rn.loader.DepsDev(ctx, ref); err != nil {
		s.Unavailable[SourceDepsDev] = err
	} else {
		s.DepsDev = facts
	}
	if fl, ok := rn.loader.(DepsDevFindingsLoader); ok {
		if findings, err := fl.DepsDevFindings(ctx, ref); err != nil {
			if _, seen := s.Unavailable[SourceDepsDev]; !seen {
				s.Unavailable[SourceDepsDev] = err
			}
		} else {
			s.DepsDevFindings = findings
		}
	} else {
		rn.log.Debug("loader has no deps.dev findings; leaving them empty", "ref", ref.String())
	}
	if count, err := rn.loader.Downloads(ctx, ref.Ecosystem, ref.Name); err != nil {
		s.Unavailable[SourceDownloads] = err
	} else {
		s.Downloads = count
	}
	for source, err := range s.Unavailable {
		rn.log.Debug("source unavailable", "source", source, "ref", ref.String(), "error", err)
	}
	return ""
}

// loadPrevious replaces the previous version's list entry with its full detail.
// The list carries what the package-level response had, while the comparisons
// (dependencies, install scripts, provenance) need the per-version answer, which
// may take another request. When that request fails the list entry stays, for
// its publish time and publisher, and the failure is recorded under
// SourcePrevious so the comparing checks skip instead of reading facts the entry
// may not carry.
func (rn *run) loadPrevious(ctx context.Context, s *Subject) {
	if s.Previous == nil {
		return
	}
	prev, err := rn.loader.VersionInfo(ctx, s.Previous.Ref)
	if err != nil {
		rn.log.Debug("previous version details unavailable, keeping the list entry", "ref", s.Previous.Ref.String(), "error", err)
		s.Unavailable[SourcePrevious] = err
		return
	}
	copied := *prev
	s.Previous = &copied
}

// loadBase fetches the version the base lockfile locked, when diff named one and
// it is neither the evaluated version nor the release the registry calls
// previous. Upgrading across several releases makes those differ, and what the
// project actually had is the comparison a pull request gate cares about (brief
// section 4.1). A failure leaves PreviousInBase nil and is recorded like any
// other previous-version failure, so a check that wanted it skips rather than
// comparing against nothing.
func (rn *run) loadBase(ctx context.Context, s *Subject, baseVersion string) {
	if baseVersion == "" || baseVersion == s.Ref.Version {
		return
	}
	if s.Previous != nil && s.Previous.Ref.Version == baseVersion {
		return
	}
	ref := s.Ref.WithVersion(baseVersion)
	info, err := rn.loader.VersionInfo(ctx, ref)
	if err != nil {
		rn.log.Debug("base version details unavailable", "ref", ref.String(), "error", err)
		if _, seen := s.Unavailable[SourcePrevious]; !seen {
			s.Unavailable[SourcePrevious] = err
		}
		return
	}
	copied := *info
	s.PreviousInBase = &copied
}

// expiredAllows builds one expired-allow finding per expired entry whose package
// pattern matches the subject.
func (rn *run) expiredAllows(s *Subject) []model.Finding {
	var out []model.Finding
	expired := rn.policy.ExpiredAllows(rn.now)
	for i := range expired {
		entry := &expired[i]
		if !entry.Package.Match(s.Ref) {
			continue
		}
		f := policy.ExpiredAllowFinding(entry, s.Ref, rn.now)
		f.Location = s.Location
		out = append(out, f)
	}
	return out
}

// runCheck runs one check under the per-check timeout and recovers a panic. The
// check runs in its own goroutine so that a check ignoring ctx cannot hold the
// subject; the result channel is buffered so that goroutine can always finish.
// unfinished is true when the check did not return in time (timeout, canceled
// run): the data was not available to it, whatever the reason says.
func (rn *run) runCheck(ctx context.Context, c Check, s *Subject) (result Result, unfinished bool) {
	cctx, cancel := context.WithTimeout(ctx, rn.timeout)
	defer cancel()
	done := make(chan Result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				rn.log.Error("check panicked", "check", c.ID(), "ref", s.Ref.String(), "panic", p, "stack", string(debug.Stack()))
				done <- Skip(c.ID(), fmt.Sprintf("check panicked: %v", p))
			}
		}()
		done <- c.Run(cctx, s)
	}()
	select {
	case result := <-done:
		return result, false
	case <-cctx.Done():
		if ctx.Err() != nil {
			return Skip(c.ID(), fmt.Sprintf("run canceled: %v", ctx.Err())), true
		}
		rn.log.Warn("check timed out", "check", c.ID(), "ref", s.Ref.String(), "timeout", rn.timeout)
		return Skip(c.ID(), fmt.Sprintf("timed out after %s", rn.timeout)), true
	}
}

// finish orders the subject's slices so that the same run always renders the
// same bytes: evaluated ids ascending, skipped by check then reason, findings by
// id then title.
func finish(out *report.Subject) {
	slices.Sort(out.Evaluated)
	slices.SortStableFunc(out.Skipped, func(a, b model.Skipped) int {
		return cmp.Or(cmp.Compare(a.Check, b.Check), cmp.Compare(a.Reason, b.Reason))
	})
	slices.SortStableFunc(out.Findings, func(a, b model.Finding) int {
		return cmp.Or(cmp.Compare(a.ID, b.ID), cmp.Compare(a.Title, b.Title))
	})
}
