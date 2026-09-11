package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/advisory/osv"
	"github.com/vahapogut/trustdiff/internal/advisory/osvindex"
	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/manifest"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/registry/crates"
	"github.com/vahapogut/trustdiff/internal/registry/jsr"
	"github.com/vahapogut/trustdiff/internal/registry/npm"
	"github.com/vahapogut/trustdiff/internal/registry/pypi"
	"github.com/vahapogut/trustdiff/internal/report"
	"github.com/vahapogut/trustdiff/internal/version"
)

// loaderFactory builds the data loader for a run from the run's clock, zero when
// the run has none of its own. Tests replace it with a fake so the command can be
// exercised without registries.
var loaderFactory = func(a *App, now time.Time) (checks.Loader, error) { return a.defaultLoader(now) }

// checkTimeout bounds one check for one subject; zero means checks.DefaultTimeout.
// Tests shorten it to exercise the timed-out path.
var checkTimeout time.Duration

// nowEnv overrides the run's clock for tests and the demo, as RFC 3339.
const nowEnv = "TRUSTDIFF_NOW"

func (a *App) newCheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "check <ref|manifest>...",
		Short: "Evaluate one or more package versions, or a manifest's direct dependencies",
		Long: `Evaluate package versions given as <ecosystem>:<name>[@<version>], for example
npm:express@4.19.2, pypi:requests or cargo:serde. Without a version the latest
non-prerelease version is evaluated and the report says so.

An argument that names a package.json, a pyproject.toml or a Cargo.toml evaluates
that file's direct dependencies at the versions their ranges resolve to today, so
it answers what an install run now would bring in. A declaration with no published
version behind it, a git URL or a path or a range trustdiff cannot read, is named
beside the report rather than guessed at.

The policy comes from --policy, else from the .trustdiff.yaml found upward from the
working directory, else from the user-level policy, else from the built-in defaults.`,
		Args: cobra.MinimumNArgs(1),
		RunE: a.runCheck,
	}
}

func (a *App) runCheck(cmd *cobra.Command, args []string) error {
	targets, err := readCheckArgs(args)
	if err != nil {
		return err
	}

	pol, policyPath, err := a.loadPolicyOrDefault()
	if err != nil {
		return err
	}
	pol, cooldownSpelling := a.applyCooldownOverride(pol)

	now, err := runClock(os.Getenv(nowEnv))
	if err != nil {
		return err
	}

	// Everything that can reject the command line is settled before the loader
	// is built, so a format the writer does not have yet fails at once instead
	// of after the full network run.
	failOn, err := report.ParseFailOn(a.Opts.FailOn)
	if err != nil {
		return Usagef("%v", err)
	}
	writer, err := report.New(a.Opts.Format, report.Options{Color: a.Opts.Color, Width: a.Opts.Width})
	if err != nil {
		return Usagef("%v", err)
	}

	loader, err := loaderFactory(a, now)
	if err != nil {
		return Usagef("%v", err)
	}

	// A manifest's declarations are resolved through the run's own loader, so the
	// packument a range was resolved against is the one the checks then read.
	inputs, notes, incomplete := a.checkInputs(cmd.Context(), loader, targets)
	if err := a.writeNotes(notes); err != nil {
		return err
	}

	runner := &checks.Runner{
		Loader:  loader,
		Policy:  pol,
		Jobs:    a.Opts.Jobs,
		Timeout: checkTimeout,
		Now:     now,
		Log:     a.Opts.Log,
	}
	outcomes := runner.Evaluate(cmd.Context(), inputs)

	rep := report.Build(checks.Subjects(outcomes), report.CurrentTool(), report.Policy{
		Path:     policyPath,
		Cooldown: cooldownSpelling,
		FailOn:   a.Opts.FailOn,
	}, failOn)
	// Exit code 1 says there is something to act on now, 3 that the answer is
	// incomplete. When both apply the findings win: a script that retries on 3
	// must not retry past a block.
	if rep.Summary.ExitCode == ExitOK && (dataUnavailableFails(pol, outcomes) || unreadFails(pol, incomplete)) {
		rep.SetExitCode(ExitUnavailable)
	}

	if err := writer.Write(a.Stdout, rep); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if rep.Summary.ExitCode != ExitOK {
		return Exit(rep.Summary.ExitCode, nil)
	}
	return nil
}

// checkTarget is one argument of the command: either a package ref to evaluate as
// it stands, or a manifest whose direct dependencies are resolved once the loader
// exists.
type checkTarget struct {
	ref model.PackageRef
	// manifest is the parsed file, nil when the argument was a ref.
	manifest *manifest.Manifest
}

// readCheckArgs reads the command line. A ref stays a ref; a path naming one of the
// manifests trustdiff reads is read from disk here, before the loader is built,
// because a file that cannot be read is a usage error and a usage error must not
// cost a run over the registries. Anything else keeps the invalid-ref error it has
// always had.
func readCheckArgs(args []string) ([]checkTarget, error) {
	targets := make([]checkTarget, 0, len(args))
	for _, arg := range args {
		ref, err := model.ParseRef(arg)
		if err == nil {
			targets = append(targets, checkTarget{ref: ref})
			continue
		}
		if _, ok := manifest.For(arg); !ok {
			return nil, Usagef("%v", err)
		}
		m, readErr := readManifest(arg)
		if readErr != nil {
			return nil, Usagef("%v", readErr)
		}
		targets = append(targets, checkTarget{manifest: m})
	}
	return targets, nil
}

// readManifest reads one manifest named on the command line, and only if it is a
// plain file.
//
// A path in a repository is text somebody chose, and git records a symbolic link as
// a blob holding the link text, so a manifest committed as a link to any path on the
// machine would otherwise put that file into the report and into the registry
// lookups. openLockfile refuses one for the same reason; this is that rule for a
// file that is not a lockfile, which is the whole of the difference between them.
func readManifest(path string) (*manifest.Manifest, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return nil, fmt.Errorf("%s: a symbolic link, not a manifest: trustdiff does not follow links out of the tree it evaluates", path)
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s: not a regular file, so not a manifest trustdiff reads", path)
	}
	f, err := os.Open(path) // #nosec G304 -- the path is a manifest the user named, and Lstat above has refused everything that is not a plain file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// The report names the file the way the user typed it, with forward slashes so
	// that a location reads the same on every platform.
	return manifest.Read(filepath.ToSlash(path), f)
}

// checkInputs turns the arguments into the subjects to evaluate. Every manifest
// declaration is resolved against its registry through the run's own loader, whose
// memo then serves the checks for free, and the notes that come back are what the
// run could not resolve.
//
// incomplete says that a declaration was left unresolved because a registry could
// not be consulted, which is the same kind of partial answer as a lockfile no parser
// got through and follows on_data_unavailable in the same way. A git or path
// dependency is not that: it is a definite answer that no run will ever improve on.
func (a *App) checkInputs(ctx context.Context, src manifest.Source, targets []checkTarget) (inputs []checks.Input, notes []string, incomplete bool) {
	at := make(map[model.PackageRef]int, len(targets))
	add := func(in checks.Input) {
		// One package asked for twice, by two manifests or by two tables of one,
		// is one subject to evaluate, and it counts as direct if any of the
		// declarations that reached it was.
		if i, seen := at[in.Ref]; seen {
			if in.Direct {
				inputs[i].Direct = true
			}
			return
		}
		at[in.Ref] = len(inputs)
		inputs = append(inputs, in)
	}
	for _, target := range targets {
		if target.manifest == nil {
			add(checks.Input{Ref: target.ref})
			continue
		}
		m := target.manifest
		resolved, unresolved := manifest.Resolve(ctx, src, m.Dependencies, a.Opts.Jobs)
		for i := range resolved {
			add(checks.Input{
				Ref:      resolved[i].Ref,
				Location: &model.Location{Path: m.Path},
				Direct:   true,
			})
		}
		skipped := slices.Concat(m.Skipped, unresolved)
		for _, s := range skipped {
			if s.Unavailable {
				incomplete = true
			}
		}
		notes = append(notes, manifestNotes(m, len(resolved), skipped)...)
	}
	return inputs, notes, incomplete
}

// manifestNotes words what one manifest contributed to the run: how much is being
// evaluated, so a person knows to wait, and then one capped line for the
// declarations nothing was resolved for. It is the voice scan and diff use for what
// they could not read, because it is the same thing: a report that covers less than
// the file asked for has to say so.
func manifestNotes(m *manifest.Manifest, resolved int, skipped []manifest.Skipped) []string {
	// The count line, and at most one more for everything that was not resolved.
	notes := make([]string, 0, 2)
	notes = append(notes, fmt.Sprintf("%s: evaluating %s at the versions they resolve to today",
		m.Path, countOf(resolved, "direct dependency", "direct dependencies")))
	if len(skipped) == 0 {
		return notes
	}
	listed := make([]string, 0, len(skipped))
	for _, s := range skipped {
		listed = append(listed, s.String())
	}
	counted := "declarations were"
	if len(skipped) == 1 {
		counted = "declaration was"
	}
	return append(notes, fmt.Sprintf("%s: %d %s not resolved (%s)", m.Path, len(skipped), counted, listSome(listed)))
}

// loadPolicyOrDefault returns the loaded policy and its path, or a nil policy
// (built-in defaults) when no file exists and --policy was not given.
func (a *App) loadPolicyOrDefault() (*policy.Policy, string, error) {
	path := a.Opts.Policy
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, "", Usagef("working directory: %v", err)
		}
		found, ok, err := policy.Find(cwd)
		if err != nil {
			return nil, "", Usagef("%v", err)
		}
		if !ok {
			a.Opts.Log.Debug("no policy file found, using the built-in defaults")
			return nil, "", nil
		}
		path = found
	}
	pol, err := policy.Load(path)
	if err != nil {
		return nil, "", Usagef("%v", err)
	}
	a.Opts.Log.Debug("policy loaded", "path", path)
	return pol, path, nil
}

// applyCooldownOverride makes --cooldown win over the policy file and its
// per-ecosystem overrides, as the precedence rule in root.go states. It returns
// the policy to run with and the cooldown spelling for the report.
func (a *App) applyCooldownOverride(pol *policy.Policy) (*policy.Policy, string) {
	if a.Opts.Cooldown == "" {
		cooldown := policy.DefaultCooldown
		if pol != nil && pol.Cooldown != 0 {
			cooldown = time.Duration(pol.Cooldown)
		}
		return pol, policy.FormatDuration(cooldown)
	}
	d, err := policy.ParseDuration(a.Opts.Cooldown)
	if err != nil || d <= 0 {
		// prepare validated the flag already; keep the policy untouched if that changes.
		return pol, a.Opts.Cooldown
	}
	out := &policy.Policy{Version: 1}
	if pol != nil {
		copied := *pol
		out = &copied
		out.Ecosystems = make(map[model.Ecosystem]policy.EcosystemOverride, len(pol.Ecosystems))
		for eco, override := range pol.Ecosystems {
			override.Cooldown = 0
			out.Ecosystems[eco] = override
		}
	}
	out.Cooldown = policy.Duration(d)
	return out, policy.FormatDuration(d)
}

// jsrOptions are the JSR client's options for this run. JSR is the one registry
// that measures a window against a clock of its own: its download counts are daily
// buckets the client sums over the week ending now. The run's clock is passed only
// when the run has one, because a zero time would put that week in the year one and
// report every package as never installed.
func jsrOptions(log *slog.Logger, now time.Time) []jsr.Option {
	opts := []jsr.Option{jsr.WithLogger(log)}
	if !now.IsZero() {
		opts = append(opts, jsr.WithNow(func() time.Time { return now }))
	}
	return opts
}

// runClock parses the TRUSTDIFF_NOW override, or returns the zero time so the
// runner uses the wall clock.
func runClock(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, Usagef("%s must be an RFC 3339 time such as 2026-09-09T12:00:00Z, got %q", nowEnv, value)
	}
	return t, nil
}

// dataUnavailableFails reports whether a check was skipped because a data source
// could not be consulted, for a subject whose ecosystem policy says
// on_data_unavailable: fail. The runner decides that per outcome from the errors
// it saw (a timeout counts, a definite not-found or not-indexed answer does not);
// the wording of the skipped reasons is for people.
func dataUnavailableFails(pol *policy.Policy, outcomes []checks.Outcome) bool {
	for i := range outcomes {
		o := &outcomes[i]
		if !o.Unavailable {
			continue
		}
		if pol.Effective(o.Subject.Ref.Ecosystem).OnDataUnavailable == policy.OnDataUnavailableFail {
			return true
		}
	}
	return false
}

// defaultLoader wires the real registries and advisory sources behind one HTTP
// cache client configured from the global flags. now is the run's clock, already
// parsed by the caller, and zero when the run did not override it.
func (a *App) defaultLoader(now time.Time) (checks.Loader, error) {
	hc, err := httpcache.New(httpcache.Options{
		Offline:   a.Opts.Offline,
		NoCache:   a.Opts.NoCache,
		UserAgent: version.UserAgent(),
		Logger:    a.Opts.Log,
	})
	if err != nil {
		return nil, fmt.Errorf("cache: %w", err)
	}
	log := a.Opts.Log
	reg := registry.Registry{
		model.NPM:   npm.New(hc, npm.WithLogger(log)),
		model.PyPI:  pypi.New(hc, pypi.WithLogger(log)),
		model.Cargo: crates.New(hc, crates.WithLogger(log)),
		model.JSR:   jsr.New(hc, jsrOptions(log, now)...),
	}
	var osvOpts []osv.Option
	if a.Opts.Offline {
		// Offline the API is unreachable by definition, so OSV answers from the
		// index the cache holds. Open's error, when there is no index, reaches
		// every advisory check as the reason it was skipped, and that reason
		// begins with "offline".
		osvOpts = append(osvOpts, osv.WithIndex(osvindex.Open(hc.Dir())))
	}
	return checks.NewLoader(reg, osv.New(hc, osvOpts...), depsdev.New(hc), log), nil
}
