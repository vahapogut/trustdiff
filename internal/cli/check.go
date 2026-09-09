package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/advisory/depsdev"
	"github.com/vahapogut/trustdiff/internal/advisory/osv"
	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/registry/crates"
	"github.com/vahapogut/trustdiff/internal/registry/npm"
	"github.com/vahapogut/trustdiff/internal/registry/pypi"
	"github.com/vahapogut/trustdiff/internal/report"
	"github.com/vahapogut/trustdiff/internal/version"
)

// loaderFactory builds the data loader for a run. Tests replace it with a fake so
// the command can be exercised without registries.
var loaderFactory = func(a *App) (checks.Loader, error) { return a.defaultLoader() }

// nowEnv overrides the run's clock for tests and the demo, as RFC 3339.
const nowEnv = "TRUSTDIFF_NOW"

func (a *App) newCheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "check <ref>...",
		Short: "Evaluate one or more package versions",
		Long: `Evaluate package versions given as <ecosystem>:<name>[@<version>], for example
npm:express@4.19.2, pypi:requests or cargo:serde. Without a version the latest
non-prerelease version is evaluated and the report says so.

The policy comes from --policy, else from the .trustdiff.yaml found upward from the
working directory, else from the user-level policy, else from the built-in defaults.`,
		Args: cobra.MinimumNArgs(1),
		RunE: a.runCheck,
	}
}

func (a *App) runCheck(cmd *cobra.Command, args []string) error {
	inputs := make([]checks.Input, 0, len(args))
	for _, arg := range args {
		ref, err := model.ParseRef(arg)
		if err != nil {
			if looksLikeManifest(arg) {
				return Usagef("%s: evaluating a manifest file arrives in a later release; pass <ecosystem>:<name>[@<version>] refs", arg)
			}
			return Usagef("%v", err)
		}
		inputs = append(inputs, checks.Input{Ref: ref})
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

	loader, err := loaderFactory(a)
	if err != nil {
		return Usagef("%v", err)
	}
	runner := &checks.Runner{
		Loader: loader,
		Policy: pol,
		Jobs:   a.Opts.Jobs,
		Now:    now,
		Log:    a.Opts.Log,
	}
	subjects := runner.Run(cmd.Context(), inputs)

	failOn, err := report.ParseFailOn(a.Opts.FailOn)
	if err != nil {
		return Usagef("%v", err)
	}
	rep := report.Build(subjects, report.CurrentTool(), report.Policy{
		Path:     policyPath,
		Cooldown: cooldownSpelling,
		FailOn:   a.Opts.FailOn,
	}, failOn)
	if dataUnavailableFails(pol, subjects) {
		rep.SetExitCode(ExitUnavailable)
	}

	writer, err := report.New(a.Opts.Format, report.Options{Color: a.Opts.Color, Width: a.Opts.Width})
	if err != nil {
		return Usagef("%v", err)
	}
	if err := writer.Write(a.Stdout, rep); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if rep.Summary.ExitCode != ExitOK {
		return Exit(rep.Summary.ExitCode, nil)
	}
	return nil
}

// looksLikeManifest recognizes the manifest paths the brief allows as refs, so the
// error can say the feature is planned instead of calling the path an invalid ref.
func looksLikeManifest(arg string) bool {
	base := strings.ToLower(arg)
	for _, name := range []string{"package.json", "pyproject.toml", "cargo.toml"} {
		if strings.HasSuffix(base, name) {
			return true
		}
	}
	return false
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

// dataUnavailableFails reports whether a data source was unavailable for a
// subject whose ecosystem policy says on_data_unavailable: fail. Checks phrase
// those reasons as "<source> unavailable: ..." through Subject.Skipped.
func dataUnavailableFails(pol *policy.Policy, subjects []report.Subject) bool {
	for i := range subjects {
		s := &subjects[i]
		if pol.Effective(s.Ref.Ecosystem).OnDataUnavailable != policy.OnDataUnavailableFail {
			continue
		}
		for _, sk := range s.Skipped {
			if strings.Contains(sk.Reason, "unavailable") {
				return true
			}
		}
	}
	return false
}

// defaultLoader wires the real registries and advisory sources behind one HTTP
// cache client configured from the global flags.
func (a *App) defaultLoader() (checks.Loader, error) {
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
	}
	return checks.NewLoader(reg, osv.New(hc), depsdev.New(hc), log), nil
}
