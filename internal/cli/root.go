// Package cli wires the trustdiff commands. It holds no business logic: every command
// parses its flags, calls into an internal package, and maps the result to an exit code.
package cli

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/version"
)

// Formats accepted by --format.
var formats = []string{"human", "json", "sarif", "markdown"}

// Levels accepted by --fail-on.
var failOnLevels = []string{"block", "warn", "never"}

// Options are the global flags shared by every command. Precedence for values that
// also exist in the policy file: command line flag, then the ecosystem override in
// the policy, then the policy value, then the built-in default.
type Options struct {
	Format   string
	Policy   string
	Offline  bool
	NoCache  bool
	Cooldown string
	FailOn   string
	Jobs     int
	NoColor  bool
	Verbose  bool

	// Derived at startup.
	Color bool
	Width int
	Log   *slog.Logger
}

// App carries the writers and options through the command tree.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Opts   Options
}

// Main runs the CLI with the given arguments and returns the process exit code.
// Errors are printed to stderr; stdout is reserved for reports.
func Main(args []string, stdout, stderr io.Writer) int {
	app := &App{Stdout: stdout, Stderr: stderr}
	root := app.newRootCommand()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Err != nil {
			fmt.Fprintf(stderr, "trustdiff: %v\n", exitErr.Err)
		}
		return exitErr.Code
	}
	fmt.Fprintf(stderr, "trustdiff: %v\n", err)
	return ExitUsage
}

func (a *App) newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "trustdiff",
		Short: "Detect trust regressions in a dependency tree before they land",
		Long: `trustdiff evaluates package versions and lockfile changes for trust regressions:
a publisher that changed, provenance that was lost, an install script or a new
dependency that was introduced, look-alike names, and known malicious or vulnerable
versions. It also audits package manager hardening settings with "doctor".

Exit codes: 0 no blocking findings, 1 blocking findings, 2 usage or configuration
error, 3 a required data source was unavailable and the policy says to fail.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return a.prepare(cmd)
		},
	}

	f := root.PersistentFlags()
	f.StringVar(&a.Opts.Format, "format", "human", "output format: human, json, sarif or markdown")
	f.StringVar(&a.Opts.Policy, "policy", "", "policy file (default: .trustdiff.yaml found upward from the working directory)")
	f.BoolVar(&a.Opts.Offline, "offline", false, "use only cached data; checks that need the network are reported as skipped")
	f.BoolVar(&a.Opts.NoCache, "no-cache", false, "ignore the disk cache for this run")
	f.StringVar(&a.Opts.Cooldown, "cooldown", "", "override the policy cooldown, for example 3d, 12h, 1w or P3D")
	f.StringVar(&a.Opts.FailOn, "fail-on", "block", "lowest finding level that makes the exit code 1: block, warn or never")
	f.IntVar(&a.Opts.Jobs, "jobs", 8, "maximum concurrent registry requests")
	f.BoolVar(&a.Opts.NoColor, "no-color", false, "disable colored output (NO_COLOR and non-terminal output also disable it)")
	f.BoolVarP(&a.Opts.Verbose, "verbose", "v", false, "log progress and diagnostics to stderr")

	root.AddCommand(
		a.newCheckCommand(),
		a.newDiffCommand(),
		a.newScanCommand(),
		a.newDoctorCommand(),
		a.newBaselineCommand(),
		a.newHookCommand(),
		a.newCacheCommand(),
		a.newPolicyCommand(),
		a.newVersionCommand(),
	)
	return root
}

// prepare validates the global flags and derives the runtime settings.
func (a *App) prepare(cmd *cobra.Command) error {
	o := &a.Opts
	if !slices.Contains(formats, o.Format) {
		return Usagef("--format must be one of %s, got %q", strings.Join(formats, ", "), o.Format)
	}
	if !slices.Contains(failOnLevels, o.FailOn) {
		return Usagef("--fail-on must be one of %s, got %q", strings.Join(failOnLevels, ", "), o.FailOn)
	}
	if o.Jobs < 1 {
		return Usagef("--jobs must be at least 1, got %d", o.Jobs)
	}
	if o.Offline && o.NoCache {
		return Usagef("--offline and --no-cache cannot be combined: offline mode has nothing but the cache to read from")
	}

	o.Color = colorEnabled(o.NoColor, os.LookupEnv, isTerminal(a.Stdout))
	o.Width = terminalWidth(a.Stdout, 100)

	level := slog.LevelWarn
	if o.Verbose {
		level = slog.LevelDebug
	}
	o.Log = slog.New(slog.NewTextHandler(a.Stderr, &slog.HandlerOptions{Level: level}))
	o.Log.Debug("starting", "command", cmd.Name(), "version", version.Version, "format", o.Format, "offline", o.Offline)
	return nil
}

// notImplemented is the placeholder body for commands that a later milestone fills in.
func notImplemented(name string) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, _ []string) error {
		return Usagef("%s: not implemented in %s", name, version.Version)
	}
}
