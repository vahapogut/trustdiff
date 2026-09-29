package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/baseline"
	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/report"
	"github.com/vahapogut/trustdiff/internal/watch"
)

func (a *App) newWatchCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch [<path>]",
		Short: "Re-evaluate a reviewed baseline and report trust changes",
		Long: `Load the existing .trustdiff/baseline.json found upward from a directory,
the working directory by default. Evaluate its pinned versions immediately and
then after each interval. The first report is always printed; subsequent reports
are printed only when findings or check coverage change. Nothing is written to
the baseline, and changes to it or to lockfiles require restarting the command.

Online evaluations bypass the HTTP cache to request current registry and advisory
data on every cycle. Offline mode uses existing caches and cannot discover new
remote data. Evaluations never overlap: the interval starts after a run completes.

Use --once with an external scheduler. It returns the ordinary report exit code.
Continuous mode keeps monitoring findings and outages until canceled (exit 3).
Formats are human or newline-delimited JSON events (trustdiff.watch/1).`,
		Args: cobra.MaximumNArgs(1),
		RunE: a.runWatch,
	}
	cmd.Flags().Bool("once", false, "evaluate the baseline once and exit with the report status")
	cmd.Flags().Duration("interval", watch.DefaultInterval, "delay between completed evaluations (1m to 24h)")
	return cmd
}

func (a *App) runWatch(cmd *cobra.Command, args []string) error {
	if a.Opts.Format != "human" && a.Opts.Format != "json" {
		return Usagef("watch supports --format human or json (newline-delimited events)")
	}
	interval, _ := cmd.Flags().GetDuration("interval")
	if interval < watch.MinInterval || interval > watch.MaxInterval {
		return Usagef("watch --interval must be between 1m and 24h")
	}
	st, err := a.settle()
	if err != nil {
		return err
	}
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	info, err := os.Stat(dir)
	if err != nil {
		return Usagef("watch directory %q: %v", dir, err)
	}
	if !info.IsDir() {
		return Usagef("watch path %q must be a directory", dir)
	}
	path, err := a.baselinePath(dir)
	if err != nil {
		return err
	}
	recorded, err := a.readBaseline(path)
	if err != nil {
		return err
	}
	if recorded == nil || len(recorded.Packages) == 0 {
		return Usagef("watch requires an existing, nonempty baseline; run trustdiff baseline and review it first")
	}
	inputs := make([]checks.Input, 0, len(recorded.Packages))
	for i := range recorded.Packages {
		ref := recorded.Packages[i].Ref()
		if _, err := model.ParseRef(ref.String()); err != nil {
			return Usagef("watch baseline: %v", err)
		}
		inputs = append(inputs, checks.Input{Ref: ref})
	}
	note := fmt.Sprintf("watching %s from %s; baseline and policy are fixed for this session",
		countOf(len(inputs), "package", "packages"), path)
	if a.Opts.Offline {
		note += "; offline caches cannot reveal new remote data"
	} else {
		note += "; each cycle requests fresh data without the HTTP cache"
	}
	if err := a.writeNotes([]string{note}); err != nil {
		return err
	}
	once, _ := cmd.Flags().GetBool("once")
	loop := watch.Loop{Interval: interval, Once: once, Now: func() time.Time { return baselineClock(st) }}
	code, err := loop.Run(cmd.Context(), func(ctx context.Context) (*report.Report, error) {
		return a.evaluateWatch(ctx, st, inputs, recorded)
	}, func(event watch.Event) error { return a.writeWatchEvent(st, &event) })
	if err != nil {
		return err
	}
	if code != ExitOK {
		return Exit(code, nil)
	}
	return nil
}

func (a *App) evaluateWatch(ctx context.Context, st *settings, inputs []checks.Input, recorded *baseline.File) (*report.Report, error) {
	// A fresh memo alone is not enough: advisory responses otherwise remain fresh
	// in the HTTP cache for hours. Keep ordinary offline cache semantics while
	// online watch makes a fresh request on each cycle without changing the cache.
	cycle := *a
	if !cycle.Opts.Offline {
		cycle.Opts.NoCache = true
	}
	loader, err := loaderFactory(&cycle, st.now)
	if err != nil {
		return nil, Usagef("%v", err)
	}
	selected := checks.All()
	for i := range selected {
		if selected[i].ID() == baselineCheckID {
			selected[i] = watchMaintainers{recorded: recorded}
		}
	}
	runner := &checks.Runner{
		Loader: withBaseline(loader, &baseline.Set{Head: recorded}), Policy: st.pol,
		Checks: selected, Jobs: a.Opts.Jobs, Timeout: checkTimeout,
		Now: st.now, Log: a.Opts.Log,
	}
	outcomes := runner.Evaluate(ctx, inputs)
	rep := report.Build(checks.Subjects(outcomes), report.CurrentTool(), report.Policy{
		Path: st.policyPath, Cooldown: st.cooldown, FailOn: a.Opts.FailOn,
	}, st.failOn)
	if rep.Summary.ExitCode == ExitOK && dataUnavailableFails(st.pol, outcomes) {
		rep.SetExitCode(ExitUnavailable)
	}
	a.addGuardDog(ctx, rep, inputs)
	return rep, nil
}

func (a *App) writeWatchEvent(st *settings, event *watch.Event) error {
	if a.Opts.Format == "json" {
		if err := json.NewEncoder(a.Stdout).Encode(event); err != nil {
			return fmt.Errorf("write watch event: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintf(a.Stdout, "watch %s at %s\n", event.Kind, event.ObservedAt.Format(time.RFC3339)); err != nil {
		return fmt.Errorf("write watch event: %w", err)
	}
	for _, change := range event.Changes {
		if _, err := fmt.Fprintf(a.Stdout, "  %s %s: %s\n", change.Ref, change.Check, change.Kind); err != nil {
			return fmt.Errorf("write watch change: %w", err)
		}
	}
	if err := st.writer.Write(a.Stdout, event.Report); err != nil {
		return fmt.Errorf("write watch report: %w", err)
	}
	return nil
}

// watchMaintainers compares owners now with the reviewed observation. The usual
// TD003 prefers npm's release maintainer lists, which cannot reveal a takeover
// that happened after the same pinned release was published.
type watchMaintainers struct{ recorded *baseline.File }

func (watchMaintainers) ID() string                    { return baselineCheckID }
func (watchMaintainers) Name() string                  { return baselineCheck }
func (watchMaintainers) Ecosystems() []model.Ecosystem { return nil }

func (w watchMaintainers) Run(_ context.Context, s *checks.Subject) checks.Result {
	was, ok := w.recorded.Lookup(s.Ref)
	if !ok || len(was.Maintainers) == 0 {
		return checks.Skip(baselineCheckID, "the baseline records no maintainer set for this package")
	}
	if reason, unavailable := s.Skipped(checks.SourceOwners); unavailable {
		return checks.Skip(baselineCheckID, reason)
	}
	if len(s.Owners) == 0 {
		return checks.Skip(baselineCheckID, "the registry lists no maintainer for this package now")
	}
	fresh := baseline.Entry{
		Ecosystem: s.Ref.Ecosystem, Name: s.Ref.Name, Version: s.Ref.Version, ObservedAt: s.Now,
	}
	for _, owner := range s.Owners {
		fresh.Maintainers = append(fresh.Maintainers, owner.Name)
	}
	// Put normalizes the in-memory observation's owner set, not the baseline.
	observed := baseline.New(s.Now)
	observed.Put(&fresh)
	if len(observed.Packages[0].Maintainers) == 0 {
		return checks.Skip(baselineCheckID, "the registry lists no named maintainer for this package now")
	}
	changes := baseline.Compare(w.recorded, observed.Packages)
	if len(changes) == 0 {
		return checks.Result{}
	}
	return checks.Result{Findings: []model.Finding{driftFinding(&changes[0], s.Setting(baselineCheck).Level, s.Now)}}
}
