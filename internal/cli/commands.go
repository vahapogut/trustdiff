package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/version"
)

func (a *App) newDiffCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Evaluate lockfile changes against a git base",
		Long: `Evaluate only the lockfile entries that were added or changed since a git base.
The default base is the merge-base of HEAD with origin/main.`,
		Args: cobra.NoArgs,
		RunE: notImplemented("diff"),
	}
	cmd.Flags().String("base", "", "git ref to compare against (default: merge-base with origin/main)")
	cmd.Flags().String("base-file", "", "compare against this lockfile instead of a git ref")
	cmd.Flags().Bool("update-baseline", false, "write the observed trust signals to .trustdiff/baseline.json")
	return cmd
}

func (a *App) newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [<path>]",
		Short: "Evaluate every entry of every lockfile found under a path",
		Args:  cobra.MaximumNArgs(1),
		RunE:  notImplemented("scan"),
	}
	cmd.Flags().Bool("update-baseline", false, "write the observed trust signals to .trustdiff/baseline.json")
	return cmd
}

func (a *App) newDoctorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor [<path>]",
		Short: "Audit or fix package manager hardening settings",
		Args:  cobra.MaximumNArgs(1),
		RunE:  notImplemented("doctor"),
	}
	cmd.Flags().Bool("fix", false, "write the recommended settings, with a diff preview and backups")
	cmd.Flags().Bool("ci", false, "exit 1 when any setting is missing or wrong at or above the policy severity")
	cmd.Flags().Bool("user", false, "also report user-level configuration files")
	return cmd
}

func (a *App) newBaselineCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "baseline",
		Short: "Snapshot the current trust signals of all locked packages",
		Args:  cobra.NoArgs,
		RunE:  notImplemented("baseline"),
	}
}

func (a *App) newHookCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage the git pre-commit and pre-push hook that runs diff",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "install", Short: "Install the git hook", Args: cobra.NoArgs, RunE: notImplemented("hook install")},
		&cobra.Command{Use: "uninstall", Short: "Remove the git hook", Args: cobra.NoArgs, RunE: notImplemented("hook uninstall")},
	)
	return cmd
}

func (a *App) newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, build date and Go version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := version.Get()
			if a.Opts.Format == "json" {
				enc := json.NewEncoder(a.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}
			_, err := fmt.Fprintln(a.Stdout, info.String())
			return err
		},
	}
}
