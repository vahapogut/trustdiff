package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/version"
)

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
