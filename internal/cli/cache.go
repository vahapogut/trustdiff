package cli

import "github.com/spf13/cobra"

// cache subcommands. status and clear are implemented with the http cache (task 0.8);
// refresh-lists and refresh arrive in later milestones.
func (a *App) newCacheCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect or refresh the local data cache",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "status", Short: "Show cache location, size and age", Args: cobra.NoArgs, RunE: notImplemented("cache status")},
		&cobra.Command{Use: "clear", Short: "Delete the cache", Args: cobra.NoArgs, RunE: notImplemented("cache clear")},
		&cobra.Command{Use: "refresh-lists", Short: "Refresh the popular package lists used for typosquat detection", Args: cobra.NoArgs, RunE: notImplemented("cache refresh-lists")},
		&cobra.Command{Use: "refresh", Short: "Download the advisory databases for offline use", Args: cobra.NoArgs, RunE: notImplemented("cache refresh")},
	)
	return cmd
}
