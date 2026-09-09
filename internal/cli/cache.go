package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/httpcache"
)

// cache subcommands. status and clear are thin wrappers over internal/httpcache;
// refresh-lists and refresh arrive in later milestones.
func (a *App) newCacheCommand() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect or refresh the local data cache",
	}
	cmd.PersistentFlags().StringVar(&dir, "cache-dir", "",
		"cache directory (default: $"+httpcache.EnvDir+" when set, otherwise the trustdiff directory under the user cache directory)")
	cmd.AddCommand(
		&cobra.Command{
			Use:   "status",
			Short: "Show cache location, size and age",
			Args:  cobra.NoArgs,
			RunE: func(_ *cobra.Command, _ []string) error {
				return a.cacheStatus(dir)
			},
		},
		&cobra.Command{
			Use:   "clear",
			Short: "Delete the cache",
			Args:  cobra.NoArgs,
			RunE: func(_ *cobra.Command, _ []string) error {
				return a.cacheClear(dir)
			},
		},
		&cobra.Command{Use: "refresh-lists", Short: "Refresh the popular package lists used for typosquat detection", Args: cobra.NoArgs, RunE: notImplemented("cache refresh-lists")},
		&cobra.Command{Use: "refresh", Short: "Download the advisory databases for offline use", Args: cobra.NoArgs, RunE: notImplemented("cache refresh")},
	)
	return cmd
}

// resolveCacheDir applies the precedence: --cache-dir, then TRUSTDIFF_CACHE_DIR,
// then the platform default.
func resolveCacheDir(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	dir, err := httpcache.DefaultDir()
	if err != nil {
		return "", Usagef("cache directory: %v", err)
	}
	return dir, nil
}

// cacheStatusReport is the --format json shape of "cache status".
type cacheStatusReport struct {
	Dir             string    `json:"dir"`
	Entries         int       `json:"entries"`
	Bytes           int64     `json:"bytes"`
	OldestFetchedAt time.Time `json:"oldest_fetched_at,omitzero"`
	NewestFetchedAt time.Time `json:"newest_fetched_at,omitzero"`
}

func (a *App) cacheStatus(dirFlag string) error {
	dir, err := resolveCacheDir(dirFlag)
	if err != nil {
		return err
	}
	stats, err := httpcache.Stat(dir)
	if err != nil {
		return Exit(ExitUsage, fmt.Errorf("cache status: %w", err))
	}
	if a.Opts.Format == "json" {
		return a.writeJSON(cacheStatusReport{
			Dir:             dir,
			Entries:         stats.Entries,
			Bytes:           stats.Bytes,
			OldestFetchedAt: stats.OldestFetchedAt,
			NewestFetchedAt: stats.NewestFetchedAt,
		})
	}
	now := time.Now()
	oldest, newest := "none", "none"
	if stats.Entries > 0 {
		oldest = formatAge(now.Sub(stats.OldestFetchedAt))
		newest = formatAge(now.Sub(stats.NewestFetchedAt))
	}
	_, err = fmt.Fprintf(a.Stdout, "Directory: %s\nEntries:   %d\nSize:      %s\nOldest:    %s\nNewest:    %s\n",
		dir, stats.Entries, formatBytes(stats.Bytes), oldest, newest)
	return err
}

// cacheClearReport is the --format json shape of "cache clear".
type cacheClearReport struct {
	Dir            string `json:"dir"`
	RemovedEntries int    `json:"removed_entries"`
	RemovedBytes   int64  `json:"removed_bytes"`
}

func (a *App) cacheClear(dirFlag string) error {
	dir, err := resolveCacheDir(dirFlag)
	if err != nil {
		return err
	}
	before, err := httpcache.Stat(dir)
	if err != nil {
		return Exit(ExitUsage, fmt.Errorf("cache clear: %w", err))
	}
	if err := httpcache.Clear(dir); err != nil {
		return Exit(ExitUsage, fmt.Errorf("cache clear: %w", err))
	}
	a.Opts.Log.Debug("cache cleared", "dir", dir, "entries", before.Entries, "bytes", before.Bytes)
	if a.Opts.Format == "json" {
		return a.writeJSON(cacheClearReport{Dir: dir, RemovedEntries: before.Entries, RemovedBytes: before.Bytes})
	}
	if before.Entries == 0 && before.Bytes == 0 {
		_, err = fmt.Fprintf(a.Stdout, "Nothing to remove in %s\n", dir)
		return err
	}
	_, err = fmt.Fprintf(a.Stdout, "Removed %d entries (%s) from %s\n", before.Entries, formatBytes(before.Bytes), dir)
	return err
}

func (a *App) writeJSON(v any) error {
	enc := json.NewEncoder(a.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// formatAge renders how long ago something happened, coarsely: this is for a
// status line, not for arithmetic.
func formatAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "less than a minute ago"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %dm ago", int(d.Hours()), int(d.Minutes())%60)
	default:
		hours := int(d.Hours())
		return fmt.Sprintf("%dd %dh ago", hours/24, hours%24)
	}
}

// formatBytes renders a size with binary units.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f PiB", value/unit)
}
