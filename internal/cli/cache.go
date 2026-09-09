package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/advisory/osvindex"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/typosquat"
	"github.com/vahapogut/trustdiff/internal/version"
)

// refreshOptions lets the tests point "cache refresh" at an httptest server and
// shorten its budget. Nothing outside tests sets it, so the command uses the
// real bucket and the real defaults.
var refreshOptions = func() osvindex.Options { return osvindex.Options{} }

// cache subcommands. status and clear are thin wrappers over internal/httpcache
// and internal/advisory/osvindex; refresh downloads the OSV advisory archives
// and rebuilds the offline index; refresh-lists downloads the popular package
// lists the typosquat check compares a name against.
func (a *App) newCacheCommand() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect or refresh the local data cache",
		// NoArgs is what makes a mistyped subcommand a usage error, and RunE is what makes
		// NoArgs run at all: cobra returns help for a command with no body of its own
		// before it ever validates the arguments, so "trustdiff cache refresh-lsits"
		// would exit 0 and read as a success. With both, a bare "trustdiff cache" still
		// prints its help and exits 0, which is what a group of subcommands should do.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.PersistentFlags().StringVar(&dir, "cache-dir", "",
		"cache directory for this command only; the other commands read $"+httpcache.EnvDir+
			" when set, otherwise the trustdiff directory under the user cache directory")

	var ecosystems []string
	refresh := &cobra.Command{
		Use:   "refresh",
		Short: "Download the advisory databases for offline use",
		Long: `Download the OSV advisory archive of each configured ecosystem and rebuild the
offline index under the cache directory. With the index in place, --offline
answers the advisory checks from it instead of reporting them as skipped.

The ecosystems come from the "ecosystems" block of the policy when it names any
that OSV publishes an archive for, otherwise every ecosystem OSV indexes (npm,
pypi and cargo). --ecosystem overrides both.

The download is conditional: an archive the server reports as unchanged since the
last refresh is not transferred again and the index on disk is kept.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.cacheRefresh(cmd, dir, ecosystems)
		},
	}
	refresh.Flags().StringSliceVar(&ecosystems, "ecosystem", nil,
		"ecosystem to refresh, repeatable (default: the ecosystems the policy configures)")

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
		&cobra.Command{
			Use:   "refresh-lists",
			Short: "Refresh the popular package lists used for typosquat detection",
			Long: `Download the popular package lists of npm, PyPI and crates.io into the cache,
where the typosquat check prefers them over the snapshot compiled into the binary
for thirty days.

The lists are what a name is compared with, so a stale one is a package that
became popular after the release and is not recognized as the thing a squat
imitates. It makes about fifty requests to crates.io at one request per second,
so it takes about a minute, and nothing is written unless every source answered.`,
			Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return a.cacheRefreshLists(cmd, dir)
			},
		},
		refresh,
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
	// AdvisoryIndex describes the offline advisory index, which is what
	// --offline reads. It is always present, with an empty ecosystem list when
	// nothing has been downloaded.
	AdvisoryIndex cacheIndexReport `json:"advisory_index"`
}

// cacheIndexReport is the advisory index half of "cache status".
type cacheIndexReport struct {
	Dir        string           `json:"dir"`
	Bytes      int64            `json:"bytes"`
	StaleAfter string           `json:"stale_after"`
	Ecosystems []cacheIndexEcho `json:"ecosystems"`
}

// cacheIndexEcho is one indexed ecosystem as the json report prints it: the
// stored metadata plus the two values a reader would otherwise have to compute,
// the age and whether that age is past the staleness threshold.
type cacheIndexEcho struct {
	osvindex.Meta
	AgeSeconds float64 `json:"age_seconds"`
	Stale      bool    `json:"stale"`
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
	index, err := osvindex.Stat(dir)
	if err != nil {
		return Exit(ExitUsage, fmt.Errorf("cache status: %w", err))
	}
	now := time.Now()

	if a.Opts.Format == "json" {
		report := cacheStatusReport{
			Dir:             dir,
			Entries:         stats.Entries,
			Bytes:           stats.Bytes,
			OldestFetchedAt: stats.OldestFetchedAt,
			NewestFetchedAt: stats.NewestFetchedAt,
			AdvisoryIndex: cacheIndexReport{
				Dir:        index.Dir,
				Bytes:      index.Bytes,
				StaleAfter: policy.FormatDuration(osvindex.StaleAfter),
				Ecosystems: make([]cacheIndexEcho, 0, len(index.Ecosystems)),
			},
		}
		for i := range index.Ecosystems {
			meta := index.Ecosystems[i]
			report.AdvisoryIndex.Ecosystems = append(report.AdvisoryIndex.Ecosystems, cacheIndexEcho{
				Meta:       meta,
				AgeSeconds: meta.Age(now).Seconds(),
				Stale:      meta.Stale(now),
			})
		}
		return a.writeJSON(report)
	}

	oldest, newest := "none", "none"
	if stats.Entries > 0 {
		oldest = formatAge(now.Sub(stats.OldestFetchedAt))
		newest = formatAge(now.Sub(stats.NewestFetchedAt))
	}
	if _, err := fmt.Fprintf(a.Stdout, "Directory: %s\nEntries:   %d\nSize:      %s\nOldest:    %s\nNewest:    %s\n",
		dir, stats.Entries, formatBytes(stats.Bytes), oldest, newest); err != nil {
		return err
	}
	return a.writeIndexStatus(&index, now)
}

// writeIndexStatus prints the advisory index block of "cache status": which
// ecosystems are indexed, how many advisories each holds, how old the download
// is, and out loud when that age is past the threshold. A stale advisory index
// that looks fresh is worse than none, so the line says so rather than leaving
// the reader to subtract dates.
func (a *App) writeIndexStatus(index *osvindex.Stats, now time.Time) error {
	if len(index.Ecosystems) == 0 {
		_, err := fmt.Fprintf(a.Stdout, "Advisory index: none, run \"trustdiff cache refresh\" to use --offline\n")
		return err
	}
	if _, err := fmt.Fprintf(a.Stdout, "Advisory index: %s in %s\n", formatBytes(index.Bytes), index.Dir); err != nil {
		return err
	}
	indexed := make(map[model.Ecosystem]bool, len(index.Ecosystems))
	for i := range index.Ecosystems {
		meta := &index.Ecosystems[i]
		indexed[meta.Ecosystem] = true
		line := fmt.Sprintf("  %-6s %d advisories", meta.Ecosystem, meta.Advisories)
		if meta.Withdrawn > 0 {
			line += fmt.Sprintf(" (%d withdrawn)", meta.Withdrawn)
		}
		line += fmt.Sprintf(", %d packages, downloaded %s", meta.Packages, formatAge(meta.Age(now)))
		if meta.Stale(now) {
			line += fmt.Sprintf(", stale (older than %s), run \"trustdiff cache refresh\"", policy.FormatDuration(osvindex.StaleAfter))
		}
		if _, err := fmt.Fprintln(a.Stdout, line); err != nil {
			return err
		}
	}
	for _, eco := range osvindex.Indexable() {
		if indexed[eco] {
			continue
		}
		if _, err := fmt.Fprintf(a.Stdout, "  %-6s not downloaded\n", eco); err != nil {
			return err
		}
	}
	return nil
}

// cacheClearReport is the --format json shape of "cache clear". The counts are
// what was actually removed, so a run that refused one half reports the other
// half's bytes and zero for the half it kept.
type cacheClearReport struct {
	Dir            string `json:"dir"`
	RemovedEntries int    `json:"removed_entries"`
	RemovedBytes   int64  `json:"removed_bytes"`
	// RemovedIndexBytes is the part of RemovedBytes that was the advisory index.
	RemovedIndexBytes int64 `json:"removed_index_bytes"`
	// Refused names what was kept and why, empty when everything was removed.
	Refused string `json:"refused,omitempty"`
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
	index, err := osvindex.Stat(dir)
	if err != nil {
		return Exit(ExitUsage, fmt.Errorf("cache clear: %w", err))
	}
	// The advisory index goes first, because it is the one that may leave its
	// directory behind: osvindex.Clear removes every file it owns and keeps
	// anything else, naming what it kept, so a cache directory that is not one
	// still keeps its contents. httpcache.Clear then steps around that directory
	// whether or not it survived, so a refusal over one stray advisory file never
	// costs the rest of the cache. Both refusals are reported together, because
	// somebody who asked for the cache to be cleared wants to know everything
	// that was kept and not only the first thing.
	indexErr := osvindex.Clear(dir)
	refused := errors.Join(indexErr, httpcache.Clear(dir))

	// What was removed is measured rather than assumed, because a refusal is
	// partial now: the index files of an ecosystem go even when a file beside
	// them is kept, and the counts have to say what actually happened.
	afterCache, cacheStatErr := httpcache.Stat(dir)
	afterIndex, indexStatErr := osvindex.Stat(dir)
	if statErr := errors.Join(cacheStatErr, indexStatErr); statErr != nil {
		return Exit(ExitUsage, fmt.Errorf("cache clear: %w", errors.Join(statErr, refused)))
	}
	removed := cacheClearReport{
		Dir:               dir,
		RemovedEntries:    before.Entries - afterCache.Entries,
		RemovedBytes:      (before.Bytes - afterCache.Bytes) + (index.Bytes - afterIndex.Bytes),
		RemovedIndexBytes: index.Bytes - afterIndex.Bytes,
	}
	a.Opts.Log.Debug("cache cleared", "dir", dir, "entries", removed.RemovedEntries,
		"bytes", removed.RemovedBytes, "index_bytes", removed.RemovedIndexBytes, "refused", refused)

	if err := a.writeClearReport(&removed, refused); err != nil {
		return err
	}
	if refused != nil {
		return Exit(ExitUsage, fmt.Errorf("cache clear: %w", refused))
	}
	return nil
}

// writeClearReport prints what "cache clear" removed. Nothing is printed when a
// refusal left nothing removed, so a run that could do nothing says so on stderr
// alone and stdout stays reserved for reports.
func (a *App) writeClearReport(removed *cacheClearReport, refused error) error {
	if refused != nil && removed.RemovedEntries == 0 && removed.RemovedBytes == 0 {
		return nil
	}
	if a.Opts.Format == "json" {
		if refused != nil {
			removed.Refused = refused.Error()
		}
		return a.writeJSON(removed)
	}
	if removed.RemovedEntries == 0 && removed.RemovedBytes == 0 {
		_, err := fmt.Fprintf(a.Stdout, "Nothing to remove in %s\n", removed.Dir)
		return err
	}
	suffix := ""
	if removed.RemovedIndexBytes > 0 {
		suffix = fmt.Sprintf(", the advisory index included (%s)", formatBytes(removed.RemovedIndexBytes))
	}
	_, err := fmt.Fprintf(a.Stdout, "Removed %d entries (%s) from %s%s\n",
		removed.RemovedEntries, formatBytes(removed.RemovedBytes), removed.Dir, suffix)
	return err
}

// cacheRefreshReport is the --format json shape of "cache refresh".
type cacheRefreshReport struct {
	Dir        string                  `json:"dir"`
	Ecosystems []cacheRefreshEcosystem `json:"ecosystems"`
}

// cacheRefreshEcosystem is one ecosystem's outcome. Error is the message when
// that ecosystem failed; the others in the same run still report what they did.
type cacheRefreshEcosystem struct {
	Ecosystem     model.Ecosystem `json:"ecosystem"`
	Unchanged     bool            `json:"unchanged"`
	WroteShards   int             `json:"wrote_shards"`
	RemovedShards int             `json:"removed_shards"`
	Meta          *osvindex.Meta  `json:"meta,omitempty"`
	Error         string          `json:"error,omitempty"`
}

func (a *App) cacheRefresh(cmd *cobra.Command, dirFlag string, ecosystemFlag []string) error {
	dir, err := resolveCacheDir(dirFlag)
	if err != nil {
		return err
	}
	ecosystems, err := a.refreshEcosystems(ecosystemFlag)
	if err != nil {
		return err
	}
	opts := refreshOptions()
	opts.UserAgent = version.UserAgent()
	opts.Logger = a.Opts.Log
	if a.Opts.Offline {
		return Usagef("cache refresh downloads the advisory archives and cannot run with --offline")
	}

	results, err := osvindex.Refresh(cmd.Context(), dir, ecosystems, opts)
	if err != nil {
		return Usagef("cache refresh: %v", err)
	}

	report := cacheRefreshReport{Dir: dir, Ecosystems: make([]cacheRefreshEcosystem, 0, len(results))}
	failed := 0
	for i := range results {
		res := &results[i]
		entry := cacheRefreshEcosystem{
			Ecosystem:     res.Ecosystem,
			Unchanged:     res.Unchanged,
			WroteShards:   res.WroteShards,
			RemovedShards: res.RemovedShards,
		}
		if res.Err != nil {
			failed++
			entry.Error = res.Err.Error()
		} else {
			meta := res.Meta
			entry.Meta = &meta
		}
		report.Ecosystems = append(report.Ecosystems, entry)
	}

	if a.Opts.Format == "json" {
		if err := a.writeJSON(report); err != nil {
			return err
		}
	} else if err := a.writeRefreshLines(&report); err != nil {
		return err
	}
	if err := a.warnUnreadableIndexDir(dirFlag, dir); err != nil {
		return err
	}
	if failed > 0 {
		// A refresh that could not reach a source is the same condition
		// on_data_unavailable describes: the data is not there, and a later run
		// may succeed. The messages went to stdout with the rest of the report,
		// so the exit carries no second copy.
		return Exit(ExitUnavailable, nil)
	}
	return nil
}

// warnUnreadableIndexDir says out loud when "cache refresh" has written an index
// where no other command will look for it.
//
// --cache-dir belongs to the cache command alone: the other commands build their
// cache client from the global flags and take the directory from $TRUSTDIFF_CACHE_DIR
// or the platform default, so "cache refresh --cache-dir X" followed by
// "check --offline" reads an index that is not there and reports every advisory
// check as skipped. Making the flag global would mean changing the root command
// and the loader every command shares, which is a wider change than this defect
// needs and a decision about the whole flag set rather than about the cache; the
// mismatch is made impossible to hit silently instead. The refresh still writes
// where it was told to, since a run that fills a cache directory for a container
// or a CI artifact is exactly what the flag is for, and the line names the
// environment variable that makes the choice reach every command.
func (a *App) warnUnreadableIndexDir(dirFlag, dir string) error {
	if dirFlag == "" {
		return nil
	}
	other, err := httpcache.DefaultDir()
	if err == nil && sameDir(other, dir) {
		return nil
	}
	if err != nil {
		// The other commands cannot locate their cache directory either, so the
		// warning is still the right answer; it just cannot name a directory
		// that is not there.
		a.Opts.Log.Debug("could not locate the default cache directory", "error", err)
		other = "the default cache directory"
	}
	_, err = fmt.Fprintf(a.Stderr, "trustdiff: the advisory index is in %s, but the other commands read %s; "+
		"set %s=%s so that \"trustdiff check --offline\" reads this index\n", dir, other, httpcache.EnvDir, dir)
	return err
}

// sameDir compares two directory paths as the file system would on this platform.
// It is a spelling comparison, not a resolution: two paths that reach the same
// directory through a symbolic link read as different, which costs a warning
// nobody needed and never hides one that was needed.
func sameDir(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// writeRefreshLines prints one line per ecosystem.
func (a *App) writeRefreshLines(report *cacheRefreshReport) error {
	for i := range report.Ecosystems {
		e := &report.Ecosystems[i]
		var line string
		switch {
		case e.Error != "":
			line = fmt.Sprintf("  %-6s failed: %s", e.Ecosystem, e.Error)
		case e.Unchanged:
			line = fmt.Sprintf("  %-6s unchanged, %d advisories for %d packages", e.Ecosystem, e.Meta.Advisories, e.Meta.Packages)
		default:
			line = fmt.Sprintf("  %-6s %d advisories for %d packages, %s indexed from %s downloaded",
				e.Ecosystem, e.Meta.Advisories, e.Meta.Packages, formatBytes(e.Meta.IndexBytes), formatBytes(e.Meta.ArchiveBytes))
			if e.WroteShards == 0 && e.RemovedShards == 0 {
				line += ", index unchanged"
			}
		}
		if _, err := fmt.Fprintln(a.Stdout, line); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(a.Stdout, "Advisory index in %s\n", osvindex.Dir(report.Dir))
	return err
}

// refreshEcosystems decides what "cache refresh" downloads: --ecosystem when
// given, otherwise the ecosystems the policy configures, otherwise every
// ecosystem OSV publishes an archive for. An ecosystem OSV does not index (Deno,
// JSR) is a usage error when it was asked for by name and is quietly left out
// when it only came from the policy, since a policy that configures Deno is not
// asking for an advisory archive that does not exist.
func (a *App) refreshEcosystems(flag []string) ([]model.Ecosystem, error) {
	if len(flag) > 0 {
		out := make([]model.Ecosystem, 0, len(flag))
		for _, name := range flag {
			eco, err := model.ParseEcosystem(name)
			if err != nil {
				return nil, Usagef("--ecosystem: %v", err)
			}
			if osvindex.OSVEcosystem(eco) == "" {
				return nil, Usagef("--ecosystem: OSV publishes no advisory archive for %s (it indexes %s)",
					eco, joinEcosystemNames(osvindex.Indexable()))
			}
			if !slices.Contains(out, eco) {
				out = append(out, eco)
			}
		}
		return out, nil
	}
	pol, _, err := a.loadPolicyOrDefault()
	if err != nil {
		return nil, err
	}
	var configured []model.Ecosystem
	if pol != nil {
		for _, eco := range osvindex.Indexable() {
			if _, ok := pol.Ecosystems[eco]; ok {
				configured = append(configured, eco)
			}
		}
	}
	if len(configured) > 0 {
		a.Opts.Log.Debug("refreshing the ecosystems the policy configures", "ecosystems", configured)
		return configured, nil
	}
	return osvindex.Indexable(), nil
}

// joinEcosystemNames renders an ecosystem list for a message.
func joinEcosystemNames(ecosystems []model.Ecosystem) string {
	names := make([]string, len(ecosystems))
	for i, eco := range ecosystems {
		names[i] = string(eco)
	}
	return strings.Join(names, ", ")
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

// cacheRefreshLists downloads the popular package lists into the cache.
//
// It is a separate command from "cache refresh", which downloads the advisory
// archives, because the two are different sizes and different schedules: the
// lists are a megabyte and change slowly, the advisories are two hundred and
// change hourly. A project that wants both runs both.
func (a *App) cacheRefreshLists(cmd *cobra.Command, dirFlag string) error {
	dir, err := resolveCacheDir(dirFlag)
	if err != nil {
		return err
	}
	if a.Opts.Offline {
		return Usagef("cache refresh-lists downloads the popular package lists and cannot run with --offline")
	}
	// The lists are fetched without the disk cache: a refresh that answered from
	// the copy an earlier refresh left would write the same file back and report
	// it as new.
	client, err := httpcache.New(httpcache.Options{
		NoCache:   true,
		UserAgent: version.UserAgent(),
		Logger:    a.Opts.Log,
	})
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	if err := typosquat.Refresh(cmd.Context(), client, dir, typosquat.WithLogger(a.Opts.Log)); err != nil {
		return Exit(ExitUnavailable, err)
	}
	written := typosquat.ListsDir(dir)
	lists := typosquat.Load(dir, time.Now(), a.Opts.Log)
	if a.Opts.Format != "human" {
		return a.writeJSON(map[string]any{
			"dir":   filepath.ToSlash(written),
			"lists": listCounts(lists),
		})
	}
	if _, err := fmt.Fprintf(a.Stdout, "Popular package lists in %s\n", written); err != nil {
		return err
	}
	for _, eco := range model.Ecosystems() {
		list, ok := lists.List(eco)
		if !ok {
			continue
		}
		if _, err := fmt.Fprintf(a.Stdout, "  %-6s %d names from %s\n", eco, len(list.Names), list.Source); err != nil {
			return err
		}
	}
	return nil
}

// listCounts is the json shape of what was written: one entry per ecosystem with
// the number of names and where they came from, which is what a reader checking
// whether a refresh did anything wants.
func listCounts(lists *typosquat.Lists) map[string]any {
	out := map[string]any{}
	for _, eco := range model.Ecosystems() {
		list, ok := lists.List(eco)
		if !ok {
			continue
		}
		out[string(eco)] = map[string]any{
			"names":   len(list.Names),
			"source":  list.Source,
			"fetched": list.Fetched,
			"license": list.License,
		}
	}
	return out
}
