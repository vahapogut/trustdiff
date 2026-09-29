package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/registry"
	"github.com/vahapogut/trustdiff/internal/registry/crates/dumpindex"
	"github.com/vahapogut/trustdiff/internal/version"
)

var cratesRefreshOptions = func() dumpindex.Options { return dumpindex.Options{} }

type cratesIndexReport struct {
	dumpindex.Stats
	AgeSeconds float64 `json:"age_seconds"`
	Stale      bool    `json:"stale"`
	StaleAfter string  `json:"stale_after"`
}

func cratesStatus(stats dumpindex.Stats, now time.Time) cratesIndexReport {
	r := cratesIndexReport{Stats: stats, StaleAfter: "48h"}
	if stats.Meta != nil {
		r.AgeSeconds = stats.Meta.Age(now).Seconds()
		r.Stale = stats.Meta.Stale(now)
	}
	return r
}

func (a *App) writeCratesStatus(r *cratesIndexReport) error {
	if r.Error != "" {
		_, err := fmt.Fprintf(a.Stdout, "Crates dump: unreadable (%s)\n", r.Error)
		return err
	}
	if r.Meta == nil {
		_, err := fmt.Fprintln(a.Stdout, "Crates dump: none, run \"trustdiff cache refresh --crates-dump\" for bulk Cargo scans")
		return err
	}
	stale := ""
	if r.Stale {
		stale = ", stale; run trustdiff cache refresh --crates-dump"
	}
	_, err := fmt.Fprintf(a.Stdout, "Crates dump: %d crates, %d versions, snapshot %s (%s)%s\n", r.Meta.Crates, r.Meta.Versions, formatAge(time.Duration(r.AgeSeconds)*time.Second), formatBytes(r.Bytes), stale)
	return err
}

func (a *App) cacheRefreshCrates(cmd *cobra.Command, dirFlag string) error {
	if a.Opts.Offline {
		return Usagef("cache refresh --crates-dump downloads the registry database and cannot run with --offline")
	}
	dir, err := resolveCacheDir(dirFlag)
	if err != nil {
		return err
	}
	opts := cratesRefreshOptions()
	opts.UserAgent = version.UserAgent()
	meta, err := dumpindex.Refresh(cmd.Context(), dir, &opts)
	if err != nil {
		return Exit(ExitUnavailable, err)
	}
	if a.Opts.Format == "json" {
		if err := a.writeJSON(meta); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(a.Stdout, "Indexed %d crates and %d versions from the %s snapshot in %s\n", meta.Crates, meta.Versions, meta.SnapshotAt.Format(time.RFC3339), dumpindex.Dir(dir)); err != nil {
			return err
		}
	}
	if dirFlag != "" {
		if _, err := fmt.Fprintf(a.Stderr, "trustdiff: set TRUSTDIFF_CACHE_DIR=%s for scans to read this crates dump index\n", dir); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) bulkCratesSource(dir string, api registry.Source, now time.Time) registry.Source {
	if now.IsZero() {
		now = time.Now()
	}
	index, err := dumpindex.Open(dir, now)
	if err == nil {
		a.Opts.Log.Debug("using crates dump for bulk scan", "snapshot", index.Meta.SnapshotAt, "crates", index.Meta.Crates)
		return index
	}
	_, presentErr := os.Lstat(filepath.Join(dumpindex.Dir(dir), "current.json"))
	if !errors.Is(presentErr, os.ErrNotExist) {
		fmt.Fprintf(a.Stderr, "trustdiff: crates dump unavailable (%v); using the ordinary Cargo API/cache path\n", err)
	}
	return api
}
