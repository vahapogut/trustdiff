// Command gen-toplists regenerates the popular package snapshots embedded in the
// binary for typosquat detection (internal/typosquat/data/*.txt). It downloads
// the same sources as "trustdiff cache refresh-lists": the hugovk
// top-pypi-packages artifact, the npm-high-impact and npm-rank lists, and 50
// pages of the crates.io list endpoint at one request per second with the
// identifying User-Agent, so a run takes about a minute.
//
// Usage:
//
//	go run ./scripts/gen-toplists [-out internal/typosquat/data] [-pages 50] [-v]
//
// Each file starts with a NOTICE line that records the source URL, the fetch
// date and the license observed for the source; commit the files together with
// the README under internal/typosquat/testdata that explains the choices.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/typosquat"
	"github.com/vahapogut/trustdiff/internal/version"
)

func main() {
	out := flag.String("out", "internal/typosquat/data", "directory to write npm.txt, pypi.txt and cargo.txt into")
	pages := flag.Int("pages", 50, "crates.io pages of 100 names to fetch")
	verbose := flag.Bool("v", false, "log every request")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err := run(*out, *pages, log); err != nil {
		fmt.Fprintf(os.Stderr, "gen-toplists: %v\n", err)
		os.Exit(1)
	}
}

func run(out string, pages int, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// No disk cache: the snapshot is recorded once and must not pick up a copy an
	// earlier run left in the user cache.
	client, err := httpcache.New(httpcache.Options{NoCache: true, UserAgent: version.UserAgent(), Logger: log})
	if err != nil {
		return err
	}
	sources := typosquat.DefaultSources()
	sources.CratesPages = pages
	lists, err := typosquat.Fetch(ctx, client, typosquat.WithSources(sources), typosquat.WithLogger(log))
	if err != nil {
		return err
	}
	if err := typosquat.WriteLists(out, lists); err != nil {
		return err
	}
	for _, list := range lists {
		fmt.Printf("%s: %d names from %s\n", list.Ecosystem, len(list.Names), list.Source)
	}
	return nil
}
