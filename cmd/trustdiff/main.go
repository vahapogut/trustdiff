// Command trustdiff is the entry point of the trustdiff CLI. All behavior lives in internal/cli.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/vahapogut/trustdiff/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.MainContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
