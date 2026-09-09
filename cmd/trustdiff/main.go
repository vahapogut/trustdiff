// Command trustdiff is the entry point of the trustdiff CLI. All behavior lives in internal/cli.
package main

import (
	"os"

	"github.com/vahapogut/trustdiff/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
