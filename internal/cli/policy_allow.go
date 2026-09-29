package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/checks"
	"github.com/vahapogut/trustdiff/internal/policy"
	"github.com/vahapogut/trustdiff/internal/textdiff"
)

func (a *App) newPolicyAllowCommand() *cobra.Command {
	var reason, expires string
	var write bool
	cmd := &cobra.Command{
		Use:   "allow <check-id-or-name> <ecosystem:package[@version]>",
		Short: "Preview a reviewed exception with a reason and expiry; --write saves it",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			check, ok := checks.Lookup(args[0])
			if !ok {
				return Usagef("unknown check %q", args[0])
			}
			path, err := a.policyPath()
			if err != nil {
				return err
			}
			stat, err := os.Lstat(path)
			if err != nil {
				return Usagef("policy: %v", err)
			}
			if !stat.Mode().IsRegular() || stat.Size() > 1<<20 {
				return Usagef("policy must be a regular file at most 1 MiB")
			}
			before, err := os.ReadFile(path) // #nosec G304 -- user-selected policy path, regular file checked above
			if err != nil {
				return Usagef("policy: %v", err)
			}
			now, err := runClock(os.Getenv(nowEnv))
			if err != nil {
				return err
			}
			// runClock leaves the default for Runner to resolve. This command has
			// no runner, so resolve it before checking expiry or naming a backup.
			if now.IsZero() {
				now = time.Now()
			}
			after, err := policy.AddAllow(before, check.Name(), args[1], reason, expires, now)
			if err != nil {
				return Usagef("policy allow: %v", err)
			}
			changed := !bytes.Equal(before, after)
			backup := ""
			if write && changed {
				current, err := os.ReadFile(path) // #nosec G304 -- same user-selected policy path
				if err != nil || !bytes.Equal(current, before) {
					return Usagef("policy changed during review; run the command again")
				}
				backup, err = textdiff.Backup(path, now)
				if err != nil {
					return Usagef("backup policy: %v", err)
				}
				if err := textdiff.Write(path, after, stat.Mode().Perm()); err != nil {
					return Usagef("write policy: %v", err)
				}
			}
			diff := string(textdiff.Unified(path, path, before, after))
			if a.Opts.Format == "json" {
				return json.NewEncoder(a.Stdout).Encode(map[string]any{"path": path, "changed": changed, "written": write && changed, "backup": backup, "diff": diff})
			}
			if !changed {
				_, err = fmt.Fprintln(a.Stdout, "exception already present; no change")
				return err
			}
			if _, err := fmt.Fprint(a.Stdout, diff); err != nil {
				return err
			}
			if write {
				_, err = fmt.Fprintf(a.Stdout, "wrote %s (backup: %s)\n", path, backup)
			} else {
				_, err = fmt.Fprintln(a.Stdout, "preview only; pass --write to save with a backup")
			}
			return err
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why this specific finding was reviewed and accepted (required)")
	cmd.Flags().StringVar(&expires, "expires", "", "last valid UTC date, YYYY-MM-DD (required)")
	cmd.Flags().BoolVar(&write, "write", false, "save the exception atomically after creating a backup")
	return cmd
}
