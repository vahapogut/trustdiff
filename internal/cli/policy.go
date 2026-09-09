package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vahapogut/trustdiff/internal/policy"
)

// policy subcommands: init writes the commented default file, validate loads a file
// through the same strict decoder and schema the other commands use.
func (a *App) newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Create or validate the .trustdiff.yaml policy file",
		// See newCacheCommand: without these two, a mistyped subcommand exits 0.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}

	var output string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Write a commented default policy file",
		Long: `Write the default policy, with a comment explaining every key, to .trustdiff.yaml
in the working directory (or to --output). An existing file is never overwritten.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			path := output
			if path == "" {
				path = policy.FileName
			}
			if err := policy.WriteDefault(path); err != nil {
				if errors.Is(err, policy.ErrExists) {
					return Usagef("%v (remove it first, or pass --output to write elsewhere)", err)
				}
				return Usagef("%v", err)
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				abs = path
			}
			if a.Opts.Format == "json" {
				enc := json.NewEncoder(a.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"path": abs, "written": true})
			}
			_, err = fmt.Fprintf(a.Stdout, "wrote %s\n", abs)
			return err
		},
	}
	initCmd.Flags().StringVarP(&output, "output", "o", "", "where to write the policy (default: .trustdiff.yaml in the working directory)")

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the policy file against its schema",
		Long: `Load the policy named by --policy, or the .trustdiff.yaml found upward from the
working directory, or the user-level policy, and report every problem. Exit code 2
when the file is invalid or none is found.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			path, err := a.policyPath()
			if err != nil {
				return err
			}
			if _, err := policy.Load(path); err != nil {
				return Usagef("%v", err)
			}
			if a.Opts.Format == "json" {
				enc := json.NewEncoder(a.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"path": path, "valid": true})
			}
			_, err = fmt.Fprintf(a.Stdout, "policy %s: valid\n", path)
			return err
		},
	}

	cmd.AddCommand(initCmd, validateCmd)
	return cmd
}

// policyPath resolves the policy file: --policy, then discovery from the working
// directory. A missing file is a usage error so scripts get exit code 2.
func (a *App) policyPath() (string, error) {
	if a.Opts.Policy != "" {
		return a.Opts.Policy, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", Usagef("working directory: %v", err)
	}
	path, found, err := policy.Find(cwd)
	if err != nil {
		return "", Usagef("%v", err)
	}
	if !found {
		return "", Usagef("no policy file found: create one with \"trustdiff policy init\" or pass --policy <file>")
	}
	return path, nil
}
