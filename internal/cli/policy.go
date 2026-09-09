package cli

import "github.com/spf13/cobra"

// policy subcommands, implemented with internal/policy (task 0.7).
func (a *App) newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Create or validate the .trustdiff.yaml policy file",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "init", Short: "Write a commented default policy file", Args: cobra.NoArgs, RunE: notImplemented("policy init")},
		&cobra.Command{Use: "validate", Short: "Validate the policy file against its schema", Args: cobra.NoArgs, RunE: notImplemented("policy validate")},
	)
	return cmd
}
