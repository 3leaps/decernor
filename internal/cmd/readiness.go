package cmd

import (
	"fmt"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/spf13/cobra"

	"github.com/3leaps/decernor/internal/readiness"
)

func newReadinessCmd(identity *appidentity.Identity) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "readiness",
		Short: "Validate readiness configuration and future capability checks",
		Long: fmt.Sprintf(`Validate readiness configurations for signing and authentication capability checks.

Examples:
  %s readiness validate-config examples/github-org-bootstrap.readiness.json`, identity.BinaryName),
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "validate-config PATH",
		Short: "Validate a readiness config file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := readiness.LoadConfig(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("valid readiness config: %s capabilities=%d\n", cfg.Name, len(cfg.Capabilities))
			return nil
		},
	})

	return cmd
}
