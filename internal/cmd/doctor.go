package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/fulmenhq/gofulmen/crucible"
	"github.com/fulmenhq/gofulmen/foundry"
)

// newDoctorCmd creates the doctor command
func newDoctorCmd(identity *appidentity.Identity) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run diagnostic checks",
		Long:  `Run diagnostic checks on the system and suggest fixes for common issues.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			var output strings.Builder
			output.WriteString("=== ")
			output.WriteString(identity.BinaryName)
			output.WriteString(" Doctor ===\n\n")
			output.WriteString("Running diagnostic checks...\n\n")

			allChecks := true
			exitCode := foundry.ExitSuccess

			// Check 1: Go version
			goVersion := runtime.Version()
			if goVersion >= "go1.21" {
				output.WriteString("[1/5] Go version... OK ")
				output.WriteString(goVersion)
				output.WriteString("\n")
			} else {
				output.WriteString("[1/5] Go version... WARN ")
				output.WriteString(goVersion)
				output.WriteString(" (recommended: go1.21+)\n")
				allChecks = false
			}

			// Check 2: Gofulmen/Crucible access
			version := crucible.GetVersion()
			if version.Gofulmen != "" {
				output.WriteString("[2/5] Gofulmen access... OK v")
				output.WriteString(version.Gofulmen)
				output.WriteString("\n")
			} else {
				output.WriteString("[2/5] Gofulmen access... FAIL Cannot access Gofulmen\n")
				allChecks = false
				exitCode = foundry.ExitExternalServiceUnavailable
			}

			if version.Crucible != "" {
				output.WriteString("[3/5] Crucible access... OK v")
				output.WriteString(version.Crucible)
				output.WriteString("\n")
			} else {
				output.WriteString("[3/5] Crucible access... WARN Cannot access Crucible (embedded version used)\n")
			}

			// Check 4: App Identity
			if identity.BinaryName != "" && identity.Vendor != "" {
				output.WriteString("[4/5] App identity... OK ")
				output.WriteString(identity.Vendor)
				output.WriteString(" / ")
				output.WriteString(identity.BinaryName)
				output.WriteString("\n")
			} else {
				output.WriteString("[4/5] App identity... FAIL Invalid app identity\n")
				allChecks = false
				exitCode = foundry.ExitConfigInvalid
			}

			// Check 5: Config directory
			homeDir, err := os.UserHomeDir()
			if err != nil {
				output.WriteString("[5/5] Config directory... FAIL Cannot find home directory: ")
				output.WriteString(err.Error())
				output.WriteString("\n")
				allChecks = false
				if exitCode == foundry.ExitSuccess {
					exitCode = foundry.ExitFileNotFound
				}
			} else {
				configDir := filepath.Join(homeDir, ".config", identity.Vendor)
				// Check if config directory exists or can be created
				if stat, err := os.Stat(configDir); err == nil && stat.IsDir() {
					output.WriteString("[5/5] Config directory... OK ")
					output.WriteString(configDir)
					output.WriteString("\n")
				} else {
					output.WriteString("[5/5] Config directory... WARN ")
					output.WriteString(configDir)
					output.WriteString(" (will be created on first config save)\n")
				}
			}

			output.WriteString("\n")
			if allChecks {
				output.WriteString("All checks passed. Your ")
				output.WriteString(identity.BinaryName)
				output.WriteString(" installation is healthy.\n")
			} else {
				output.WriteString("Some checks failed. Review the output above for details.\n")
			}
			output.WriteString("\n=== End Diagnostics ===\n")
			if _, err := out.Write([]byte(output.String())); err != nil {
				return err
			}

			// Exit with appropriate code
			if exitCode != foundry.ExitSuccess {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	return cmd
}
