package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/fulmenhq/gofulmen/crucible"
)

// newEnvinfoCmd creates the envinfo command
func newEnvinfoCmd(identity *appidentity.Identity) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "envinfo",
		Short: "Display environment information",
		Long:  `Display comprehensive environment, configuration, and version information.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			version := crucible.GetVersion()
			out := cmd.OutOrStdout()
			var output strings.Builder

			output.WriteString("=== ")
			output.WriteString(identity.BinaryName)
			output.WriteString(" Environment Information ===\n\n")

			// Application Info
			output.WriteString("Application:\n")
			output.WriteString("  Name:        ")
			output.WriteString(identity.BinaryName)
			output.WriteString("\n  Vendor:      ")
			output.WriteString(identity.Vendor)
			output.WriteString("\n  Description: ")
			output.WriteString(identity.Description)
			output.WriteString("\n  Version:     ")
			output.WriteString(getVersionString())
			output.WriteString("\n  Commit:      ")
			output.WriteString(commit)
			output.WriteString("\n  Built:       ")
			output.WriteString(buildDate)
			output.WriteString("\n\n")

			// SSOT Info
			output.WriteString("SSOT Dependencies:\n")
			output.WriteString("  Gofulmen:    v")
			output.WriteString(version.Gofulmen)
			output.WriteString("\n  Crucible:    v")
			output.WriteString(version.Crucible)
			output.WriteString("\n\n")

			// Runtime Info
			output.WriteString("Runtime:\n")
			output.WriteString("  Go Version:  ")
			output.WriteString(runtime.Version())
			output.WriteString("\n  GOOS:        ")
			output.WriteString(runtime.GOOS)
			output.WriteString("\n  GOARCH:      ")
			output.WriteString(runtime.GOARCH)
			output.WriteString("\n  NumCPU:      ")
			output.WriteString(strconv.Itoa(runtime.NumCPU()))
			output.WriteString("\n\n")

			// Configuration
			output.WriteString("Configuration:\n")
			output.WriteString("  Env Prefix:  ")
			output.WriteString(identity.EnvPrefix)
			output.WriteString("\n  Config Name: ")
			output.WriteString(identity.ConfigName)
			output.WriteString("\n")

			// Config path
			homeDir, err := os.UserHomeDir()
			if err == nil {
				configPath := filepath.Join(homeDir, ".config", identity.Vendor, identity.ConfigName+".yaml")
				if _, err := os.Stat(configPath); err == nil {
					output.WriteString("  Config File: ")
					output.WriteString(configPath)
					output.WriteString(" (exists)\n")
				} else {
					output.WriteString("  Config File: ")
					output.WriteString(configPath)
					output.WriteString(" (not found, using defaults)\n")
				}
			}

			// Environment variables (show if set)
			output.WriteString("\nEnvironment Variables:\n")
			envVars := []string{
				identity.EnvPrefix + "LOG_LEVEL",
				identity.EnvPrefix + "CONFIG_PATH",
			}
			foundAny := false
			for _, envVar := range envVars {
				if val := os.Getenv(envVar); val != "" {
					output.WriteString("  ")
					output.WriteString(envVar)
					output.WriteString("=")
					output.WriteString(val)
					output.WriteString("\n")
					foundAny = true
				}
			}
			if !foundAny {
				output.WriteString("  (no environment variables set with prefix ")
				output.WriteString(identity.EnvPrefix)
				output.WriteString(")\n")
			}

			output.WriteString("\n=== End ")
			output.WriteString(identity.BinaryName)
			output.WriteString(" Environment Information ===\n")
			_, err = out.Write([]byte(output.String()))
			return err
		},
	}

	return cmd
}

func getVersionString() string {
	if version != "" && version != "dev" {
		return version
	}
	return "dev"
}
