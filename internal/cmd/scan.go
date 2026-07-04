package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/3leaps/decernor/internal/report"
	"github.com/3leaps/decernor/internal/scanner"
)

type scanOptions struct {
	format                   string
	failOn                   string
	profile                  string
	detectors                string
	allowProtectedSecretKeys bool
	maxFileSize              int64
	timeout                  time.Duration
}

func newScanCmd(identity *appidentity.Identity) *cobra.Command {
	opts := scanOptions{
		format:      "text",
		failOn:      "unsafe",
		profile:     string(scanner.ProfileArtifact),
		detectors:   "all",
		maxFileSize: 25 * 1024 * 1024,
		timeout:     10 * time.Second,
	}

	cmd := &cobra.Command{
		Use:   "scan PATH",
		Short: "Scan a folder for risky key material",
		Long: fmt.Sprintf(`Scan a folder for risky GPG, minisign, SSH, and private-key artifacts.

Reports are written to stdout. Operational logs use stderr when enabled with
--log-level, so JSON output can be piped safely.

Examples:
  %s scan /path/to/artifacts
  %s scan /path/to/artifacts --format json
  %s scan /path/to/artifacts --profile workstation
  %s scan /path/to/artifacts --fail-on warn`, identity.BinaryName, identity.BinaryName, identity.BinaryName, identity.BinaryName),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.validate(); err != nil {
				return err
			}
			detectors, err := parseDetectors(opts.detectors)
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			loggerInstance.Info("scan_start", zap.String("path", args[0]))
			result, err := scanner.Scan(ctx, args[0], scanner.Config{
				MaxFileSize:              opts.maxFileSize,
				GPGTimeout:               opts.timeout,
				AllowProtectedSecretKeys: opts.allowProtectedSecretKeys,
				Profile:                  scanner.Profile(opts.profile),
				EnableGPG:                detectors.gpg,
				EnableSSH:                detectors.ssh,
				EnableMinisign:           detectors.minisign,
			})
			if err != nil {
				loggerInstance.Error("scan_error", zap.String("path", args[0]), zap.Error(err))
				return err
			}
			loggerInstance.Info("scan_complete",
				zap.String("path", args[0]),
				zap.Int("scanned", result.Scanned),
				zap.Int("skipped", result.Skipped),
				zap.Int("warns", result.Warns),
				zap.Int("unsafes", result.Unsafes))

			switch opts.format {
			case "json":
				err = report.WriteJSON(os.Stdout, result)
			default:
				err = report.WriteText(os.Stdout, result)
			}
			if err != nil {
				return err
			}
			if failsPolicy(result, opts.failOn) {
				return fmt.Errorf("scan failed policy: fail-on=%s warns=%d unsafes=%d", opts.failOn, result.Warns, result.Unsafes)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.format, "format", opts.format, "output format: text or json")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", opts.failOn, "exit non-zero on: none, warn, or unsafe")
	cmd.Flags().StringVar(&opts.profile, "profile", opts.profile, "scan profile: artifact or workstation")
	cmd.Flags().StringVar(&opts.detectors, "detectors", opts.detectors, "comma-separated detectors: all,gpg,ssh,minisign")
	cmd.Flags().BoolVar(&opts.allowProtectedSecretKeys, "allow-protected-secret-keys", false, "downgrade passphrase-protected OpenPGP secret key exports to info")
	cmd.Flags().Int64Var(&opts.maxFileSize, "max-file-size", opts.maxFileSize, "maximum regular file size to inspect in bytes")
	cmd.Flags().DurationVar(&opts.timeout, "gpg-timeout", opts.timeout, "timeout for each gpg packet inspection")
	return cmd
}

func (o scanOptions) validate() error {
	if o.format != "text" && o.format != "json" {
		return fmt.Errorf("unsupported --format %q", o.format)
	}
	if o.failOn != "none" && o.failOn != "warn" && o.failOn != "unsafe" {
		return fmt.Errorf("unsupported --fail-on %q", o.failOn)
	}
	if o.profile != string(scanner.ProfileArtifact) && o.profile != string(scanner.ProfileWorkstation) {
		return fmt.Errorf("unsupported --profile %q", o.profile)
	}
	return nil
}

type detectorOptions struct {
	gpg      bool
	ssh      bool
	minisign bool
}

func parseDetectors(raw string) (detectorOptions, error) {
	var out detectorOptions
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		switch part {
		case "all":
			out.gpg = true
			out.ssh = true
			out.minisign = true
		case "gpg":
			out.gpg = true
		case "ssh":
			out.ssh = true
		case "minisign":
			out.minisign = true
		default:
			return detectorOptions{}, fmt.Errorf("unsupported detector %q", part)
		}
	}
	if !out.gpg && !out.ssh && !out.minisign {
		return detectorOptions{}, fmt.Errorf("at least one detector must be enabled")
	}
	return out, nil
}

func failsPolicy(result scanner.Result, failOn string) bool {
	if failOn == "none" {
		return false
	}
	for _, finding := range result.Findings {
		if finding.Severity == scanner.SeverityUnsafe {
			return true
		}
		if failOn == "warn" && finding.Severity == scanner.SeverityWarn {
			return true
		}
	}
	return false
}
