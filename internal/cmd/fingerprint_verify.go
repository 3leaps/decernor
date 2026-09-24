package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/3leaps/decernor/internal/fingerprint"
	"github.com/spf13/cobra"
)

func newFingerprintVerifyCmd() *cobra.Command {
	var anchors, anchorsNDJSON, gpg, minisign, asOf, format string
	var allowExpired bool
	cmd := &cobra.Command{
		Use:           "verify",
		Short:         "Compare committed anchors with exported public keys",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return withExitCode(2, fmt.Errorf("fingerprint verify takes flags only"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format != "ndjson" && format != "json" {
				return withExitCode(2, fmt.Errorf("unsupported verify format"))
			}
			var instant time.Time
			if asOf != "" {
				var err error
				instant, err = time.Parse(time.RFC3339, asOf)
				if err != nil {
					return withExitCode(2, fmt.Errorf("--as-of requires RFC3339 with a zone"))
				}
			}
			result, err := fingerprint.Verify(cmd.Context(), anchors, anchorsNDJSON, gpg, minisign, fingerprint.VerifyConfig{
				AsOf: instant, AsOfSet: asOf != "", AllowExpired: allowExpired,
			})
			if err != nil {
				var verifyErr *fingerprint.VerifyError
				if errors.As(err, &verifyErr) {
					return withExitCode(verifyErr.Code, verifyErr)
				}
				return withExitCode(2, fmt.Errorf("fingerprint verify failed"))
			}
			var output bytes.Buffer
			encoder := json.NewEncoder(&output)
			if format == "json" {
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(result.Records); err != nil {
					return withExitCode(2, fmt.Errorf("verify output encoding failed"))
				}
			} else {
				for _, record := range result.Records {
					if err := encoder.Encode(record); err != nil {
						return withExitCode(2, fmt.Errorf("verify output encoding failed"))
					}
				}
			}
			if _, err := cmd.OutOrStdout().Write(output.Bytes()); err != nil {
				return withExitCode(2, fmt.Errorf("verify output write failed"))
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "fingerprint verify: records=%d findings=%d\n", len(result.Records), countVerifyFindings(result.Records))
			if result.ExitCode != 0 {
				return withExitCode(result.ExitCode, fmt.Errorf("fingerprint verify found %d issue(s)", countVerifyFindings(result.Records)))
			}
			return nil
		},
	}
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, _ error) error {
		return withExitCode(2, fmt.Errorf("fingerprint verify flag error"))
	})
	cmd.Flags().StringVar(&anchors, "anchors", "", "committed two-line anchor TXT file")
	cmd.Flags().StringVar(&anchorsNDJSON, "anchors-ndjson", "", "selected-record anchor NDJSON file")
	cmd.Flags().StringVar(&gpg, "gpg", "", "exported GPG public key regular file")
	cmd.Flags().StringVar(&minisign, "minisign", "", "exported minisign public key regular file")
	cmd.Flags().StringVar(&asOf, "as-of", "", "expiry evaluation time (RFC3339; default now UTC)")
	cmd.Flags().BoolVar(&allowExpired, "allow-expired", false, "allow expiry only when both anchors match")
	cmd.Flags().StringVar(&format, "format", "ndjson", "output format: ndjson or json")
	return cmd
}

func countVerifyFindings(records []fingerprint.VerifyRecord) int {
	count := 0
	for _, record := range records {
		if record.Reason != "none" {
			count++
		}
	}
	return count
}
