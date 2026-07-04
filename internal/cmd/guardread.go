package cmd

import (
	"fmt"
	"io"
	"time"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/spf13/cobra"

	"github.com/3leaps/decernor/internal/guardread"
)

type guardreadOptions struct {
	maxFileSize int64
	gpgTimeout  time.Duration
}

func newGuardreadCmd(identity *appidentity.Identity) *cobra.Command {
	opts := guardreadOptions{
		maxFileSize: guardread.DefaultMaxFileSize,
		gpgTimeout:  guardread.DefaultGPGTimeout,
	}
	binaryName := "decernor"
	if identity != nil && identity.BinaryName != "" {
		binaryName = identity.BinaryName
	}

	cmd := &cobra.Command{
		Use:          "guardread PATH",
		Short:        "Read a file only after key-material checks pass",
		SilenceUsage: true,
		Long: fmt.Sprintf(`Read one regular file only after bounded key-material checks pass.

On pass, %s writes the file bytes to stdout with no diagnostic records. On
refusal, stdout is empty and sanitized diagnostics are written to stderr. This
command is a supported-detector guard, not a general content-safety or prompt
injection filter.

Examples:
  %s guardread ./notes.txt`, binaryName, binaryName),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.maxFileSize <= 0 {
				return withExitCode(2, fmt.Errorf("--max-file-size must be greater than zero"))
			}
			result, err := guardread.ReadFile(cmd.Context(), args[0], guardread.Config{
				MaxFileSize: opts.maxFileSize,
				GPGTimeout:  opts.gpgTimeout,
			})
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "guardread: input-error %v\n", err)
				return withExitCode(2, err)
			}
			if result.Verdict == guardread.VerdictRefuse {
				writeGuardreadRefusal(cmd.ErrOrStderr(), result)
				return withExitCode(3, fmt.Errorf("guardread refused input"))
			}
			if _, err := cmd.OutOrStdout().Write(result.Content); err != nil {
				return withExitCode(2, err)
			}
			return nil
		},
	}

	cmd.Flags().Int64Var(&opts.maxFileSize, "max-file-size", opts.maxFileSize, "maximum regular file size to read in bytes")
	cmd.Flags().DurationVar(&opts.gpgTimeout, "gpg-timeout", opts.gpgTimeout, "timeout for OpenPGP helper inspection")
	return cmd
}

func writeGuardreadRefusal(w io.Writer, result guardread.Result) {
	_, _ = fmt.Fprintf(w, "guardread: refused reason=%s", result.Reason)
	if result.Finding != nil {
		_, _ = fmt.Fprintf(w,
			" code=%s classification=%s exposure=%s sensitivity=%s confidence=%s",
			result.Finding.Code,
			result.Finding.Classification,
			result.Finding.Exposure,
			result.Finding.Sensitivity,
			result.Finding.Confidence,
		)
	}
	_, _ = fmt.Fprintln(w)
}
