package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/fulmenhq/gofulmen/foundry"
	fulmenschema "github.com/fulmenhq/gofulmen/schema"
	"github.com/spf13/cobra"

	"github.com/3leaps/decernor/internal/contracts"
	"github.com/3leaps/decernor/internal/gate"
)

type validateOptions struct {
	schemaPath         string
	contractID         string
	contractBase       string
	dataPath           string
	gatePolicyPath     string
	metaOnly           bool
	classificationGate bool
	pathMode           string
}

func newValidateCmd(identity *appidentity.Identity) *cobra.Command {
	var opts validateOptions

	binaryName := "tool"
	if identity != nil && identity.BinaryName != "" {
		binaryName = identity.BinaryName
	}

	cmd := &cobra.Command{
		Use:          "validate",
		Short:        "Validate schema and data",
		SilenceUsage: true,
		Long: fmt.Sprintf(`Validate JSON Schema documents and data.

Examples:
  # Validate that a schema file is valid JSON Schema
  %s validate --schema config.schema.json --meta-only

  # Validate data against a schema
  %s validate --schema config.schema.json --data config.yaml

  # Resolve a host-less contract id against an explicit local base
  %s validate --contract "contract: widget/v0" --contract-base contracts --data widget.json`, binaryName, binaryName, binaryName),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(opts, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}

	cmd.Flags().StringVarP(&opts.schemaPath, "schema", "s", "", "path to JSON Schema file")
	cmd.Flags().StringVar(&opts.contractID, "contract", "", `host-less contract id, for example "contract: widget/v0"`)
	cmd.Flags().StringVar(&opts.contractBase, "contract-base", "", "local directory or file URI used to resolve --contract")
	cmd.Flags().StringVarP(&opts.dataPath, "data", "d", "", "path to data file (YAML or JSON) to validate")
	cmd.Flags().BoolVarP(&opts.metaOnly, "meta-only", "m", false, "only validate schema or contract schema")
	cmd.Flags().BoolVar(&opts.classificationGate, "classification-gate", false, "run fail-closed sensitivity classification gate after contract validation")
	cmd.Flags().StringVar(&opts.gatePolicyPath, "gate-policy", "", "path to classification gate policy file")
	cmd.Flags().StringVar(&opts.pathMode, "path-mode", "relative", "path privacy mode for diagnostics (relative|hash|none)")

	return cmd
}

func runValidate(opts validateOptions, stdout io.Writer, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if opts.pathMode == "" {
		opts.pathMode = "relative"
	}
	if opts.pathMode != "relative" && opts.pathMode != "hash" && opts.pathMode != "none" {
		return withExitCode(2, fmt.Errorf("unsupported path_mode %q", opts.pathMode))
	}
	if opts.schemaPath == "" && opts.contractID == "" {
		return withExitCode(2, fmt.Errorf("either --schema or --contract is required"))
	}
	if opts.schemaPath != "" && opts.contractID != "" {
		return withExitCode(2, fmt.Errorf("--schema and --contract are mutually exclusive"))
	}
	if opts.contractID != "" && opts.contractBase == "" {
		return withExitCode(2, fmt.Errorf("--contract requires --contract-base"))
	}
	if opts.gatePolicyPath != "" {
		opts.classificationGate = true
	}
	if opts.classificationGate && opts.contractID == "" {
		return withExitCode(2, fmt.Errorf("--classification-gate requires --contract"))
	}

	label, validator, err := resolveValidateTarget(opts)
	if err != nil {
		return withExitCode(2, err)
	}

	successMessage := "✓ Schema meta-validation passed"
	if opts.contractID != "" {
		successMessage = "✓ Contract schema resolved and compiled"
	}
	_, _ = fmt.Fprintln(stdout, successMessage)

	if opts.metaOnly {
		return nil
	}
	if opts.dataPath == "" {
		if opts.classificationGate {
			return withExitCode(2, fmt.Errorf("--classification-gate requires --data"))
		}
		_, _ = fmt.Fprintln(stdout, "\nNo data file specified. Use --data to validate data against schema.")
		return nil
	}

	dataBytes, dataLabel, err := loadDataForValidation(opts.dataPath, opts.pathMode)
	if err != nil {
		return withExitCode(2, err)
	}

	diags, err := validator.ValidateJSON(dataBytes)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "\nData validation error:\n%v\n\n", err)
		return withExitCode(foundry.ExitDataInvalid, err)
	}
	if len(diags) > 0 {
		_, _ = fmt.Fprintln(stderr, "\nData validation failed:")
		for _, diag := range diags {
			_, _ = fmt.Fprintf(stderr, "  - %s: %s\n", diag.Pointer, diag.Message)
		}
		_, _ = fmt.Fprintf(stderr, "\nSchema: %s\n", label)
		_, _ = fmt.Fprintf(stderr, "Data:   %s\n\n", dataLabel)
		if opts.classificationGate {
			return withExitCode(2, fmt.Errorf("data validation failed"))
		}
		return withExitCode(foundry.ExitDataInvalid, fmt.Errorf("data validation failed"))
	}

	if opts.classificationGate {
		result, err := runClassificationGate(dataBytes, opts.gatePolicyPath)
		if err != nil {
			return withExitCode(2, err)
		}
		renderGateResult(stderr, result)
		if result.Denied() {
			return withExitCode(3, fmt.Errorf("classification gate refused descriptor"))
		}
		_, _ = fmt.Fprintln(stdout, "✓ Classification gate passed")
	}

	_, _ = fmt.Fprintln(stdout, "✓ Data validation passed")
	_, _ = fmt.Fprintln(stdout, "\nValidation complete")
	_, _ = fmt.Fprintf(stdout, "   Schema: %s\n", label)
	_, _ = fmt.Fprintf(stdout, "   Data:   %s\n", dataLabel)
	return nil
}

type validateTarget interface {
	ValidateJSON([]byte) ([]fulmenschema.Diagnostic, error)
}

func resolveValidateTarget(opts validateOptions) (string, validateTarget, error) {
	if opts.contractID != "" {
		resolver, err := contracts.NewResolver(opts.contractBase)
		if err != nil {
			return "", nil, err
		}
		validator, err := resolver.Validator(opts.contractID)
		if err != nil {
			return "", nil, err
		}
		return opts.contractID, validator, nil
	}

	absSchemaPath, err := filepath.Abs(opts.schemaPath)
	if err != nil {
		return "", nil, fmt.Errorf("invalid schema path")
	}
	schemaData, err := os.ReadFile(absSchemaPath) // #nosec G304 -- User-provided validation schema.
	if err != nil {
		return "", nil, fmt.Errorf("cannot read schema: %w", err)
	}
	diags, err := fulmenschema.ValidateSchemaBytes(schemaData)
	if err != nil {
		return "", nil, fmt.Errorf("schema meta-validation failed: %w", err)
	}
	if len(diags) > 0 {
		return "", nil, fmt.Errorf("schema meta-validation failed")
	}
	validator, err := fulmenschema.NewValidator(schemaData)
	if err != nil {
		return "", nil, fmt.Errorf("cannot create validator: %w", err)
	}
	return sanitizePath(absSchemaPath, opts.pathMode), validator, nil
}

func loadDataForValidation(path string, pathMode string) ([]byte, string, error) {
	absDataPath, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("invalid data path")
	}
	var dataBytes []byte
	if filepath.Ext(absDataPath) == ".yaml" || filepath.Ext(absDataPath) == ".yml" {
		dataBytes, err = fulmenschema.LoadYAMLFile(absDataPath)
		if err != nil {
			return nil, "", fmt.Errorf("cannot load YAML file: %w", err)
		}
	} else {
		dataBytes, err = fulmenschema.LoadJSONFile(absDataPath)
		if err != nil {
			return nil, "", fmt.Errorf("cannot load JSON file: %w", err)
		}
	}
	return dataBytes, sanitizePath(absDataPath, pathMode), nil
}

func runClassificationGate(data []byte, policyPath string) (gate.Result, error) {
	policy := gate.DefaultPolicy()
	if policyPath != "" {
		loaded, err := gate.LoadPolicy(policyPath)
		if err != nil {
			return gate.Result{}, err
		}
		policy = loaded
	}
	return gate.EvaluateJSON(data, policy)
}

func renderGateResult(stderr io.Writer, result gate.Result) {
	if stderr == nil || !result.Denied() {
		return
	}
	_, _ = fmt.Fprintln(stderr, "\nClassification gate verdicts:")
	for _, record := range result.Records {
		if record.Verdict == gate.VerdictDeny {
			_, _ = fmt.Fprintf(stderr, "  - item=%s verdict=%s reason=%s\n", record.Locator, record.Verdict, record.Reason)
		} else {
			_, _ = fmt.Fprintf(stderr, "  - item=%s verdict=%s\n", record.Locator, record.Verdict)
		}
	}
	_, _ = fmt.Fprintln(stderr)
}

func sanitizePath(path string, mode string) string {
	switch mode {
	case "none":
		return ""
	case "hash":
		sum := sha256.Sum256([]byte(filepath.ToSlash(filepath.Clean(path))))
		return hex.EncodeToString(sum[:16])
	default:
		return filepath.Base(path)
	}
}
