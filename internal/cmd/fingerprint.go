package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/3leaps/decernor/internal/fingerprint"
	"github.com/3leaps/decernor/internal/scanner"
)

type fingerprintOptions struct {
	format      string
	kinds       string
	classes     string
	includes    []string
	excludes    []string
	failOnEmpty bool
	maxFileSize int64
	gpgTimeout  time.Duration
	pathMode    string
}

type fingerprintFileConfig struct {
	SchemaVersion string   `json:"schema_version"`
	Kind          []string `json:"kind"`
	Class         []string `json:"class"`
	Include       []string `json:"include"`
	Exclude       []string `json:"exclude"`
	Format        string   `json:"format"`
	FailOnEmpty   *bool    `json:"fail_on_empty"`
	MaxFileSize   int64    `json:"max_file_size"`
	PathMode      string   `json:"path_mode"`
}

func newFingerprintCmd(identity *appidentity.Identity) *cobra.Command {
	opts := fingerprintOptions{
		format:      "ndjson",
		kinds:       "all",
		classes:     "all",
		maxFileSize: 25 * 1024 * 1024,
		gpgTimeout:  10 * time.Second,
		pathMode:    string(fingerprint.PathModeRelative),
	}
	cmd := &cobra.Command{
		Use:           "fingerprint [PATHS...]",
		Aliases:       []string{"fp"},
		Short:         "Emit safe key-material fingerprints",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: fmt.Sprintf(`Emit safe, structured key-material fingerprints without printing private material.

The default output is newline-delimited JSON. Operational diagnostics are written
to stderr; stdout contains records only.

Examples:
  %s fingerprint ./release-materials
  %s fp ./release-materials --kind ssh,minisign
  %s fingerprint ./release-materials --format json --fail-on-empty`, identity.BinaryName, identity.BinaryName, identity.BinaryName),
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath != "" {
				if err := opts.mergeConfig(configPath, cmd.Flags()); err != nil {
					return withExitCode(2, err)
				}
			}
			if err := opts.validate(); err != nil {
				return withExitCode(2, err)
			}
			cfg, err := opts.runnerConfig()
			if err != nil {
				return withExitCode(2, err)
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			result, err := fingerprint.Run(ctx, args, cfg, cmd.ErrOrStderr())
			if err != nil {
				return withExitCode(2, err)
			}
			switch opts.format {
			case "json":
				err = fingerprint.WriteJSON(os.Stdout, result.Records)
			default:
				err = fingerprint.WriteNDJSON(os.Stdout, result.Records)
			}
			if err != nil {
				return withExitCode(2, err)
			}
			if opts.failOnEmpty && result.Empty {
				return withExitCode(3, fmt.Errorf("fingerprint found no matching key material"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.format, "format", opts.format, "output format: ndjson or json")
	cmd.Flags().StringVar(&opts.kinds, "kind", opts.kinds, "comma-separated kinds: all,ssh,gpg,minisign")
	cmd.Flags().StringVar(&opts.classes, "class", opts.classes, "comma-separated classes: all,public,private,other")
	cmd.Flags().StringArrayVar(&opts.includes, "include", nil, "include glob; may be repeated")
	cmd.Flags().StringArrayVar(&opts.excludes, "exclude", nil, "exclude glob; may be repeated")
	cmd.Flags().BoolVar(&opts.failOnEmpty, "fail-on-empty", false, "exit 3 when no matching records are emitted")
	cmd.Flags().Int64Var(&opts.maxFileSize, "max-file-size", opts.maxFileSize, "maximum regular file size to inspect in bytes")
	cmd.Flags().DurationVar(&opts.gpgTimeout, "gpg-timeout", opts.gpgTimeout, "timeout for each OpenPGP helper inspection")
	cmd.Flags().StringVar(&opts.pathMode, "path-mode", opts.pathMode, "path disclosure mode: relative, hash, or none")
	return cmd
}

func (o *fingerprintOptions) mergeConfig(path string, flags *pflag.FlagSet) error {
	data, err := readFingerprintConfig(path)
	if err != nil {
		return err
	}
	var cfg fingerprintFileConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("cannot parse fingerprint config: %w", err)
	}
	if cfg.SchemaVersion != "" && cfg.SchemaVersion != fingerprint.SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", cfg.SchemaVersion)
	}
	if cfg.Format != "" && !flagChanged(flags, "format") {
		o.format = cfg.Format
	}
	if len(cfg.Kind) > 0 && !flagChanged(flags, "kind") {
		o.kinds = strings.Join(cfg.Kind, ",")
	}
	if len(cfg.Class) > 0 && !flagChanged(flags, "class") {
		o.classes = strings.Join(cfg.Class, ",")
	}
	if len(cfg.Include) > 0 && !flagChanged(flags, "include") {
		o.includes = cfg.Include
	}
	if len(cfg.Exclude) > 0 && !flagChanged(flags, "exclude") {
		o.excludes = cfg.Exclude
	}
	if cfg.FailOnEmpty != nil && !flagChanged(flags, "fail-on-empty") {
		o.failOnEmpty = *cfg.FailOnEmpty
	}
	if cfg.MaxFileSize > 0 && !flagChanged(flags, "max-file-size") {
		o.maxFileSize = cfg.MaxFileSize
	}
	if cfg.PathMode != "" && !flagChanged(flags, "path-mode") {
		o.pathMode = cfg.PathMode
	}
	return nil
}

func readFingerprintConfig(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot inspect fingerprint config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("fingerprint config must not be a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("fingerprint config must be a regular file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read fingerprint config: %w", err)
	}
	return data, nil
}

func flagChanged(flags *pflag.FlagSet, name string) bool {
	return flags != nil && flags.Changed(name)
}

func (o fingerprintOptions) validate() error {
	if o.format != "ndjson" && o.format != "json" {
		return fmt.Errorf("unsupported --format %q", o.format)
	}
	if o.maxFileSize <= 0 {
		return fmt.Errorf("--max-file-size must be positive")
	}
	if o.gpgTimeout <= 0 {
		return fmt.Errorf("--gpg-timeout must be positive")
	}
	if !validPathMode(fingerprint.PathMode(o.pathMode)) {
		return fmt.Errorf("unsupported --path-mode %q", o.pathMode)
	}
	return nil
}

func (o fingerprintOptions) runnerConfig() (fingerprint.Config, error) {
	kinds, err := parseFingerprintKinds(o.kinds)
	if err != nil {
		return fingerprint.Config{}, err
	}
	classes, err := parseFingerprintClasses(o.classes)
	if err != nil {
		return fingerprint.Config{}, err
	}
	cfg := fingerprint.Config{
		MaxFileSize: o.maxFileSize,
		Include:     o.includes,
		Exclude:     o.excludes,
		Kinds:       kinds,
		Classes:     classes,
		PathMode:    fingerprint.PathMode(o.pathMode),
		FailOnEmpty: o.failOnEmpty,
		GPGTimeout:  o.gpgTimeout,
		EnableGPG:   true,
		EnableSSH:   true,
		EnableMini:  true,
	}
	if len(kinds) > 0 {
		cfg.EnableGPG = kinds[scanner.ArtifactKindGPG]
		cfg.EnableSSH = kinds[scanner.ArtifactKindSSH]
		cfg.EnableMini = kinds[scanner.ArtifactKindMinisign]
	}
	return cfg, nil
}

func validPathMode(mode fingerprint.PathMode) bool {
	switch mode {
	case fingerprint.PathModeHash, fingerprint.PathModeNone, fingerprint.PathModeRelative:
		return true
	default:
		return false
	}
}

func parseFingerprintKinds(raw string) (map[scanner.ArtifactKind]bool, error) {
	out := map[scanner.ArtifactKind]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" || part == "all" {
			continue
		}
		switch scanner.ArtifactKind(part) {
		case scanner.ArtifactKindGPG, scanner.ArtifactKindSSH, scanner.ArtifactKindMinisign:
			out[scanner.ArtifactKind(part)] = true
		default:
			return nil, fmt.Errorf("unsupported --kind %q", part)
		}
	}
	return out, nil
}

func parseFingerprintClasses(raw string) (map[scanner.ArtifactClass]bool, error) {
	out := map[scanner.ArtifactClass]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" || part == "all" {
			continue
		}
		switch scanner.ArtifactClass(part) {
		case scanner.ArtifactClassPublic, scanner.ArtifactClassPrivate, scanner.ArtifactClassOther:
			out[scanner.ArtifactClass(part)] = true
		default:
			return nil, fmt.Errorf("unsupported --class %q", part)
		}
	}
	return out, nil
}
