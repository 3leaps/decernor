package guardread

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/3leaps/decernor/internal/scanner"
)

const (
	DefaultMaxFileSize = 25 * 1024 * 1024
	DefaultGPGTimeout  = 10 * time.Second
)

type Verdict string

const (
	VerdictPass   Verdict = "pass"
	VerdictRefuse Verdict = "refuse"
)

type RefusalReason string

const (
	ReasonKeyMaterialDetected RefusalReason = "key-material-detected"
	ReasonBinaryInputDenied   RefusalReason = "binary-input-denied"
)

type InputReason string

const (
	InputReasonSymlink    InputReason = "symlink-input"
	InputReasonDirectory  InputReason = "directory-input"
	InputReasonNonRegular InputReason = "non-regular-input"
	InputReasonTooLarge   InputReason = "file-too-large"
	InputReasonReadError  InputReason = "read-error"
)

type Config struct {
	MaxFileSize int64
	GPGTimeout  time.Duration
}

type Result struct {
	Verdict Verdict
	Reason  RefusalReason
	Finding *scanner.Finding
	Content []byte
}

type InputError struct {
	Reason InputReason
	Path   string
	Detail string
}

func (e InputError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s: %s", e.Reason, e.Path)
	}
	return fmt.Sprintf("%s: %s: %s", e.Reason, e.Path, e.Detail)
}

func ReadFile(ctx context.Context, path string, cfg Config) (Result, error) {
	cfg = withDefaults(cfg)
	displayPath := filepath.Base(filepath.Clean(path))

	info, err := os.Lstat(path)
	if err != nil {
		return Result{}, InputError{Reason: InputReasonReadError, Path: displayPath}
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return Result{}, InputError{Reason: InputReasonSymlink, Path: displayPath}
	}
	if info.IsDir() {
		return Result{}, InputError{Reason: InputReasonDirectory, Path: displayPath}
	}
	if !mode.IsRegular() {
		return Result{}, InputError{Reason: InputReasonNonRegular, Path: displayPath}
	}
	if info.Size() > cfg.MaxFileSize {
		return Result{}, InputError{
			Reason: InputReasonTooLarge,
			Path:   displayPath,
			Detail: fmt.Sprintf("size %d exceeds max %d", info.Size(), cfg.MaxFileSize),
		}
	}

	data, err := readBounded(path, cfg.MaxFileSize)
	if err != nil {
		return Result{}, InputError{Reason: InputReasonReadError, Path: displayPath}
	}
	if int64(len(data)) > cfg.MaxFileSize {
		return Result{}, InputError{
			Reason: InputReasonTooLarge,
			Path:   displayPath,
			Detail: fmt.Sprintf("size exceeds max %d", cfg.MaxFileSize),
		}
	}

	if artifact, ok := scanner.ClassifyBuffer(ctx, path, data, scanner.Config{
		MaxFileSize:    cfg.MaxFileSize,
		GPGTimeout:     cfg.GPGTimeout,
		EnableGPG:      true,
		EnableSSH:      true,
		EnableMinisign: true,
	}); ok {
		finding := artifact.Finding()
		return Result{
			Verdict: VerdictRefuse,
			Reason:  ReasonKeyMaterialDetected,
			Finding: &finding,
		}, nil
	}
	if looksBinaryOrAmbiguous(data) {
		return Result{
			Verdict: VerdictRefuse,
			Reason:  ReasonBinaryInputDenied,
		}, nil
	}
	return Result{
		Verdict: VerdictPass,
		Content: data,
	}, nil
}

func withDefaults(cfg Config) Config {
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = DefaultMaxFileSize
	}
	if cfg.GPGTimeout <= 0 {
		cfg.GPGTimeout = DefaultGPGTimeout
	}
	return cfg
}

func readBounded(path string, max int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	return io.ReadAll(io.LimitReader(file, max+1))
}

func looksBinaryOrAmbiguous(data []byte) bool {
	return bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data)
}
