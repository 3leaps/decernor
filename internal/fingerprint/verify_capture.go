package fingerprint

import (
	"errors"
	"io"
	"os"
)

// VerifyError carries the documented process exit while keeping all diagnostics
// independent of user supplied paths, key contents, and helper output.
type VerifyError struct {
	Code   int
	Reason string
}

func (e *VerifyError) Error() string { return "fingerprint verify: " + e.Reason }

func verifyError(code int, reason string) error { return &VerifyError{Code: code, Reason: reason} }

const verifyMaxFileSize int64 = 25 * 1024 * 1024

func captureRegular(path string, max int64) ([]byte, error) {
	return captureRegularWithHook(path, max, nil)
}

// The hook is solely for the path-replacement regression. Production passes nil.
func captureRegularWithHook(path string, max int64, afterLstat func()) ([]byte, error) {
	if max <= 0 {
		max = verifyMaxFileSize
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, verifyError(2, "input-unreadable")
	}
	if !before.Mode().IsRegular() {
		return nil, verifyError(3, "input-not-regular")
	}
	if before.Size() > max {
		return nil, verifyError(2, "input-too-large")
	}
	if afterLstat != nil {
		afterLstat()
	}
	file, err := openVerifyFile(path)
	if err != nil {
		if errors.Is(err, os.ErrInvalid) {
			return nil, verifyError(3, "input-not-regular")
		}
		return nil, verifyError(2, "input-unreadable")
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil {
		return nil, verifyError(2, "input-unreadable")
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, verifyError(3, "input-changed-or-not-regular")
	}
	selected, err := os.Lstat(path)
	if err != nil || !selected.Mode().IsRegular() || !os.SameFile(selected, after) {
		return nil, verifyError(3, "input-changed-or-not-regular")
	}
	if after.Size() > max {
		return nil, verifyError(2, "input-too-large")
	}
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, verifyError(2, "input-unreadable")
	}
	if int64(len(data)) > max {
		return nil, verifyError(2, "input-too-large")
	}
	return data, nil
}
