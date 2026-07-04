package cmd

import "errors"

type exitCodeError struct {
	code int
	err  error
}

func (e exitCodeError) Error() string {
	return e.err.Error()
}

func (e exitCodeError) Unwrap() error {
	return e.err
}

func withExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return exitCodeError{code: code, err: err}
}

func ExitCode(err error, fallback int) int {
	var coded exitCodeError
	if errors.As(err, &coded) {
		return coded.code
	}
	return fallback
}
