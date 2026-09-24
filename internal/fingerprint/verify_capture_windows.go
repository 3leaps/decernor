//go:build windows

package fingerprint

import "os"

func openVerifyFile(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- fstat and SameFile reject replacement; Windows has no FIFO open hazard.
}
