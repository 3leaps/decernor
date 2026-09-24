//go:build !windows

package fingerprint

import (
	"os"
	"syscall"
)

func openVerifyFile(path string) (*os.File, error) {
	// O_NONBLOCK keeps a regular-file-to-FIFO replacement from blocking open.
	// O_NOFOLLOW refuses a leaf symlink; fstat and SameFile bind the bytes to
	// the Lstat selection. The caller then reads only this descriptor.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- bounded explicit file, fd verified by fstat and SameFile.
	if err != nil {
		if err == syscall.ELOOP {
			return nil, os.ErrInvalid
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
