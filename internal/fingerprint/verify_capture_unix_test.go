//go:build !windows

package fingerprint

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCaptureRegularRefusesFIFOAndSwapWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	_, err := captureRegular(fifo, verifyMaxFileSize)
	if verifyCode(err) != 3 {
		t.Fatalf("fifo code=%d err=%v", verifyCode(err), err)
	}
	path := filepath.Join(dir, "selected")
	writeFixture(t, path, []byte("public fixture"))
	done := make(chan error, 1)
	go func() {
		_, err := captureRegularWithHook(path, verifyMaxFileSize, func() {
			_ = os.Remove(path)
			_ = syscall.Mkfifo(path, 0o600)
		})
		done <- err
	}()
	select {
	case err := <-done:
		if verifyCode(err) != 3 {
			t.Fatalf("swap-to-fifo code=%d err=%v", verifyCode(err), err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("capture blocked opening FIFO replacement")
	}
	regular := filepath.Join(dir, "regular")
	writeFixture(t, regular, []byte("public fixture"))
	_, err = captureRegularWithHook(regular, verifyMaxFileSize, func() {
		_ = os.Rename(regular, regular+".old")
		_ = os.Symlink(regular+".old", regular)
	})
	if verifyCode(err) != 3 {
		t.Fatalf("swap-to-symlink code=%d err=%v", verifyCode(err), err)
	}
}
