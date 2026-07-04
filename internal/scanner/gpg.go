package scanner

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

type packetLister interface {
	ListPackets(ctx context.Context, path string, timeout time.Duration) (string, error)
}

type gpgPacketLister struct{}

func (gpgPacketLister) ListPackets(ctx context.Context, path string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	home, err := os.MkdirTemp("", "decernor-gpg-")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = os.RemoveAll(home)
	}()

	cmd := exec.CommandContext(ctx, "gpg", "--batch", "--no-tty", "--homedir", home, "--list-packets", path)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	return string(out), err
}
