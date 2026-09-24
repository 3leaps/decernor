package scanner

import (
	"bytes"
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

type capturedPacketLister struct{ data []byte }

// CapturedOpenPGPPacketEvidence describes packets in a captured input buffer.
// It never reopens the caller's named path.
type CapturedOpenPGPPacketEvidence struct {
	PublicPrimary    bool
	Secret           bool
	KeyRevocation    bool
	SubkeyRevocation bool
}

func InspectCapturedOpenPGPPackets(ctx context.Context, data []byte, timeout time.Duration) (CapturedOpenPGPPacketEvidence, error) {
	output, err := (capturedPacketLister{data: data}).ListPackets(ctx, "", timeout)
	lower := strings.ToLower(output)
	return CapturedOpenPGPPacketEvidence{
		PublicPrimary:    strings.Contains(lower, ":public key packet:"),
		Secret:           containsAny(lower, packetSecretIndicators),
		KeyRevocation:    strings.Contains(lower, ":signature packet:") && strings.Contains(lower, "sigclass 0x20"),
		SubkeyRevocation: strings.Contains(lower, ":signature packet:") && strings.Contains(lower, "sigclass 0x28"),
	}, err
}

func (l capturedPacketLister) ListPackets(ctx context.Context, _ string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	home, err := os.MkdirTemp("", "decernor-gpg-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(home) }()
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, gpgPath, "--batch", "--no-tty", "--homedir", home, "--list-packets", "-")
	cmd.Stdin = bytes.NewReader(l.data)
	out, err := cmd.Output()
	return string(out), err
}

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
