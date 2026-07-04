package guardread

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadFileCleanTextPassesContent(t *testing.T) {
	path := writeTestFile(t, "clean.txt", []byte("plain release notes\n"))

	result, err := ReadFile(context.Background(), path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictPass {
		t.Fatalf("verdict = %s", result.Verdict)
	}
	if string(result.Content) != "plain release notes\n" {
		t.Fatalf("content = %q", result.Content)
	}
}

func TestReadFileKeyMarkerAtStartRefusesWithoutContent(t *testing.T) {
	marker := testPrivateMarker()
	path := writeTestFile(t, "key.txt", []byte(marker+"\nsynthetic body\n"))

	result, err := ReadFile(context.Background(), path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictRefuse || result.Reason != ReasonKeyMaterialDetected {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Content) != 0 {
		t.Fatalf("refusal content length = %d", len(result.Content))
	}
	if result.Finding == nil || result.Finding.Code == "" {
		t.Fatalf("finding = %#v", result.Finding)
	}
}

func TestReadFileEmbeddedKeyMarkerRefusesWithoutContent(t *testing.T) {
	marker := testPrivateMarker()
	path := writeTestFile(t, "embedded.txt", []byte("safe prefix\n"+marker+"\nsynthetic body\n"))

	result, err := ReadFile(context.Background(), path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictRefuse || result.Reason != ReasonKeyMaterialDetected {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Content) != 0 {
		t.Fatalf("refusal content length = %d", len(result.Content))
	}
}

func TestReadFileEmbeddedSSHPublicKeyRefusesWithoutContent(t *testing.T) {
	key := "ssh-ed25519 AAAA operator@example.invalid"
	path := writeTestFile(t, "embedded-public.txt", []byte("ordinary note\n"+key+"\n"))

	result, err := ReadFile(context.Background(), path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictRefuse || result.Reason != ReasonKeyMaterialDetected {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Content) != 0 {
		t.Fatalf("refusal content length = %d", len(result.Content))
	}
	if result.Finding == nil || result.Finding.Code != "SSH-PUBLIC-KEY" {
		t.Fatalf("finding = %#v", result.Finding)
	}
}

func TestReadFileMalformedEmbeddedSSHPublicKeyShapeRefusesWithoutContent(t *testing.T) {
	key := "ssh-ed25519 AAAA=== operator@example.invalid"
	path := writeTestFile(t, "malformed-embedded-public.txt", []byte("ordinary note\n"+key+"\n"))

	result, err := ReadFile(context.Background(), path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictRefuse || result.Reason != ReasonKeyMaterialDetected {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Content) != 0 {
		t.Fatalf("refusal content length = %d", len(result.Content))
	}
	if result.Finding == nil || result.Finding.Code != "SSH-PUBLIC-KEY" {
		t.Fatalf("finding = %#v", result.Finding)
	}
}

func TestReadFileBinaryInputRefusesWithoutContent(t *testing.T) {
	path := writeTestFile(t, "binary.bin", []byte{'o', 'k', 0, 'x'})

	result, err := ReadFile(context.Background(), path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictRefuse || result.Reason != ReasonBinaryInputDenied {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Content) != 0 {
		t.Fatalf("refusal content length = %d", len(result.Content))
	}
}

func TestReadFileOversizeFailsClosed(t *testing.T) {
	path := writeTestFile(t, "large.txt", bytes.Repeat([]byte("x"), 4))

	_, err := ReadFile(context.Background(), path, Config{MaxFileSize: 3})
	if err == nil {
		t.Fatal("expected oversize error")
	}
	assertInputReason(t, err, InputReasonTooLarge)
}

func TestReadFileSymlinkFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")
	if err := os.WriteFile(target, []byte("clean\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err := ReadFile(context.Background(), link, Config{})
	if err == nil {
		t.Fatal("expected symlink error")
	}
	assertInputReason(t, err, InputReasonSymlink)
}

func TestReadFileDirectoryFailsClosed(t *testing.T) {
	_, err := ReadFile(context.Background(), t.TempDir(), Config{})
	if err == nil {
		t.Fatal("expected directory error")
	}
	assertInputReason(t, err, InputReasonDirectory)
}

func TestReadFileSpecialFileFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("special file check uses /dev/null")
	}
	if _, err := os.Lstat("/dev/null"); err != nil {
		t.Skipf("/dev/null unavailable: %v", err)
	}

	_, err := ReadFile(context.Background(), "/dev/null", Config{})
	if err == nil {
		t.Fatal("expected special-file error")
	}
	assertInputReason(t, err, InputReasonNonRegular)
}

func assertInputReason(t *testing.T, err error, want InputReason) {
	t.Helper()
	got, ok := err.(InputError)
	if !ok {
		t.Fatalf("err type = %T (%v)", err, err)
	}
	if got.Reason != want {
		t.Fatalf("reason = %s, want %s", got.Reason, want)
	}
}

func writeTestFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testPrivateMarker() string {
	return "-----" + strings.Join([]string{"BEGIN", "OPENSSH", "PRIVATE", "KEY"}, " ") + "-----"
}
