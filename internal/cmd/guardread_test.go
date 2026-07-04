package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/fulmenhq/gofulmen/appidentity"
)

func TestGuardreadCommandCleanTextWritesOnlyContent(t *testing.T) {
	path := guardreadWriteFile(t, "clean.txt", []byte("clean bytes\n"))

	stdout, stderr, err := executeGuardreadForTest(t, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "clean bytes\n" {
		t.Fatalf("stdout = %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestGuardreadCommandRefusalUsesExit3AndEmptyStdout(t *testing.T) {
	marker := guardreadPrivateMarker()
	path := guardreadWriteFile(t, "embedded.txt", []byte("prefix\n"+marker+"\nsynthetic body\n"))

	stdout, stderr, err := executeGuardreadForTest(t, []string{path})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
	if stdout != "" {
		t.Fatalf("stdout leaked %q", stdout)
	}
	if !strings.Contains(stderr, "reason=key-material-detected") {
		t.Fatalf("stderr = %q", stderr)
	}
	if strings.Contains(stderr, marker) || strings.Contains(stderr, filepath.Dir(path)) {
		t.Fatalf("stderr leaked raw marker or absolute path: %q", stderr)
	}
}

func TestGuardreadCommandEmbeddedSSHPublicKeyUsesExit3AndEmptyStdout(t *testing.T) {
	key := "ssh-ed25519 AAAA operator@example.invalid"
	path := guardreadWriteFile(t, "embedded-public.txt", []byte("ordinary note\n"+key+"\n"))

	stdout, stderr, err := executeGuardreadForTest(t, []string{path})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
	if stdout != "" {
		t.Fatalf("stdout leaked %q", stdout)
	}
	if !strings.Contains(stderr, "reason=key-material-detected") || !strings.Contains(stderr, "code=SSH-PUBLIC-KEY") {
		t.Fatalf("stderr = %q", stderr)
	}
	if strings.Contains(stderr, key) || strings.Contains(stderr, filepath.Dir(path)) {
		t.Fatalf("stderr leaked raw key or absolute path: %q", stderr)
	}
}

func TestGuardreadCommandMalformedEmbeddedSSHPublicKeyShapeUsesExit3AndEmptyStdout(t *testing.T) {
	key := "ssh-ed25519 AAAA=== operator@example.invalid"
	path := guardreadWriteFile(t, "malformed-embedded-public.txt", []byte("ordinary note\n"+key+"\n"))

	stdout, stderr, err := executeGuardreadForTest(t, []string{path})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
	if stdout != "" {
		t.Fatalf("stdout leaked %q", stdout)
	}
	if !strings.Contains(stderr, "reason=key-material-detected") || !strings.Contains(stderr, "code=SSH-PUBLIC-KEY") {
		t.Fatalf("stderr = %q", stderr)
	}
	if strings.Contains(stderr, key) || strings.Contains(stderr, filepath.Dir(path)) {
		t.Fatalf("stderr leaked raw key shape or absolute path: %q", stderr)
	}
}

func TestGuardreadCommandBinaryRefusalUsesExit3AndEmptyStdout(t *testing.T) {
	path := guardreadWriteFile(t, "binary.bin", []byte{'a', 0, 'b'})

	stdout, stderr, err := executeGuardreadForTest(t, []string{path})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
	if stdout != "" {
		t.Fatalf("stdout leaked %q", stdout)
	}
	if !strings.Contains(stderr, "reason=binary-input-denied") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestGuardreadCommandInputErrorUsesExit2AndEmptyStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	target := guardreadWriteFile(t, "target.txt", []byte("clean\n"))
	link := filepath.Join(filepath.Dir(target), "target-link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	stdout, stderr, err := executeGuardreadForTest(t, []string{link})
	if err == nil {
		t.Fatal("expected input error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
	if stdout != "" {
		t.Fatalf("stdout leaked %q", stdout)
	}
	if !strings.Contains(stderr, "input-error") || !strings.Contains(stderr, "symlink-input") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestGuardreadCommandOversizeUsesExit2AndEmptyStdout(t *testing.T) {
	path := guardreadWriteFile(t, "large.txt", []byte("abcd"))

	stdout, stderr, err := executeGuardreadForTest(t, []string{path, "--max-file-size", "3"})
	if err == nil {
		t.Fatal("expected input error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
	if stdout != "" {
		t.Fatalf("stdout leaked %q", stdout)
	}
	if !strings.Contains(stderr, "file-too-large") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func executeGuardreadForTest(t *testing.T, args []string) (string, string, error) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := newGuardreadCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs(args)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func guardreadWriteFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func guardreadPrivateMarker() string {
	return "-----" + strings.Join([]string{"BEGIN", "OPENSSH", "PRIVATE", "KEY"}, " ") + "-----"
}
