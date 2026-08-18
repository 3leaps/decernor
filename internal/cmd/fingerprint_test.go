package cmd

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/fulmenhq/gofulmen/appidentity"
)

func TestFingerprintCommand_OversizedNonKeyFailOnEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "large.txt"), []byte("not key material\n"), 0600); err != nil {
		t.Fatal(err)
	}

	configPath = ""
	cmd := newFingerprintCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{dir, "--kind", "ssh", "--class", "public", "--max-file-size", "1", "--fail-on-empty"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected fail-on-empty error")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
}

func TestFingerprintCommand_ConfigSymlinkFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	configLink := filepath.Join(dir, "config-link.json")
	mustWriteFile(t, config, `{"schema_version":"v0","kind":["ssh"],"class":["public"],"path_mode":"none"}`+"\n")
	if err := os.Symlink(config, configLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	mustWriteFile(t, filepath.Join(dir, "keys", "id.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testCmdSSHPublicBlob())+" comment\n")

	err := executeFingerprintForTest(t, configLink, []string{filepath.Join(dir, "keys")})
	if err == nil {
		t.Fatal("expected symlinked config error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
	if !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("err = %v", err)
	}
}

func TestFingerprintCommand_ConfigSpecialFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "keys", "id.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testCmdSSHPublicBlob())+" comment\n")

	err := executeFingerprintForTest(t, dir, []string{filepath.Join(dir, "keys")})
	if err == nil {
		t.Fatal("expected special-file config error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("err = %v", err)
	}
}

func TestFingerprintCommand_ExplicitPathModeOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	mustWriteFile(t, config, `{"schema_version":"v0","kind":["minisign"],"class":["public"],"path_mode":"relative"}`+"\n")
	mustWriteFile(t, filepath.Join(dir, "keys", "sensitive", "nested", "minisign.pub"), testCmdMinisignPublic())

	var err error
	out := captureStdout(t, func() {
		err = executeFingerprintForTest(t, config, []string{filepath.Join(dir, "keys"), "--path-mode", "none"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"path"`) {
		t.Fatalf("stdout = %s", out)
	}
	if strings.Contains(out, "sensitive") || strings.Contains(out, "nested") || strings.Contains(out, "minisign.pub") {
		t.Fatalf("stdout leaked path metadata: %s", out)
	}
}

func TestFingerprintCommand_ExplicitFailOnEmptyOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	mustWriteFile(t, config, `{"schema_version":"v0","kind":["ssh"],"class":["public"],"fail_on_empty":false}`+"\n")
	mustWriteFile(t, filepath.Join(dir, "large.txt"), "not key material\n")

	err := executeFingerprintForTest(t, config, []string{dir, "--max-file-size", "1", "--fail-on-empty"})
	if err == nil {
		t.Fatal("expected fail-on-empty error")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d, err = %v", code, err)
	}
}

func TestFingerprintCommand_ExplicitKindAndClassOverrideConfig(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	mustWriteFile(t, config, `{"schema_version":"v0","kind":["minisign"],"class":["private"]}`+"\n")
	mustWriteFile(t, filepath.Join(dir, "keys", "id.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testCmdSSHPublicBlob())+" comment\n")
	mustWriteFile(t, filepath.Join(dir, "keys", "minisign.pub"), testCmdMinisignPublic())

	var err error
	out := captureStdout(t, func() {
		err = executeFingerprintForTest(t, config, []string{filepath.Join(dir, "keys"), "--kind", "ssh", "--class", "public"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"kind":"ssh"`) || !strings.Contains(out, `"class":"public"`) {
		t.Fatalf("stdout = %s", out)
	}
	if strings.Contains(out, `"kind":"minisign"`) || strings.Contains(out, `"class":"private"`) {
		t.Fatalf("config kind/class overrode explicit flags: %s", out)
	}
}

func TestFingerprintCommand_ExplicitMaxFileSizeOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	mustWriteFile(t, config, `{"schema_version":"v0","max_file_size":1,"kind":["minisign"],"class":["public"]}`+"\n")
	mustWriteFile(t, filepath.Join(dir, "keys", "minisign.pub"), testCmdMinisignPublic())

	var err error
	out := captureStdout(t, func() {
		err = executeFingerprintForTest(t, config, []string{filepath.Join(dir, "keys"), "--max-file-size", "1000", "--kind", "minisign", "--class", "public", "--fail-on-empty"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"kind":"minisign"`) || strings.Contains(out, "too-large") {
		t.Fatalf("stdout = %s", out)
	}
}

func TestFingerprintCommand_ExplicitFormatOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	mustWriteFile(t, config, `{"schema_version":"v0","format":"json","kind":["ssh"],"class":["public"]}`+"\n")
	mustWriteFile(t, filepath.Join(dir, "keys", "id.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testCmdSSHPublicBlob())+" comment\n")

	var err error
	out := captureStdout(t, func() {
		err = executeFingerprintForTest(t, config, []string{filepath.Join(dir, "keys"), "--format", "ndjson"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Fatalf("config format overrode explicit --format ndjson: %s", out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("stdout = %s", out)
	}
}

func TestFingerprintCommand_GPGRolePrimaryEmitsOneRecord(t *testing.T) {
	dir := t.TempDir()
	installCmdFakeGPG(t, dir)
	path := filepath.Join(dir, "release-key.asc")
	mustWriteFile(t, path, "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----\n")
	mustWriteFile(t, path+".colon", ""+
		"pub:u:3072:1:0000111122223333:1000:::escaESCA:::::\n"+
		"fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF0000111122223333:\n"+
		"sub:e:3072:1:7777888899990000:1000::::::s:\n"+
		"fpr:::::::::1111222233334444555566667777888899990000:\n")

	var err error
	out := captureStdout(t, func() {
		err = executeFingerprintForTest(t, "", []string{path, "--kind", "gpg", "--class", "public", "--format", "json", "--path-mode", "none", "--gpg-role", "primary"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"key_role": "primary"`) || strings.Contains(out, `"key_role": "subkey"`) {
		t.Fatalf("stdout = %s", out)
	}
	if !strings.Contains(out, "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333") {
		t.Fatalf("stdout = %s", out)
	}
}

func TestFingerprintCommand_GPGRolePrimaryRefusesZeroAndManyWithEmptyStdout(t *testing.T) {
	dir := t.TempDir()
	installCmdFakeGPG(t, dir)

	none := filepath.Join(dir, "sub-only.asc")
	mustWriteFile(t, none, "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----\n")
	mustWriteFile(t, none+".colon", ""+
		"sub:e:3072:1:7777888899990000:1000::::::s:\n"+
		"fpr:::::::::1111222233334444555566667777888899990000:\n")

	many := filepath.Join(dir, "two-primary.asc")
	mustWriteFile(t, many, "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----\n")
	mustWriteFile(t, many+".colon", ""+
		"pub:u:3072:1:0000111122223333:1000:::escaESCA:::::\n"+
		"fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF0000111122223333:\n"+
		"pub:u:3072:1:1111222233334444:1000:::escaESCA:::::\n"+
		"fpr:::::::::BBBBCCCCDDDDEEEEFFFF00001111222233334444:\n")

	for _, format := range []string{"json", "ndjson"} {
		for _, path := range []string{none, many} {
			var err error
			out := captureStdout(t, func() {
				err = executeFingerprintForTest(t, "", []string{path, "--kind", "gpg", "--class", "public", "--format", format, "--gpg-role", "primary"})
			})
			if err == nil {
				t.Fatalf("path=%s format=%s expected refusal", path, format)
			}
			if code := ExitCode(err, 1); code != 3 {
				t.Fatalf("path=%s format=%s code=%d err=%v", path, format, code, err)
			}
			if len(out) != 0 {
				t.Fatalf("path=%s format=%s stdout bytes=%d value=%q", path, format, len(out), out)
			}
		}
	}
}

func TestFingerprintCommand_GPGRolePrimaryTwoNamedFiles(t *testing.T) {
	dir := t.TempDir()
	installCmdFakeGPG(t, dir)
	a := filepath.Join(dir, "a.asc")
	b := filepath.Join(dir, "b.asc")
	mustWriteFile(t, a, "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----\n")
	mustWriteFile(t, a+".colon", ""+
		"pub:u:3072:1:0000111122223333:1000:::escaESCA:::::\n"+
		"fpr:::::::::AAAABBBBCCCCDDDDEEEEFFFF0000111122223333:\n")
	mustWriteFile(t, b, "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----\n")
	mustWriteFile(t, b+".colon", ""+
		"pub:u:3072:1:1111222233334444:1000:::escaESCA:::::\n"+
		"fpr:::::::::BBBBCCCCDDDDEEEEFFFF00001111222233334444:\n")

	var err error
	out := captureStdout(t, func() {
		err = executeFingerprintForTest(t, "", []string{a, b, "--kind", "gpg", "--class", "public", "--format", "json", "--gpg-role", "primary", "--path-mode", "none"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333") || !strings.Contains(out, "BBBBCCCCDDDDEEEEFFFF00001111222233334444") {
		t.Fatalf("stdout = %s", out)
	}
}

func TestFingerprintCommand_UnsupportedGPGRoleIsUsage(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "id.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testCmdSSHPublicBlob())+"\n")
	err := executeFingerprintForTest(t, "", []string{dir, "--gpg-role", "subkey"})
	if err == nil {
		t.Fatal("expected unsupported role error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func installCmdFakeGPG(t *testing.T, dir string) {
	t.Helper()
	script := `#!/bin/sh
file=
for a in "$@"; do file=$a; done
if [ -f "$file.colon" ]; then
  /bin/cat "$file.colon"
  exit 0
fi
exit 2
`
	if err := os.WriteFile(filepath.Join(dir, "gpg"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func executeFingerprintForTest(t *testing.T, config string, args []string) error {
	t.Helper()
	oldConfigPath := configPath
	configPath = config
	t.Cleanup(func() {
		configPath = oldConfigPath
	})
	cmd := newFingerprintCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs(args)
	return cmd.Execute()
}

func mustWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func testCmdMinisignPublic() string {
	payload := append([]byte("Ed"), []byte("12345678")...)
	payload = append(payload, strings.Repeat("B", 32)...)
	return "untrusted comment: minisign public key\n" + base64.StdEncoding.EncodeToString(payload) + "\n"
}

func testCmdSSHPublicBlob() []byte {
	var blob []byte
	blob = appendCmdSSHString(blob, []byte("ssh-ed25519"))
	blob = appendCmdSSHString(blob, []byte(strings.Repeat("\x11", 32)))
	return blob
}

func appendCmdSSHString(out []byte, value []byte) []byte {
	n := uint32(len(value))
	out = append(out, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	return append(out, value...)
}
