package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommittedFixturesContainNoPrivateKeyMaterial(t *testing.T) {
	root := repoRootForScannerTest(t)
	roots := []string{
		filepath.Join(root, "docs"),
		filepath.Join(root, "examples"),
		filepath.Join(root, "schemas"),
		filepath.Join(root, "tests"),
	}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, marker := range committedFixtureForbiddenMarkers() {
				if bytes.Contains(bytes.ToUpper(data), []byte(marker)) {
					t.Fatalf("committed fixture/documentation contains private-material marker %q: %s", marker, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func repoRootForScannerTest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func committedFixtureForbiddenMarkers() []string {
	return []string{
		strings.ToUpper(pgpPrivateHeader()),
		strings.ToUpper(sshPrivateHeader()),
		strings.ToUpper(encryptedPrivateHeader()),
		strings.ToUpper(joinWords("BEGIN", "RSA", "PRIVATE", "KEY")),
		strings.ToUpper(joinWords("BEGIN", "EC", "PRIVATE", "KEY")),
		strings.ToUpper(joinWords("BEGIN", "DSA", "PRIVATE", "KEY")),
		strings.ToUpper(minisignEncryptedSecretMarker()),
		strings.ToUpper(minisignSecretMarker()),
		strings.ToUpper(openSSHMagic),
	}
}
