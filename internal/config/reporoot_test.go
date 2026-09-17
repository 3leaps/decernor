package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindProjectRoot_CIWorkspaceBoundaryHint(t *testing.T) {
	// Simulate CI.
	t.Setenv("CI", "true")

	// When running `go test`, the working directory is the package directory.
	// For internal/config, the repo root is ../..
	expectedRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("failed to resolve expected root: %v", err)
	}

	// Provide a CI boundary hint (must contain the start path).
	t.Setenv("FULMEN_WORKSPACE_ROOT", expectedRoot)

	root, err := FindProjectRoot()
	if err != nil {
		t.Fatalf("FindProjectRoot returned error: %v", err)
	}

	if filepath.Clean(root) != filepath.Clean(expectedRoot) {
		t.Fatalf("expected root %q, got %q", expectedRoot, root)
	}
}

func TestValidCIBoundary(t *testing.T) {
	root := t.TempDir()
	start := filepath.Join(root, "..safe", "nested")
	if err := os.MkdirAll(start, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		candidate string
		wantOK    bool
	}{
		{name: "containing directory", candidate: root, wantOK: true},
		{name: "same directory", candidate: start, wantOK: true},
		{name: "relative", candidate: ".", wantOK: false},
		{name: "regular file", candidate: file, wantOK: false},
		{name: "non-containing sibling", candidate: t.TempDir(), wantOK: false},
		{name: "missing", candidate: filepath.Join(root, "missing"), wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := validCIBoundary(filepath.Clean(start), tt.candidate)
			if ok != tt.wantOK {
				t.Fatalf("validCIBoundary(%q) ok=%v, want %v (got %q)", tt.candidate, ok, tt.wantOK, got)
			}
			if ok && got != filepath.Clean(tt.candidate) {
				t.Fatalf("boundary=%q, want %q", got, filepath.Clean(tt.candidate))
			}
		})
	}
}
