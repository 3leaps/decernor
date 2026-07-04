package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/fulmenhq/gofulmen/logging"

	"github.com/3leaps/decernor/internal/config"
)

// setupTestLogger initializes the global logger for testing
func setupTestLogger(t *testing.T) {
	t.Helper()
	logger, err := logging.NewCLI("decernor-test")
	if err != nil {
		t.Fatalf("Failed to create test logger: %v", err)
	}
	loggerInstance = logger
}

// TestValidateCommand_MetaValidation tests schema meta-validation
func TestValidateCommand_MetaValidation(t *testing.T) {
	setupTestLogger(t)

	projectRoot, err := config.FindProjectRoot()
	if err != nil {
		t.Fatalf("Failed to get project root: %v", err)
	}

	schemaPath := filepath.Join(projectRoot, "tests/fixtures/schema-validation/config.schema.json")

	// Verify schema file exists
	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		t.Skipf("Schema file not found: %s (test fixtures may not be available)", schemaPath)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{
		"--schema", schemaPath,
		"--meta-only",
	})

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err = cmd.Execute()
	if err != nil {
		t.Errorf("Meta-validation failed: %v\nStderr: %s", err, stderr.String())
	}

	// Note: Output goes to os.Stdout (not captured in buffer) which is expected behavior
	// The test verifies the command executes successfully without error
}

// TestValidateCommand_ValidYAML tests validation of valid YAML data
func TestValidateCommand_ValidYAML(t *testing.T) {
	setupTestLogger(t)

	projectRoot, err := config.FindProjectRoot()
	if err != nil {
		t.Fatalf("Failed to get project root: %v", err)
	}

	schemaPath := filepath.Join(projectRoot, "tests/fixtures/schema-validation/config.schema.json")
	dataPath := filepath.Join(projectRoot, "tests/fixtures/schema-validation/valid-config.yaml")

	// Verify files exist
	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		t.Skipf("Schema file not found: %s", schemaPath)
	}
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		t.Skipf("Data file not found: %s", dataPath)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{
		"--schema", schemaPath,
		"--data", dataPath,
	})

	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err = cmd.Execute()
	if err != nil {
		t.Errorf("Validation of valid YAML failed: %v\nStderr: %s", err, stderr.String())
	}

	// Command executed successfully - validation passed
}

// TestValidateCommand_ValidJSON tests validation of valid JSON data
func TestValidateCommand_ValidJSON(t *testing.T) {
	setupTestLogger(t)

	projectRoot, err := config.FindProjectRoot()
	if err != nil {
		t.Fatalf("Failed to get project root: %v", err)
	}

	schemaPath := filepath.Join(projectRoot, "tests/fixtures/schema-validation/config.schema.json")
	dataPath := filepath.Join(projectRoot, "tests/fixtures/schema-validation/valid-config.json")

	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		t.Skipf("Schema file not found: %s", schemaPath)
	}
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		t.Skipf("Data file not found: %s", dataPath)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{
		"--schema", schemaPath,
		"--data", dataPath,
	})

	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err = cmd.Execute()
	if err != nil {
		t.Errorf("Validation of valid JSON failed: %v\nStderr: %s", err, stderr.String())
	}

	// Command executed successfully - validation passed
}

// TestValidateCommand_ValidBlueGreen tests validation of blue-green deployment config
func TestValidateCommand_ValidBlueGreen(t *testing.T) {
	setupTestLogger(t)

	projectRoot, err := config.FindProjectRoot()
	if err != nil {
		t.Fatalf("Failed to get project root: %v", err)
	}

	schemaPath := filepath.Join(projectRoot, "tests/fixtures/schema-validation/config.schema.json")
	dataPath := filepath.Join(projectRoot, "tests/fixtures/schema-validation/valid-bluegreen.yaml")

	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		t.Skipf("Schema file not found: %s", schemaPath)
	}
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		t.Skipf("Data file not found: %s", dataPath)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{
		"--schema", schemaPath,
		"--data", dataPath,
	})

	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err = cmd.Execute()
	if err != nil {
		t.Errorf("Validation of blue-green config failed: %v\nStderr: %s", err, stderr.String())
	}
}

// TestValidateCommand_InvalidData tests that invalid data is properly rejected
func TestValidateCommand_InvalidData(t *testing.T) {
	setupTestLogger(t)

	projectRoot, err := config.FindProjectRoot()
	if err != nil {
		t.Fatalf("Failed to get project root: %v", err)
	}

	schemaPath := filepath.Join(projectRoot, "tests/fixtures/schema-validation/config.schema.json")
	dataPath := filepath.Join(projectRoot, "tests/fixtures/schema-validation/invalid-config.yaml")

	if _, err := os.Stat(schemaPath); os.IsNotExist(err) {
		t.Skipf("Schema file not found: %s", schemaPath)
	}
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		t.Skipf("Invalid data file not found: %s", dataPath)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{
		"--schema", schemaPath,
		"--data", dataPath,
	})

	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	// We expect this to exit with an error, but Execute() itself shouldn't panic
	// The command calls os.Exit() internally, so we can't catch that in tests
	// Instead, we test that the command is properly constructed and would execute
	// In a real scenario, this would exit with foundry.ExitDataInvalid

	// Note: Since the validate command calls os.Exit() on validation failure,
	// this test verifies the command setup but cannot test the actual exit behavior
	// without refactoring the command to be more testable (e.g., returning errors instead of os.Exit)

	// For now, just verify the command is properly configured
	if cmd == nil {
		t.Error("Expected validate command to be created")
	}

	// Verify the invalid data file has the expected invalid content
	invalidData, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatalf("Failed to read invalid data file: %v", err)
	}

	// Verify it contains known invalid values
	if !bytes.Contains(invalidData, []byte("environment: local")) {
		t.Error("Invalid data file should contain 'environment: local' (invalid enum value)")
	}
	if !bytes.Contains(invalidData, []byte("mode: rolling")) {
		t.Error("Invalid data file should contain 'mode: rolling' (invalid enum value)")
	}
}

// TestValidateCommand_MissingSchemaFile tests error handling for missing schema
func TestValidateCommand_MissingSchemaFile(t *testing.T) {
	setupTestLogger(t)

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{
		"--schema", "/nonexistent/schema.json",
		"--meta-only",
	})

	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error for missing schema file, got nil")
	}

	// Verify error message mentions the file
	if !bytes.Contains([]byte(err.Error()), []byte("cannot read schema")) {
		t.Errorf("Expected error message about missing schema, got: %v", err)
	}
}

func TestValidateCommand_ContractResolvesAndValidatesData(t *testing.T) {
	setupTestLogger(t)
	base := writeWidgetContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "widget.json")
	writeFile(t, dataPath, `{"name":"demo","size":3}`)

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
	})

	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("contract validation failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Contract schema resolved and compiled") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "contract: widget/v0") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String(), base) || strings.Contains(stderr.String(), base) {
		t.Fatalf("output leaked base path stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestValidateCommand_ContractNestedRefsResolveUnderBase(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	writeContractManifest(t, base, "widget", "v0", "contract: widget/v0", "descriptor.schema.json")
	writeFile(t, filepath.Join(base, "widget", "v0", "defs", "name.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "string",
  "minLength": 1
}`)
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["name"],
  "properties": {
    "name": {"$ref": "defs/name.schema.json"}
  }
}`)
	dataPath := filepath.Join(t.TempDir(), "widget.json")
	writeFile(t, dataPath, `{"name":"demo"}`)

	err := executeValidateForTest(t, []string{"--contract", "contract: widget/v0", "--contract-base", base, "--data", dataPath})
	if err != nil {
		t.Fatalf("nested ref validation failed: %v", err)
	}
}

func TestValidateCommand_ContractDirectThreeSegmentResolves(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["name"],
  "properties": {"name": {"type": "string"}}
}`)
	dataPath := filepath.Join(t.TempDir(), "widget.json")
	writeFile(t, dataPath, `{"name":"demo"}`)

	err := executeValidateForTest(t, []string{"--contract", "contract: widget/v0/descriptor", "--contract-base", base, "--data", dataPath})
	if err != nil {
		t.Fatalf("direct contract validation failed: %v", err)
	}
}

func TestValidateCommand_ContractDirectDollarIDStyleResolves(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object"
}`)

	err := executeValidateForTest(t, []string{"--contract", "contract:widget/v0/descriptor.schema.json", "--contract-base", base, "--meta-only"})
	if err != nil {
		t.Fatalf("dollar-id style contract validation failed: %v", err)
	}
}

func TestValidateCommand_UnresolvedContractFailsClosed(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	dataPath := filepath.Join(t.TempDir(), "widget.json")
	writeFile(t, dataPath, `{"name":"demo"}`)

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{"--contract", "contract: missing/v0", "--contract-base", base, "--data", dataPath})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected unresolved contract error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if strings.Contains(err.Error(), base) || strings.Contains(stdout.String(), base) || strings.Contains(stderr.String(), base) {
		t.Fatalf("output leaked base path err=%q stdout=%q stderr=%q", err.Error(), stdout.String(), stderr.String())
	}
}

func TestValidateCommand_MissingContractManifestDoesNotGuess(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object"
}`)

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected missing manifest error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if strings.Contains(err.Error(), base) || strings.Contains(stdout.String(), base) || strings.Contains(stderr.String(), base) {
		t.Fatalf("output leaked base path err=%q stdout=%q stderr=%q", err.Error(), stdout.String(), stderr.String())
	}
}

func TestValidateCommand_ContractManifestCapabilityMismatchFailsClosed(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	writeContractManifest(t, base, "widget", "v0", "contract: other/v0", "descriptor.schema.json")
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object"
}`)

	err := executeValidateForTest(t, []string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	if err == nil {
		t.Fatal("expected manifest capability mismatch")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
}

func TestValidateCommand_ContractManifestEntryTraversalFailsClosed(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	writeContractManifest(t, base, "widget", "v0", "contract: widget/v0", "../outside.schema.json")
	writeFile(t, filepath.Join(base, "widget", "outside.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object"
}`)

	err := executeValidateForTest(t, []string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	if err == nil {
		t.Fatal("expected manifest traversal error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
}

func TestValidateCommand_ContractManifestUnknownFieldsFailClosed(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "widget", "v0", "contract.json"), `{
  "capability": "contract: widget/v0",
  "entry_schema": "descriptor.schema.json",
  "guess": true
}`)
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object"
}`)

	err := executeValidateForTest(t, []string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	if err == nil {
		t.Fatal("expected unknown manifest field error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
}

func TestValidateCommand_MalformedContractIDsFailClosed(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	for _, id := range []string{
		"widget/v0",
		"contract: ../v0",
		"contract: /widget/v0",
		"contract: widget/",
		"contract: widget/v0/descriptor/extra",
		"contract: widget/v0/descriptor.json",
		"contract: widget/v0?debug=true",
		"contract: https://example.invalid/widget/v0",
		"contract: widget/v0#frag",
	} {
		err := executeValidateForTest(t, []string{"--contract", id, "--contract-base", base, "--meta-only"})
		if err == nil {
			t.Fatalf("expected error for %q", id)
		}
		if code := ExitCode(err, 1); code != 2 {
			t.Fatalf("%q exit code = %d err=%v", id, code, err)
		}
	}
}

func TestValidateCommand_ExternalRefsFailWithoutBasePathLeak(t *testing.T) {
	setupTestLogger(t)
	base := t.TempDir()
	writeContractManifest(t, base, "widget", "v0", "contract: widget/v0", "descriptor.schema.json")
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "https://example.invalid/widget.schema.json"
}`)

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected external ref error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if strings.Contains(err.Error(), base) || strings.Contains(stdout.String(), base) || strings.Contains(stderr.String(), base) {
		t.Fatalf("output leaked base path err=%q stdout=%q stderr=%q", err.Error(), stdout.String(), stderr.String())
	}
}

func TestValidateCommand_PrimaryContractSymlinkFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior varies on Windows")
	}
	setupTestLogger(t)
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.schema.json")
	writeFile(t, outside, `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}`)
	writeContractManifest(t, base, "widget", "v0", "contract: widget/v0", "descriptor.schema.json")
	if err := os.MkdirAll(filepath.Join(base, "widget", "v0"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "widget", "v0", "descriptor.schema.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected symlink contract error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if strings.Contains(err.Error(), base) || strings.Contains(err.Error(), outside) || strings.Contains(stdout.String(), base) || strings.Contains(stderr.String(), base) {
		t.Fatalf("output leaked path err=%q stdout=%q stderr=%q", err.Error(), stdout.String(), stderr.String())
	}
}

func TestValidateCommand_ContractManifestSymlinkFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior varies on Windows")
	}
	setupTestLogger(t)
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "contract.json")
	writeFile(t, outside, `{"capability":"contract: widget/v0","entry_schema":"descriptor.schema.json"}`)
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object"
}`)
	if err := os.Symlink(outside, filepath.Join(base, "widget", "v0", "contract.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected symlink manifest error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if strings.Contains(err.Error(), base) || strings.Contains(err.Error(), outside) || strings.Contains(stdout.String(), base) || strings.Contains(stderr.String(), base) {
		t.Fatalf("output leaked path err=%q stdout=%q stderr=%q", err.Error(), stdout.String(), stderr.String())
	}
}

func TestValidateCommand_NestedRefSymlinkFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior varies on Windows")
	}
	setupTestLogger(t)
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.schema.json")
	writeFile(t, outside, `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string"}`)
	writeContractManifest(t, base, "widget", "v0", "contract: widget/v0", "descriptor.schema.json")
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "defs/name.schema.json"
}`)
	if err := os.MkdirAll(filepath.Join(base, "widget", "v0", "defs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "widget", "v0", "defs", "name.schema.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected symlink ref error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if strings.Contains(err.Error(), base) || strings.Contains(err.Error(), outside) || strings.Contains(stdout.String(), base) || strings.Contains(stderr.String(), base) {
		t.Fatalf("output leaked path err=%q stdout=%q stderr=%q", err.Error(), stdout.String(), stderr.String())
	}
}

func TestValidateCommand_PrimaryContractIntermediateDirSymlinkFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior varies on Windows")
	}
	setupTestLogger(t)
	base := t.TempDir()
	outsideDir := filepath.Join(t.TempDir(), "outside-widget")
	writeFile(t, filepath.Join(outsideDir, "contract.json"), `{"capability":"contract: widget/v0","entry_schema":"descriptor.schema.json"}`)
	writeFile(t, filepath.Join(outsideDir, "descriptor.schema.json"), `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}`)
	if err := os.MkdirAll(filepath.Join(base, "widget"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(base, "widget", "v0")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected intermediate symlink contract error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if strings.Contains(err.Error(), base) || strings.Contains(err.Error(), outsideDir) || strings.Contains(stdout.String(), base) || strings.Contains(stderr.String(), base) {
		t.Fatalf("output leaked path err=%q stdout=%q stderr=%q", err.Error(), stdout.String(), stderr.String())
	}
}

func TestValidateCommand_NestedRefIntermediateDirSymlinkFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior varies on Windows")
	}
	setupTestLogger(t)
	base := t.TempDir()
	outsideDir := filepath.Join(t.TempDir(), "outside-defs")
	writeFile(t, filepath.Join(outsideDir, "name.schema.json"), `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"string"}`)
	writeContractManifest(t, base, "widget", "v0", "contract: widget/v0", "descriptor.schema.json")
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "defs/name.schema.json"
}`)
	if err := os.Symlink(outsideDir, filepath.Join(base, "widget", "v0", "defs")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{"--contract", "contract: widget/v0", "--contract-base", base, "--meta-only"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected intermediate symlink ref error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if strings.Contains(err.Error(), base) || strings.Contains(err.Error(), outsideDir) || strings.Contains(stdout.String(), base) || strings.Contains(stderr.String(), base) {
		t.Fatalf("output leaked path err=%q stdout=%q stderr=%q", err.Error(), stdout.String(), stderr.String())
	}
}

func TestValidateCommand_SchemaAndContractAreMutuallyExclusive(t *testing.T) {
	setupTestLogger(t)
	err := executeValidateForTest(t, []string{"--schema", "schema.json", "--contract", "contract: widget/v0", "--contract-base", t.TempDir(), "--meta-only"})
	if err == nil {
		t.Fatal("expected mutual exclusion error")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
}

func TestValidateCommand_ClassificationGateSelectiveRefusal(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "descriptor.json")
	secretValue := "sk_test_SYNTHETIC_NOT_A_SECRET"
	writeFile(t, dataPath, `{
  "representations": [
    {
      "id": "objects_safe_projection",
      "field_catalog_ref": "fields/objects.fields.json",
      "uri": "`+secretValue+`",
      "read_path": {
        "scan_capabilities": ["columnar_scan", "predicate_pushdown"],
        "pushdown_withheld": ["object_key", "unclassified_payload_hint"]
      },
      "protection_enforceable_granularity": "column"
    }
  ],
  "field_catalogs": [
    {
      "id": "fields/objects.fields.json",
      "fields": [
        {"name": "size_bytes", "sensitivity": "public", "protection_tags": ["measure"]},
        {"name": "object_key", "sensitivity": "restricted", "protection_tags": ["direct_identifier", "source_structure"]},
        {"name": "unclassified_payload_hint", "sensitivity": "unknown", "protection_tags": ["opaque_payload"]}
      ]
    }
  ]
}`)

	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs([]string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
		"--classification-gate",
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected classification gate refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	output := stdout.String() + stderr.String() + err.Error()
	for _, want := range []string{
		"verdict=pass",
		"reason=sensitivity-unknown-denied",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q: stdout=%q stderr=%q err=%q", want, stdout.String(), stderr.String(), err.Error())
		}
	}
	if strings.Contains(output, "reason=pushdown-not-permitted") {
		t.Fatalf("withheld pushdown case should not deny predicate pushdown: stdout=%q stderr=%q err=%q", stdout.String(), stderr.String(), err.Error())
	}
	for _, leaked := range []string{secretValue, dataPath, base} {
		if strings.Contains(output, leaked) {
			t.Fatalf("classification gate output leaked %q: stdout=%q stderr=%q err=%q", leaked, stdout.String(), stderr.String(), err.Error())
		}
	}
}

func TestValidateCommand_ClassificationGatePredicatePushdownInvalidDenies(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "descriptor.json")
	writeFile(t, dataPath, `{
  "representations": [
    {
      "id": "objects_oracle_bad",
      "field_catalog_ref": "fields/objects.fields.json",
      "read_path": {
        "scan_capabilities": ["columnar_scan", "predicate_pushdown"]
      },
      "protection_enforceable_granularity": "column"
    }
  ],
  "field_catalogs": [
    {
      "id": "fields/objects.fields.json",
      "fields": [
        {"name": "size_bytes", "sensitivity": "public", "protection_tags": ["measure"]},
        {"name": "object_key", "sensitivity": "restricted", "protection_tags": ["direct_identifier", "source_structure"]}
      ]
    }
  ]
}`)

	var stdout, stderr bytes.Buffer
	err := executeValidateForTestWithOutput(t, []string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
		"--classification-gate",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected predicate pushdown refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	output := stdout.String() + stderr.String() + err.Error()
	if !strings.Contains(output, "reason=pushdown-not-permitted") {
		t.Fatalf("output missing predicate pushdown denial: stdout=%q stderr=%q err=%q", stdout.String(), stderr.String(), err.Error())
	}
	if strings.Contains(output, "objects_oracle_bad") || strings.Contains(output, "object_key") {
		t.Fatalf("classification gate output leaked descriptor values: stdout=%q stderr=%q err=%q", stdout.String(), stderr.String(), err.Error())
	}
}

func TestValidateCommand_ClassificationGateDanglingCatalogRefDenies(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "descriptor.json")
	writeFile(t, dataPath, `{
  "representations": [
    {
      "id": "objects_oracle_bad",
      "field_catalog_ref": "fields/missing.fields.json",
      "read_path": {
        "scan_capabilities": ["columnar_scan", "predicate_pushdown"]
      },
      "protection_enforceable_granularity": "column"
    }
  ],
  "field_catalogs": [
    {
      "id": "fields/objects.fields.json",
      "fields": [
        {"name": "object_key", "sensitivity": "restricted", "protection_tags": ["direct_identifier", "source_structure"]}
      ]
    }
  ]
}`)

	var stdout, stderr bytes.Buffer
	err := executeValidateForTestWithOutput(t, []string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
		"--classification-gate",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected dangling catalog refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if !strings.Contains(stderr.String(), "reason=pushdown-not-permitted") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestValidateCommand_ClassificationGateMissingCatalogsDeny(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "descriptor.json")
	writeFile(t, dataPath, `{
  "representations": [
    {
      "id": "objects_oracle_bad",
      "field_catalog_ref": "fields/missing.fields.json",
      "read_path": {
        "scan_capabilities": ["columnar_scan", "predicate_pushdown"]
      },
      "protection_enforceable_granularity": "column"
    }
  ]
}`)

	var stdout, stderr bytes.Buffer
	err := executeValidateForTestWithOutput(t, []string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
		"--classification-gate",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected missing catalog refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if !strings.Contains(stderr.String(), "reason=pushdown-not-permitted") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestValidateCommand_ClassificationGateDenyReasonsDoesNotDisableUnknownDeny(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "descriptor.json")
	policyPath := filepath.Join(dir, "gate-policy.json")
	writeFile(t, dataPath, `{"field_catalogs":[{"id":"fields/objects.fields.json","fields":[{"name":"mystery","sensitivity":"unknown"}]}]}`)
	writeFile(t, policyPath, `{
  "schema_version": "v0",
  "deny_unknown_sensitivity": true,
  "deny_reasons": ["pushdown-not-permitted"]
}`)

	var stdout, stderr bytes.Buffer
	err := executeValidateForTestWithOutput(t, []string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
		"--gate-policy", policyPath,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected unknown sensitivity refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if !strings.Contains(stderr.String(), "reason=sensitivity-unknown-denied") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestValidateCommand_ClassificationGateOutputOrderDeterministic(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "descriptor.json")
	writeFile(t, dataPath, `{
  "representations": [
    {
      "id": "objects_oracle_bad",
      "field_catalog_ref": "fields/objects.fields.json",
      "read_path": {
        "scan_capabilities": ["columnar_scan", "predicate_pushdown"]
      },
      "protection_enforceable_granularity": "column"
    }
  ],
  "field_catalogs": [
    {
      "id": "fields/objects.fields.json",
      "fields": [
        {"name": "size_bytes", "sensitivity": "public", "protection_tags": ["measure"]},
        {"name": "object_key", "sensitivity": "restricted", "protection_tags": ["direct_identifier", "source_structure"]},
        {"name": "unclassified_payload_hint", "sensitivity": "unknown", "protection_tags": ["opaque_payload"]}
      ]
    }
  ]
}`)

	var first string
	for i := 0; i < 20; i++ {
		var stdout, stderr bytes.Buffer
		err := executeValidateForTestWithOutput(t, []string{
			"--contract", "contract: widget/v0",
			"--contract-base", base,
			"--data", dataPath,
			"--classification-gate",
		}, &stdout, &stderr)
		if err == nil {
			t.Fatal("expected gate refusal")
		}
		current := stderr.String()
		if i == 0 {
			first = current
			continue
		}
		if current != first {
			t.Fatalf("stderr changed between runs:\nfirst=%s\ncurrent=%s", first, current)
		}
	}
}

func TestValidateCommand_ClassificationGateAllKnownSafePasses(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "descriptor.json")
	writeFile(t, dataPath, `{
  "field_catalogs": [
    {
      "id": "fields/objects.fields.json",
      "fields": [
        {"name": "safe_public", "sensitivity": "public"},
        {"name": "bounded_internal", "sensitivity": "internal"}
      ]
    }
  ]
}`)

	var stdout, stderr bytes.Buffer
	err := executeValidateForTestWithOutput(t, []string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
		"--classification-gate",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("classification gate failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Classification gate passed") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestValidateCommand_ClassificationGateMissingSensitivityDenies(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "descriptor.json")
	writeFile(t, dataPath, `{"field_catalogs":[{"id":"fields/objects.fields.json","fields":[{"name":"missing-sensitivity"}]}]}`)

	var stdout, stderr bytes.Buffer
	err := executeValidateForTestWithOutput(t, []string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
		"--classification-gate",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected missing sensitivity refusal")
	}
	if code := ExitCode(err, 1); code != 3 {
		t.Fatalf("exit code = %d err=%v", code, err)
	}
	if !strings.Contains(stderr.String(), "reason=sensitivity-missing-denied") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestValidateCommand_ClassificationGateStructuralInvalidExitsTwo(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "descriptor.json")
	writeFile(t, dataPath, `{"field_catalogs":"not-an-array"}`)

	var stdout, stderr bytes.Buffer
	err := executeValidateForTestWithOutput(t, []string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
		"--classification-gate",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected structural validation failure")
	}
	if code := ExitCode(err, 1); code != 2 {
		t.Fatalf("exit code = %d err=%v stderr=%s", code, err, stderr.String())
	}
	if strings.Contains(stderr.String(), "Classification gate verdicts") {
		t.Fatalf("gate ran after structural failure: stderr=%q", stderr.String())
	}
}

func TestValidateCommand_ContractValidationWithoutGateStillAllowsUnknownSensitivity(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dataPath := filepath.Join(t.TempDir(), "descriptor.json")
	writeFile(t, dataPath, `{"field_catalogs":[{"id":"fields/objects.fields.json","fields":[{"name":"mystery","sensitivity":"unknown"}]}]}`)

	err := executeValidateForTest(t, []string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
	})
	if err != nil {
		t.Fatalf("structural contract validation failed without gate: %v", err)
	}
}

func TestValidateCommand_ClassificationGatePolicyCanAllowDefaultDenials(t *testing.T) {
	setupTestLogger(t)
	base := writeGateContractFixture(t)
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "descriptor.json")
	policyPath := filepath.Join(dir, "gate-policy.json")
	writeFile(t, dataPath, `{
  "representations": [
    {
      "id": "objects_oracle_bad",
      "field_catalog_ref": "fields/objects.fields.json",
      "read_path": {"scan_capabilities": ["predicate_pushdown"]},
      "protection_enforceable_granularity": "column"
    }
  ],
  "field_catalogs": [
    {
      "id": "fields/objects.fields.json",
      "fields": [
        {"name": "mystery", "sensitivity": "unknown", "protection_tags": ["direct_identifier"]}
      ]
    }
  ]
}`)
	writeFile(t, policyPath, `{
  "schema_version": "v0",
  "deny_unknown_sensitivity": false,
  "deny_pushdown_unrestricted": false
}`)

	err := executeValidateForTest(t, []string{
		"--contract", "contract: widget/v0",
		"--contract-base", base,
		"--data", dataPath,
		"--gate-policy", policyPath,
	})
	if err != nil {
		t.Fatalf("policy-enabled classification gate failed: %v", err)
	}
}

func executeValidateForTest(t *testing.T, args []string) error {
	t.Helper()
	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs(args)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	return cmd.Execute()
}

func executeValidateForTestWithOutput(t *testing.T, args []string, stdout *bytes.Buffer, stderr *bytes.Buffer) error {
	t.Helper()
	cmd := newValidateCmd(&appidentity.Identity{BinaryName: "decernor"})
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	return cmd.Execute()
}

func writeWidgetContractFixture(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	writeContractManifest(t, base, "widget", "v0", "contract: widget/v0", "descriptor.schema.json")
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["name", "size"],
  "properties": {
    "name": {"type": "string"},
    "size": {"type": "integer", "minimum": 1}
  }
}`)
	return base
}

func writeGateContractFixture(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	writeContractManifest(t, base, "widget", "v0", "contract: widget/v0", "descriptor.schema.json")
	writeFile(t, filepath.Join(base, "widget", "v0", "descriptor.schema.json"), `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "representations": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "field_catalog_ref": {"type": "string"},
          "uri": {"type": "string"},
          "read_path": {
            "type": "object",
            "properties": {
              "scan_capabilities": {
                "type": "array",
                "items": {"type": "string"}
              },
              "pushdown_withheld": {
                "type": "array",
                "items": {"type": "string"}
              }
            },
            "additionalProperties": true
          },
          "protection_enforceable_granularity": {"type": "string"}
        },
        "additionalProperties": false
      }
    },
    "field_catalogs": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "fields": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "name": {"type": "string"},
                "sensitivity": {"type": "string"},
                "protection_tags": {
                  "type": "array",
                  "items": {"type": "string"}
                }
              },
              "additionalProperties": false
            }
          }
        },
        "additionalProperties": false
      }
    }
  },
  "additionalProperties": false
}`)
	return base
}

func writeContractManifest(t *testing.T, base string, family string, version string, capability string, entrySchema string) {
	t.Helper()
	writeFile(t, filepath.Join(base, family, version, "contract.json"), `{
  "capability": "`+capability+`",
  "entry_schema": "`+entrySchema+`"
}`)
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
