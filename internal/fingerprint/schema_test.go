package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestFingerprintRecordSchemaFixtures(t *testing.T) {
	schema := compileFingerprintRecordSchema(t)
	root := fingerprintRepoRoot(t)
	validDir := filepath.Join(root, "tests", "fixtures", "fingerprint-record", "valid")
	invalidDir := filepath.Join(root, "tests", "fixtures", "fingerprint-record", "invalid")

	valid := readJSONFixtures(t, validDir)
	if len(valid) == 0 {
		t.Fatal("expected valid fingerprint-record fixtures")
	}
	for name, doc := range valid {
		if err := schema.Validate(doc); err != nil {
			t.Fatalf("valid fixture %s rejected: %v", name, err)
		}
	}

	invalid := readJSONFixtures(t, invalidDir)
	if len(invalid) == 0 {
		t.Fatal("expected invalid fingerprint-record fixtures")
	}
	for name, doc := range invalid {
		if err := schema.Validate(doc); err == nil {
			t.Fatalf("invalid fixture %s accepted", name)
		}
	}
}

func compileFingerprintRecordSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join(fingerprintRepoRoot(t), "schemas", "fingerprint-record.v0.schema.json")
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func fingerprintRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readJSONFixtures(t *testing.T, dir string) map[string]any {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		out[entry.Name()] = doc
	}
	return out
}
