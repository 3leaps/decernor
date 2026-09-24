package fingerprint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/3leaps/decernor/internal/assets/fingerprintschemas"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestEmbeddedVerifySchemasResolveOffline(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	compiler.LoadURL = func(string) (io.ReadCloser, error) { return nil, fmt.Errorf("network disabled") }
	const recordURL = "https://schemas.3leaps.dev/decernor/fingerprint-record.v0.schema.json"
	const resultURL = "https://schemas.3leaps.dev/decernor/fingerprint-verify-result.v0.schema.json"
	for url, data := range map[string][]byte{recordURL: fingerprintschemas.Record(), resultURL: fingerprintschemas.Result()} {
		if err := compiler.AddResource(url, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	for _, url := range []string{recordURL, resultURL} {
		if _, err := compiler.Compile(url); err != nil {
			t.Fatalf("offline compile %s: %v", url, err)
		}
	}
	result, err := compiler.Compile(resultURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []VerifyRecord{
		{SchemaVersion: "v0", Kind: "gpg", Scheme: SchemeGPGOpenPGPFingerprint, Status: "match", Validity: "expired_allowed", Reason: "expired_allowed"},
		{SchemaVersion: "v0", Kind: "minisign", Scheme: SchemeMinisignPublicBlobSHA256, Status: "mismatch", Validity: "not_applicable", Reason: "fingerprint_mismatch"},
	} {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		var decoded any
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := result.Validate(decoded); err != nil {
			t.Fatalf("result schema rejected %+v: %v", record, err)
		}
	}
	if err := result.Validate(map[string]any{
		"schema_version": "v0", "kind": "gpg", "scheme": string(SchemeGPGOpenPGPFingerprint),
		"status": "mismatch", "validity": "expired", "reason": "none",
	}); err == nil {
		t.Fatal("schema accepted an unqualified mismatch")
	}
}
