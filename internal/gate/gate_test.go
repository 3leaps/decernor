package gate

import (
	"reflect"
	"testing"
)

func TestEvaluateJSON_SelectiveVerdicts(t *testing.T) {
	result, err := EvaluateJSON([]byte(selectiveDescriptorJSON()), DefaultPolicy())
	if err != nil {
		t.Fatalf("EvaluateJSON failed: %v", err)
	}
	if !result.Denied() {
		t.Fatal("expected denied result")
	}
	assertRecord(t, result, "root.field_catalogs[0].fields[0]", VerdictPass, "")
	assertRecord(t, result, "root.field_catalogs[0].fields[1]", VerdictPass, "")
	assertRecord(t, result, "root.field_catalogs[0].fields[2]", VerdictDeny, ReasonSensitivityUnknownDenied)
	assertNoRecord(t, result, "root.representations[0]", VerdictDeny, ReasonPushdownNotPermitted)
}

func TestEvaluateJSON_PredicatePushdownDenies(t *testing.T) {
	result, err := EvaluateJSON([]byte(pushdownWithheldMissingDescriptorJSON()), DefaultPolicy())
	if err != nil {
		t.Fatalf("EvaluateJSON failed: %v", err)
	}
	assertRecord(t, result, "root.representations[0]", VerdictDeny, ReasonPushdownNotPermitted)
	assertRecord(t, result, "root.field_catalogs[0].fields[0]", VerdictPass, "")
	assertRecord(t, result, "root.field_catalogs[0].fields[1]", VerdictPass, "")
}

func TestEvaluateJSON_PredicatePushdownDanglingCatalogRefDenies(t *testing.T) {
	result, err := EvaluateJSON([]byte(`{
  "representations": [
    {
      "id": "objects_oracle_bad",
      "field_catalog_ref": "fields/missing.fields.json",
      "read_path": {"scan_capabilities": ["predicate_pushdown"]},
      "protection_enforceable_granularity": "column"
    }
  ],
  "field_catalogs": [
    {
      "id": "fields/objects.fields.json",
      "fields": [
        {"name": "object_key", "sensitivity": "restricted", "protection_tags": ["direct_identifier"]}
      ]
    }
  ]
}`), DefaultPolicy())
	if err != nil {
		t.Fatalf("EvaluateJSON failed: %v", err)
	}
	assertRecord(t, result, "root.representations[0]", VerdictDeny, ReasonPushdownNotPermitted)
}

func TestEvaluateJSON_PredicatePushdownMissingCatalogsDenies(t *testing.T) {
	result, err := EvaluateJSON([]byte(`{
  "representations": [
    {
      "id": "objects_oracle_bad",
      "field_catalog_ref": "fields/missing.fields.json",
      "read_path": {"scan_capabilities": ["predicate_pushdown"]},
      "protection_enforceable_granularity": "column"
    }
  ]
}`), DefaultPolicy())
	if err != nil {
		t.Fatalf("EvaluateJSON failed: %v", err)
	}
	assertRecord(t, result, "root.representations[0]", VerdictDeny, ReasonPushdownNotPermitted)
}

func TestEvaluateJSON_DenyReasonsDoesNotDisableEnabledDenials(t *testing.T) {
	policy := DefaultPolicy()
	policy.DenyReasons = []Reason{ReasonPushdownNotPermitted}
	result, err := EvaluateJSON([]byte(`{"fields":[{"sensitivity":"unknown"}]}`), policy)
	if err != nil {
		t.Fatalf("EvaluateJSON failed: %v", err)
	}
	assertRecord(t, result, "root.fields[0]", VerdictDeny, ReasonSensitivityUnknownDenied)
}

func TestEvaluateJSON_DeterministicOrder(t *testing.T) {
	first, err := EvaluateJSON([]byte(pushdownWithheldMissingDescriptorJSON()), DefaultPolicy())
	if err != nil {
		t.Fatalf("EvaluateJSON failed: %v", err)
	}
	for i := 0; i < 25; i++ {
		next, err := EvaluateJSON([]byte(pushdownWithheldMissingDescriptorJSON()), DefaultPolicy())
		if err != nil {
			t.Fatalf("EvaluateJSON failed: %v", err)
		}
		if !reflect.DeepEqual(first.Records, next.Records) {
			t.Fatalf("records changed between runs:\nfirst=%+v\nnext=%+v", first.Records, next.Records)
		}
	}
}

func TestEvaluateJSON_MissingSensitivityDenies(t *testing.T) {
	result, err := EvaluateJSON([]byte(`{"fields":[{"name":"shape-only"}]}`), DefaultPolicy())
	if err != nil {
		t.Fatalf("EvaluateJSON failed: %v", err)
	}
	assertRecord(t, result, "root.fields[0]", VerdictDeny, ReasonSensitivityMissingDenied)
}

func TestPolicyRejectsOpenDenialReason(t *testing.T) {
	policy := DefaultPolicy()
	policy.DenyReasons = append(policy.DenyReasons, Reason("raw-secret-value"))
	if err := policy.Validate(); err == nil {
		t.Fatal("expected unsupported denial reason error")
	}
}

func assertRecord(t *testing.T, result Result, locator string, verdict Verdict, reason Reason) {
	t.Helper()
	for _, record := range result.Records {
		if record.Locator == locator && record.Verdict == verdict && record.Reason == reason {
			return
		}
	}
	t.Fatalf("missing record locator=%s verdict=%s reason=%s records=%+v", locator, verdict, reason, result.Records)
}

func assertNoRecord(t *testing.T, result Result, locator string, verdict Verdict, reason Reason) {
	t.Helper()
	for _, record := range result.Records {
		if record.Locator == locator && record.Verdict == verdict && record.Reason == reason {
			t.Fatalf("unexpected record locator=%s verdict=%s reason=%s records=%+v", locator, verdict, reason, result.Records)
		}
	}
}

func selectiveDescriptorJSON() string {
	return `{
  "representations": [
    {
      "id": "objects_safe_projection",
      "field_catalog_ref": "fields/objects.fields.json",
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
}`
}

func pushdownWithheldMissingDescriptorJSON() string {
	return `{
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
}`
}
