package gate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/3leaps/decernor/internal/scanner"
	"gopkg.in/yaml.v3"
)

type Reason string

const (
	ReasonSensitivityUnknownDenied Reason = "sensitivity-unknown-denied"
	ReasonSensitivityMissingDenied Reason = "sensitivity-missing-denied"
	ReasonUnclassifiable           Reason = "unclassifiable"
	ReasonPushdownNotPermitted     Reason = "pushdown-not-permitted"
)

type Verdict string

const (
	VerdictPass Verdict = "pass"
	VerdictDeny Verdict = "deny"
)

type Policy struct {
	Schema                       string                `json:"$schema,omitempty" yaml:"$schema,omitempty"`
	SchemaVersion                string                `json:"schema_version" yaml:"schema_version"`
	DenyUnknownSensitivity       *bool                 `json:"deny_unknown_sensitivity,omitempty" yaml:"deny_unknown_sensitivity,omitempty"`
	DenyMissingSensitivity       *bool                 `json:"deny_missing_sensitivity,omitempty" yaml:"deny_missing_sensitivity,omitempty"`
	DenyPushdownUnrestricted     *bool                 `json:"deny_pushdown_unrestricted,omitempty" yaml:"deny_pushdown_unrestricted,omitempty"`
	AllowedSensitivities         []scanner.Sensitivity `json:"allowed_sensitivities,omitempty" yaml:"allowed_sensitivities,omitempty"`
	DenyReasons                  []Reason              `json:"deny_reasons,omitempty" yaml:"deny_reasons,omitempty"`
	AllowPushdownUnrestricted    *bool                 `json:"allow_pushdown_unrestricted,omitempty" yaml:"allow_pushdown_unrestricted,omitempty"`
	AllowUnknownSensitivity      *bool                 `json:"allow_unknown_sensitivity,omitempty" yaml:"allow_unknown_sensitivity,omitempty"`
	AllowUnclassifiedSensitivity *bool                 `json:"allow_unclassified_sensitivity,omitempty" yaml:"allow_unclassified_sensitivity,omitempty"`
}

type Result struct {
	Records []Record
}

type Record struct {
	Locator string
	Verdict Verdict
	Reason  Reason
}

func DefaultPolicy() Policy {
	denyUnknown := true
	denyMissing := true
	denyPushdown := true
	return Policy{
		SchemaVersion:            "v0",
		DenyUnknownSensitivity:   &denyUnknown,
		DenyMissingSensitivity:   &denyMissing,
		DenyPushdownUnrestricted: &denyPushdown,
		AllowedSensitivities: []scanner.Sensitivity{
			scanner.SensitivityPublic,
			scanner.SensitivityConfidential,
			scanner.SensitivityBlinded,
			scanner.SensitivityProprietary,
			scanner.SensitivityPersonal,
			scanner.SensitivityPrivileged,
			scanner.SensitivityEyesOnly,
		},
		DenyReasons: []Reason{
			ReasonSensitivityUnknownDenied,
			ReasonSensitivityMissingDenied,
			ReasonUnclassifiable,
			ReasonPushdownNotPermitted,
		},
	}
}

func LoadPolicy(path string) (Policy, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Policy{}, fmt.Errorf("gate policy is not readable")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Policy{}, fmt.Errorf("gate policy must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return Policy{}, fmt.Errorf("gate policy is not a regular file")
	}
	content, err := os.ReadFile(path) // #nosec G304 -- Explicit user-provided policy input.
	if err != nil {
		return Policy{}, fmt.Errorf("gate policy is not readable")
	}
	var policy Policy
	if isJSON(content) {
		dec := json.NewDecoder(bytes.NewReader(content))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&policy); err != nil {
			return Policy{}, fmt.Errorf("gate policy is invalid")
		}
	} else {
		dec := yaml.NewDecoder(bytes.NewReader(content))
		dec.KnownFields(true)
		if err := dec.Decode(&policy); err != nil {
			return Policy{}, fmt.Errorf("gate policy is invalid")
		}
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy.withDefaults(), nil
}

func (p Policy) Validate() error {
	if p.SchemaVersion != "" && p.SchemaVersion != "v0" {
		return fmt.Errorf("gate policy schema_version must be v0")
	}
	for _, sensitivity := range p.AllowedSensitivities {
		if _, ok := normalizeSensitivity(string(sensitivity)); !ok {
			return fmt.Errorf("gate policy contains unsupported sensitivity")
		}
	}
	for _, reason := range p.DenyReasons {
		if !isClosedReason(reason) {
			return fmt.Errorf("gate policy contains unsupported denial reason")
		}
	}
	return nil
}

func (p Policy) withDefaults() Policy {
	defaults := DefaultPolicy()
	if p.SchemaVersion == "" {
		p.SchemaVersion = defaults.SchemaVersion
	}
	if p.DenyUnknownSensitivity == nil {
		if p.AllowUnknownSensitivity != nil {
			value := !*p.AllowUnknownSensitivity
			p.DenyUnknownSensitivity = &value
		} else {
			p.DenyUnknownSensitivity = defaults.DenyUnknownSensitivity
		}
	}
	if p.DenyMissingSensitivity == nil {
		if p.AllowUnclassifiedSensitivity != nil {
			value := !*p.AllowUnclassifiedSensitivity
			p.DenyMissingSensitivity = &value
		} else {
			p.DenyMissingSensitivity = defaults.DenyMissingSensitivity
		}
	}
	if p.DenyPushdownUnrestricted == nil {
		if p.AllowPushdownUnrestricted != nil {
			value := !*p.AllowPushdownUnrestricted
			p.DenyPushdownUnrestricted = &value
		} else {
			p.DenyPushdownUnrestricted = defaults.DenyPushdownUnrestricted
		}
	}
	if len(p.AllowedSensitivities) == 0 {
		p.AllowedSensitivities = defaults.AllowedSensitivities
	}
	if len(p.DenyReasons) == 0 {
		p.DenyReasons = defaults.DenyReasons
	}
	return p
}

func EvaluateJSON(data []byte, policy Policy) (Result, error) {
	policy = policy.withDefaults()
	var payload interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return Result{}, fmt.Errorf("invalid JSON: %w", err)
	}
	evaluator := evaluator{policy: policy}
	evaluator.walk(payload, "root", "")
	return Result{Records: evaluator.records}, nil
}

func (r Result) Denied() bool {
	for _, record := range r.Records {
		if record.Verdict == VerdictDeny {
			return true
		}
	}
	return false
}

type evaluator struct {
	policy  Policy
	records []Record
}

func (e *evaluator) walk(value interface{}, locator string, parentKey string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		if e.isCandidate(typed, parentKey) {
			e.evaluateObject(typed, locator, parentKey)
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := typed[key]
			e.walk(child, locator+"."+safeKey(key), key)
		}
		e.evaluateDescriptorPushdown(typed, locator)
	case []interface{}:
		for i, child := range typed {
			e.walk(child, fmt.Sprintf("%s[%d]", locator, i), parentKey)
		}
	}
}

func (e *evaluator) isCandidate(obj map[string]interface{}, parentKey string) bool {
	if parentKey == "fields" {
		return true
	}
	if _, ok := obj["sensitivity"]; ok {
		return true
	}
	if _, ok := obj["pushdown"]; ok {
		return true
	}
	if _, ok := obj["pushdown_unrestricted"]; ok {
		return true
	}
	if _, ok := obj["read_path"]; ok {
		return true
	}
	return false
}

func (e *evaluator) evaluateObject(obj map[string]interface{}, locator string, parentKey string) {
	if reason, ok := e.sensitivityDenial(obj, parentKey == "fields"); ok {
		e.records = append(e.records, Record{Locator: locator, Verdict: VerdictDeny, Reason: reason})
	} else if _, hasSensitivity := obj["sensitivity"]; hasSensitivity {
		e.records = append(e.records, Record{Locator: locator, Verdict: VerdictPass})
	}
	if e.pushdownDenied(obj) {
		e.records = append(e.records, Record{Locator: locator, Verdict: VerdictDeny, Reason: ReasonPushdownNotPermitted})
	}
}

func (e *evaluator) sensitivityDenial(obj map[string]interface{}, denyMissing bool) (Reason, bool) {
	raw, ok := obj["sensitivity"]
	if !ok {
		if denyMissing && deny(e.policy.DenyMissingSensitivity) {
			return ReasonSensitivityMissingDenied, true
		}
		return "", false
	}
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return ReasonUnclassifiable, true
	}
	if strings.TrimSpace(value) == string(scanner.SensitivityUnknown) {
		return ReasonSensitivityUnknownDenied, deny(e.policy.DenyUnknownSensitivity)
	}
	sensitivity, ok := normalizeSensitivity(value)
	if !ok {
		return ReasonUnclassifiable, true
	}
	if !containsSensitivity(e.policy.AllowedSensitivities, sensitivity) {
		return ReasonUnclassifiable, true
	}
	return "", false
}

func normalizeSensitivity(value string) (scanner.Sensitivity, bool) {
	switch strings.TrimSpace(value) {
	case string(scanner.SensitivityPublic), "public":
		return scanner.SensitivityPublic, true
	case string(scanner.SensitivityConfidential), "internal":
		return scanner.SensitivityConfidential, true
	case string(scanner.SensitivityBlinded):
		return scanner.SensitivityBlinded, true
	case string(scanner.SensitivityProprietary), "controlled":
		return scanner.SensitivityProprietary, true
	case string(scanner.SensitivityPersonal):
		return scanner.SensitivityPersonal, true
	case string(scanner.SensitivityPrivileged), "restricted":
		return scanner.SensitivityPrivileged, true
	case string(scanner.SensitivityEyesOnly):
		return scanner.SensitivityEyesOnly, true
	default:
		return "", false
	}
}

func (e *evaluator) pushdownDenied(obj map[string]interface{}) bool {
	if !deny(e.policy.DenyPushdownUnrestricted) {
		return false
	}
	if raw, ok := obj["pushdown"]; ok {
		if value, ok := raw.(string); ok && value == "unrestricted" {
			return true
		}
	}
	if raw, ok := obj["pushdown_unrestricted"]; ok {
		if value, ok := raw.(bool); ok && value {
			return true
		}
	}
	return false
}

func (e *evaluator) evaluateDescriptorPushdown(obj map[string]interface{}, locator string) {
	if !deny(e.policy.DenyPushdownUnrestricted) {
		return
	}
	catalogs := fieldCatalogsByID(obj)
	representations, ok := obj["representations"].([]interface{})
	if !ok {
		return
	}
	for i, rawRepresentation := range representations {
		representation, ok := rawRepresentation.(map[string]interface{})
		if !ok {
			continue
		}
		if !representationUsesPredicatePushdown(representation) {
			continue
		}
		catalogID, _ := representation["field_catalog_ref"].(string)
		catalog, ok := catalogs[catalogID]
		if catalogID == "" || !ok {
			e.records = append(e.records, pushdownDenialRecord(locator, i))
			continue
		}
		if representationAllowsProtectedPushdown(representation) {
			continue
		}
		withheld := withheldFields(representation)
		if catalogHasUnwithheldPushdownProtectedField(catalog, withheld) {
			e.records = append(e.records, pushdownDenialRecord(locator, i))
		}
	}
}

func pushdownDenialRecord(locator string, index int) Record {
	return Record{
		Locator: fmt.Sprintf("%s.representations[%d]", locator, index),
		Verdict: VerdictDeny,
		Reason:  ReasonPushdownNotPermitted,
	}
}

func fieldCatalogsByID(obj map[string]interface{}) map[string]map[string]interface{} {
	catalogs := map[string]map[string]interface{}{}
	rawCatalogs, ok := obj["field_catalogs"].([]interface{})
	if !ok {
		return catalogs
	}
	for _, rawCatalog := range rawCatalogs {
		catalog, ok := rawCatalog.(map[string]interface{})
		if !ok {
			continue
		}
		id, ok := catalog["id"].(string)
		if !ok || id == "" {
			continue
		}
		catalogs[id] = catalog
	}
	return catalogs
}

func representationUsesPredicatePushdown(representation map[string]interface{}) bool {
	readPath, ok := representation["read_path"].(map[string]interface{})
	if !ok {
		return false
	}
	capabilities, ok := readPath["scan_capabilities"].([]interface{})
	if !ok {
		return false
	}
	for _, rawCapability := range capabilities {
		if capability, ok := rawCapability.(string); ok && capability == "predicate_pushdown" {
			return true
		}
	}
	return false
}

func representationAllowsProtectedPushdown(representation map[string]interface{}) bool {
	granularity, _ := representation["protection_enforceable_granularity"].(string)
	return granularity == "row" || granularity == "cell"
}

func withheldFields(representation map[string]interface{}) map[string]bool {
	result := map[string]bool{}
	readPath, ok := representation["read_path"].(map[string]interface{})
	if !ok {
		return result
	}
	withheld, ok := readPath["pushdown_withheld"].([]interface{})
	if !ok {
		return result
	}
	for _, rawField := range withheld {
		field, ok := rawField.(string)
		if ok && field != "" {
			result[field] = true
		}
	}
	return result
}

func catalogHasUnwithheldPushdownProtectedField(catalog map[string]interface{}, withheld map[string]bool) bool {
	fields, ok := catalog["fields"].([]interface{})
	if !ok {
		return false
	}
	for _, rawField := range fields {
		field, ok := rawField.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := field["name"].(string)
		if name == "" || withheld[name] {
			continue
		}
		if fieldRequiresPushdownProtection(field) {
			return true
		}
	}
	return false
}

func fieldRequiresPushdownProtection(field map[string]interface{}) bool {
	if rawSensitivity, ok := field["sensitivity"].(string); ok {
		switch rawSensitivity {
		case "controlled", "restricted":
			return true
		}
	}
	tags, ok := field["protection_tags"].([]interface{})
	if !ok {
		return false
	}
	for _, rawTag := range tags {
		tag, ok := rawTag.(string)
		if !ok {
			continue
		}
		switch tag {
		case "direct_identifier", "linkage_key", "source_structure":
			return true
		}
	}
	return false
}

func deny(value *bool) bool {
	return value != nil && *value
}

func containsSensitivity(values []scanner.Sensitivity, target scanner.Sensitivity) bool {
	for _, value := range values {
		normalized, ok := normalizeSensitivity(string(value))
		if ok && normalized == target {
			return true
		}
	}
	return false
}

func isClosedReason(reason Reason) bool {
	switch reason {
	case ReasonSensitivityUnknownDenied,
		ReasonSensitivityMissingDenied,
		ReasonUnclassifiable,
		ReasonPushdownNotPermitted:
		return true
	default:
		return false
	}
}

func safeKey(key string) string {
	switch key {
	case "field_catalogs", "fields", "items", "read_path", "representations":
		return key
	default:
		return "object"
	}
}

func isJSON(content []byte) bool {
	trimmed := strings.TrimSpace(string(content))
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}
