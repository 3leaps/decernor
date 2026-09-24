package fingerprint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/3leaps/decernor/internal/assets/fingerprintschemas"
	"github.com/3leaps/decernor/internal/scanner"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

type VerifyConfig struct {
	AsOf         time.Time
	AsOfSet      bool
	AllowExpired bool
	MaxFileSize  int64
	GPGTimeout   time.Duration
	// GPGHelper is an internal test seam. It must inspect only the supplied bytes.
	GPGHelper func(context.Context, []byte, time.Duration) (string, error)
}

type VerifyRecord struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	Scheme        Scheme `json:"scheme"`
	Status        string `json:"status"`
	Validity      string `json:"validity"`
	Reason        string `json:"reason"`
}

type VerifyResult struct {
	Records  []VerifyRecord
	ExitCode int
}

func Verify(ctx context.Context, anchors, anchorsNDJSON, gpgPath, minisignPath string, cfg VerifyConfig) (VerifyResult, error) {
	if anchors == "" || anchorsNDJSON == "" || gpgPath == "" || minisignPath == "" {
		return VerifyResult{}, verifyError(2, "required-input-missing")
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = verifyMaxFileSize
	}
	if cfg.GPGTimeout <= 0 {
		cfg.GPGTimeout = 10 * time.Second
	}
	if !cfg.AsOfSet && cfg.AsOf.IsZero() {
		cfg.AsOf = time.Now().UTC()
	}
	if cfg.GPGHelper == nil {
		cfg.GPGHelper = verifyGPGHelper
	}

	// Capture every input before pair parsing. All subsequent inspection consumes
	// these exact buffers; no helper receives a caller-controlled path.
	paths := []string{anchors, anchorsNDJSON, gpgPath, minisignPath}
	var data [4][]byte
	for i, path := range paths {
		captured, err := captureRegular(path, cfg.MaxFileSize)
		if err != nil {
			return VerifyResult{}, err
		}
		data[i] = captured
	}

	// Neutral labels prevent caller-controlled basenames from affecting the
	// classifier's header fallback when GPG is unavailable.
	gpgArtifact, gpgOK := scanner.ClassifyCaptured(ctx, "gpg-input.gpg", data[2], scanner.Config{EnableGPG: true, GPGTimeout: cfg.GPGTimeout})
	colon, helperErr := cfg.GPGHelper(ctx, data[2], cfg.GPGTimeout)
	if hasSecretColon(colon) {
		return VerifyResult{}, verifyError(3, "gpg-secret-input-refused")
	}
	isPublic := gpgOK && gpgArtifact.Kind == scanner.ArtifactKindGPG && gpgArtifact.Class == scanner.ArtifactClassPublic
	isRevocationClass := gpgOK && gpgArtifact.Kind == scanner.ArtifactKindGPG && gpgArtifact.Classification == scanner.ClassRevocation
	isRevokedPublicCandidate := false
	if isRevocationClass {
		packetEvidence, packetErr := scanner.InspectCapturedOpenPGPPackets(ctx, data[2], cfg.GPGTimeout)
		if packetEvidence.Secret {
			return VerifyResult{}, verifyError(3, "gpg-secret-input-refused")
		}
		if packetErr != nil {
			return VerifyResult{}, verifyError(2, "gpg-packet-helper-failed")
		}
		if !packetEvidence.PublicPrimary || !packetEvidence.KeyRevocation && !packetEvidence.SubkeyRevocation {
			return VerifyResult{}, verifyError(3, "gpg-revocation-not-public")
		}
		if packetEvidence.KeyRevocation {
			isRevokedPublicCandidate = true
		} else {
			// A revoked subkey does not change a valid primary's status. The
			// classifier can still say revocation when GPG prints a broad
			// revocation-reason phrase, so verify the exact subkey sigclass.
			isPublic = true
		}
	}
	// An unarmored public export needs GPG to classify its packets. When the
	// helper is unavailable, preserve that input/helper failure as exit 2.
	// A class actually identified as unsafe still refuses at exit 3.
	var helperFailure *verifyGPGHelperError
	unclassifiedHelperFailure := !gpgOK && errors.As(helperErr, &helperFailure) && helperFailure.reason == scanner.ArtifactReasonHelperUnavailable
	if !isPublic && !isRevokedPublicCandidate && !unclassifiedHelperFailure {
		return VerifyResult{}, verifyError(3, "gpg-input-not-public")
	}
	miniArtifact, miniOK := scanner.ClassifyCaptured(ctx, "minisign-input.pub", data[3], scanner.Config{EnableMinisign: true, GPGTimeout: cfg.GPGTimeout})
	miniBlob, miniParseOK := scanner.ParseMinisignPublicKeyFile(data[3])
	if !miniOK || miniArtifact.Kind != scanner.ArtifactKindMinisign || miniArtifact.Class != scanner.ArtifactClassPublic || !miniParseOK {
		return VerifyResult{}, verifyError(3, "minisign-input-not-public")
	}

	wantGPG, wantMini, err := parseVerifyPair(data[0], data[1])
	if err != nil {
		return VerifyResult{}, err
	}
	if helperErr != nil {
		if isRevokedPublicCandidate && errors.As(helperErr, &helperFailure) && helperFailure.reason == scanner.ArtifactReasonParseUnsupported {
			return VerifyResult{}, verifyError(3, "gpg-revocation-unverified")
		}
		return VerifyResult{}, verifyError(2, "gpg-helper-failed")
	}
	identities, err := parseOpenPGPColonIdentities(colon)
	if err != nil {
		if isRevokedPublicCandidate {
			return VerifyResult{}, verifyError(3, "gpg-revocation-unverified")
		}
		return VerifyResult{}, verifyError(2, "gpg-helper-output-invalid")
	}
	var primary *openPGPIdentity
	for i := range identities {
		if identities[i].Secret {
			return VerifyResult{}, verifyError(3, "gpg-secret-input-refused")
		}
		if identities[i].KeyRole == KeyRolePrimary {
			if primary != nil {
				return VerifyResult{}, verifyError(3, "gpg-primary-selection-ambiguous")
			}
			primary = &identities[i]
		}
	}
	if primary == nil {
		return VerifyResult{}, verifyError(3, "gpg-primary-missing")
	}
	if isRevokedPublicCandidate && primary.Validity != "r" {
		return VerifyResult{}, verifyError(3, "gpg-revocation-unverified")
	}
	creation, err := parseColonEpoch(primary.CreatedRaw, false)
	if err != nil {
		return VerifyResult{}, verifyError(2, "gpg-creation-invalid")
	}
	expiry, err := parseColonEpoch(primary.ExpiryRaw, true)
	if err != nil {
		return VerifyResult{}, verifyError(2, "gpg-expiry-invalid")
	}
	validity := "ok"
	if primary.Validity == "r" {
		validity = "revoked"
	} else if cfg.AsOf.Unix() < creation {
		validity = "not_yet_valid"
	} else if expiry > 0 && cfg.AsOf.Unix() >= expiry {
		validity = "expired"
	}
	gpgStatus := "match"
	if primary.Fingerprint != wantGPG {
		gpgStatus = "mismatch"
	}
	miniStatus := "match"
	if minisignPublicBlobSHA256(miniBlob) != wantMini {
		miniStatus = "mismatch"
	}
	if cfg.AllowExpired && validity == "expired" && gpgStatus == "match" && miniStatus == "match" {
		validity = "expired_allowed"
	}
	records := []VerifyRecord{
		{SchemaVersion: SchemaVersion, Kind: "gpg", Scheme: SchemeGPGOpenPGPFingerprint, Status: gpgStatus, Validity: validity, Reason: verifyReason(gpgStatus, validity)},
		{SchemaVersion: SchemaVersion, Kind: "minisign", Scheme: SchemeMinisignPublicBlobSHA256, Status: miniStatus, Validity: "not_applicable", Reason: verifyReason(miniStatus, "not_applicable")},
	}
	code := 0
	if gpgStatus != "match" || miniStatus != "match" {
		code = 5
	} else if validity == "expired" || validity == "revoked" || validity == "not_yet_valid" {
		code = 6
	}
	if err := validateVerifyResults(records); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{Records: records, ExitCode: code}, nil
}

func validateVerifyResults(records []VerifyRecord) error {
	const schemaURL = "https://schemas.3leaps.dev/decernor/fingerprint-verify-result.v0.schema.json"
	validator, err := compileEmbeddedVerifySchema(schemaURL, fingerprintschemas.Result())
	if err != nil {
		return verifyError(2, "embedded-result-schema-invalid")
	}
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			return verifyError(2, "verify-result-invalid")
		}
		var value any
		if err := json.Unmarshal(data, &value); err != nil || validator.Validate(value) != nil {
			return verifyError(2, "verify-result-invalid")
		}
	}
	return nil
}

func verifyReason(status, validity string) string {
	switch status {
	case "mismatch":
		return "fingerprint_mismatch"
	case "missing":
		return "missing_key"
	case "extra":
		return "extra_key"
	}
	if validity == "ok" || validity == "not_applicable" {
		return "none"
	}
	return validity
}

func parseColonEpoch(raw string, optional bool) (int64, error) {
	if optional && raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid epoch")
	}
	return value, nil
}

func hasSecretColon(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "sec:") || strings.HasPrefix(line, "ssb:") {
			return true
		}
	}
	return false
}

func verifyGPGHelper(ctx context.Context, data []byte, timeout time.Duration) (string, error) {
	out, reason := runOpenPGPImport(ctx, "", data, timeout)
	if reason != "" {
		return "", &verifyGPGHelperError{reason: reason}
	}
	return out, nil
}

type verifyGPGHelperError struct {
	reason scanner.ArtifactReason
}

func (e *verifyGPGHelperError) Error() string {
	return "gpg helper unavailable or rejected input"
}

func parseVerifyPair(txt, ndjson []byte) (string, string, error) {
	lines := bytes.Split(txt, []byte{'\n'})
	if len(lines) != 3 || len(lines[2]) != 0 || bytes.Contains(txt, []byte{'\r'}) {
		return "", "", verifyError(4, "anchor-txt-invalid")
	}
	var want [2]string
	for i, entry := range []struct {
		prefix string
		length int
		upper  bool
	}{{"gpg ", 40, true}, {"minisign ", 64, false}} {
		line := string(lines[i])
		if !strings.HasPrefix(line, entry.prefix) || len(line) != len(entry.prefix)+entry.length {
			return "", "", verifyError(4, "anchor-txt-invalid")
		}
		want[i] = strings.TrimPrefix(line, entry.prefix)
		for _, r := range want[i] {
			valid := r >= '0' && r <= '9' || r >= 'a' && r <= 'f'
			if entry.upper {
				valid = isUpperHexRune(r)
			}
			if !valid {
				return "", "", verifyError(4, "anchor-txt-invalid")
			}
		}
	}
	if bytes.Contains(ndjson, []byte{'\r'}) {
		return "", "", verifyError(4, "anchor-ndjson-invalid")
	}
	recordLines := bytes.Split(ndjson, []byte{'\n'})
	if len(recordLines) != 3 || len(recordLines[2]) != 0 || len(recordLines[0]) == 0 || len(recordLines[1]) == 0 {
		return "", "", verifyError(4, "anchor-ndjson-invalid")
	}
	const schemaURL = "https://schemas.3leaps.dev/decernor/fingerprint-record.v0.schema.json"
	validator, err := compileEmbeddedVerifySchema(schemaURL, fingerprintschemas.Record())
	if err != nil {
		return "", "", verifyError(2, "embedded-schema-invalid")
	}
	for i, line := range recordLines[:2] {
		record, err := decodeUniqueVerifyRecord(line)
		if err != nil {
			return "", "", verifyError(4, "anchor-ndjson-invalid")
		}
		if err := validator.Validate(record); err != nil {
			return "", "", verifyError(4, "anchor-schema-invalid")
		}
		kind, _ := record["kind"].(string)
		class, _ := record["class"].(string)
		algorithm, _ := record["algorithm"].(string)
		scheme, _ := record["fingerprint_scheme"].(string)
		fp, fpOK := record["fingerprint"].(string)
		if class != "public" || !fpOK || record["path"] != nil {
			return "", "", verifyError(4, "anchor-ineligible")
		}
		if i == 0 {
			if kind != "gpg" || algorithm != "openpgp-fingerprint" || scheme != string(SchemeGPGOpenPGPFingerprint) || record["key_role"] != "primary" || record["key_id"] != fp[len(fp)-openPGPLongKeyIDHexLen:] || fp != want[0] {
				return "", "", verifyError(4, "anchor-pair-disagrees")
			}
		} else if kind != "minisign" || algorithm != "sha256" || scheme != string(SchemeMinisignPublicBlobSHA256) || record["key_role"] != nil || fp != want[1] {
			return "", "", verifyError(4, "anchor-pair-disagrees")
		}
	}
	return want[0], want[1], nil
}

func compileEmbeddedVerifySchema(url string, data []byte) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.LoadURL = func(string) (io.ReadCloser, error) { return nil, fmt.Errorf("external schema fetch disabled") }
	if err := compiler.AddResource(url, bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return compiler.Compile(url)
}

func decodeUniqueVerifyRecord(line []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("expected object")
	}
	record := make(map[string]any)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("non-string key")
		}
		if _, exists := record[key]; exists {
			return nil, fmt.Errorf("duplicate key")
		}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		record[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("object not terminated")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON value")
	}
	return record, nil
}
