package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/3leaps/decernor/internal/scanner"
)

type verifyFixture struct {
	txt, ndjson, gpg, mini string
	miniFP                 string
}

func makeVerifyFixture(t *testing.T) verifyFixture {
	t.Helper()
	dir := t.TempDir()
	miniBlob := append([]byte("Ed12345678"), make([]byte, 32)...)
	miniSum := sha256.Sum256(miniBlob) // Independent oracle, not the product derivation.
	miniFP := hex.EncodeToString(miniSum[:])
	fixture := verifyFixture{
		txt: filepath.Join(dir, "anchors.txt"), ndjson: filepath.Join(dir, "anchors.ndjson"),
		gpg: filepath.Join(dir, "public.asc"), mini: filepath.Join(dir, "public.pub"), miniFP: miniFP,
	}
	writeFixture(t, fixture.txt, []byte("gpg "+testPrimaryFP+"\nminisign "+miniFP+"\n"))
	writeFixture(t, fixture.gpg, []byte(syntheticPGPArmor()))
	writeFixture(t, fixture.mini, []byte("untrusted comment: minisign public key\n"+base64.StdEncoding.EncodeToString(miniBlob)+"\n"))
	writePairRecords(t, fixture, nil)
	return fixture
}

func writeFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func pairRecords(f verifyFixture) []map[string]any {
	return []map[string]any{
		{"schema_version": "v0", "kind": "gpg", "class": "public", "algorithm": "openpgp-fingerprint", "fingerprint": testPrimaryFP, "fingerprint_scheme": string(SchemeGPGOpenPGPFingerprint), "key_id": testPrimaryID, "key_role": "primary", "confidence": "high"},
		{"schema_version": "v0", "kind": "minisign", "class": "public", "algorithm": "sha256", "fingerprint": f.miniFP, "fingerprint_scheme": string(SchemeMinisignPublicBlobSHA256), "confidence": "high"},
	}
}

func writePairRecords(t *testing.T, f verifyFixture, change func([]map[string]any)) {
	t.Helper()
	records := pairRecords(f)
	if change != nil {
		change(records)
	}
	var data []byte
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, line...)
		data = append(data, '\n')
	}
	writeFixture(t, f.ndjson, data)
}

func colonFixture(validity string, created, expiry int64) string {
	return fmt.Sprintf("pub:%s:3072:1:%s:%d:%d:::::\nfpr:::::::::%s:\n", validity, testPrimaryID, created, expiry, testPrimaryFP)
}

func runVerifyFixture(t *testing.T, f verifyFixture, colon string, asOf time.Time, allow bool) (VerifyResult, error) {
	t.Helper()
	return Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{
		AsOf: asOf, AllowExpired: allow,
		GPGHelper: func(context.Context, []byte, time.Duration) (string, error) { return colon, nil },
	})
}

func verifyCode(err error) int {
	var coded *VerifyError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return -1
}

func TestVerifyMatchMismatchAndValidity(t *testing.T) {
	f := makeVerifyFixture(t)
	instant := time.Unix(2000, 0).UTC()
	for _, tc := range []struct {
		name, colon string
		allow       bool
		wantCode    int
		wantStatus  string
		wantValid   string
	}{
		{"match", colonFixture("u", 1000, 3000), false, 0, "match", "ok"},
		{"expired", colonFixture("e", 1000, 2000), false, 6, "match", "expired"},
		{"allowed", colonFixture("e", 1000, 2000), true, 0, "match", "expired_allowed"},
		{"revoked", colonFixture("r", 1000, 3000), true, 6, "match", "revoked"},
		{"future", colonFixture("u", 2001, 3000), true, 6, "match", "not_yet_valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := runVerifyFixture(t, f, tc.colon, instant, tc.allow)
			if err != nil || result.ExitCode != tc.wantCode || len(result.Records) != 2 || result.Records[0].Status != tc.wantStatus || result.Records[0].Validity != tc.wantValid {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if result.Records[1].Kind != "minisign" || result.Records[1].Validity != "not_applicable" {
				t.Fatalf("order/minisign=%+v", result.Records)
			}
		})
	}
	// One second before and after each boundary, plus fractional seconds at it.
	for _, tc := range []struct {
		instant int64
		valid   string
	}{{1999, "ok"}, {2000, "expired"}, {2001, "expired"}} {
		result, err := runVerifyFixture(t, f, colonFixture("e", 1000, 2000), time.Unix(tc.instant, 500).UTC(), false)
		if err != nil || result.Records[0].Validity != tc.valid {
			t.Fatalf("instant=%d result=%+v err=%v", tc.instant, result, err)
		}
	}
	for _, tc := range []struct {
		instant int64
		valid   string
	}{{999, "not_yet_valid"}, {1000, "ok"}} {
		result, err := runVerifyFixture(t, f, colonFixture("u", 1000, 3000), time.Unix(tc.instant, 0).UTC(), false)
		if err != nil || result.Records[0].Validity != tc.valid {
			t.Fatalf("creation instant=%d result=%+v err=%v", tc.instant, result, err)
		}
	}
	result, err := Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{
		AsOf: time.Time{}, AsOfSet: true,
		GPGHelper: func(context.Context, []byte, time.Duration) (string, error) {
			return colonFixture("u", 1000, 3000), nil
		},
	})
	if err != nil || result.ExitCode != 6 || result.Records[0].Validity != "not_yet_valid" {
		t.Fatalf("explicit zero instant was ignored: result=%+v err=%v", result, err)
	}
}

func TestVerifyPairEligibilityAndGrammar(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]map[string]any)
	}{
		{"private", func(r []map[string]any) { r[0]["class"] = "private" }},
		{"other", func(r []map[string]any) { r[0]["class"] = "other" }},
		{"path", func(r []map[string]any) { r[0]["path"] = "public.asc" }},
		{"null", func(r []map[string]any) { r[0]["fingerprint"] = nil }},
		{"wrong-scheme", func(r []map[string]any) { r[1]["fingerprint_scheme"] = "minisign-key-id-v1" }},
		{"wrong-role", func(r []map[string]any) { r[0]["key_role"] = "subkey" }},
		{"wrong-key-id", func(r []map[string]any) { r[0]["key_id"] = testOtherID }},
		{"pair-disagrees", func(r []map[string]any) { r[1]["fingerprint"] = strings.Repeat("b", 64) }},
		{"schema-invalid", func(r []map[string]any) { r[1]["unknown_field"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeVerifyFixture(t)
			writePairRecords(t, f, tc.change)
			_, err := runVerifyFixture(t, f, colonFixture("u", 1000, 3000), time.Unix(2000, 0), false)
			if verifyCode(err) != 4 {
				t.Fatalf("code=%d err=%v", verifyCode(err), err)
			}
		})
	}
	for _, tc := range []struct{ name, text string }{
		{"extra-token", "gpg " + testPrimaryFP + " extra\nminisign "},
		{"crlf", "gpg " + testPrimaryFP + "\r\nminisign "},
		{"no-final-newline", "gpg " + testPrimaryFP + "\nminisign "},
		{"wrong-case", "gpg " + strings.ToLower(testPrimaryFP) + "\nminisign "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeVerifyFixture(t)
			text := tc.text + f.miniFP + "\n"
			if tc.name == "no-final-newline" {
				text = strings.TrimSuffix(text, "\n")
			}
			writeFixture(t, f.txt, []byte(text))
			_, err := runVerifyFixture(t, f, colonFixture("u", 1000, 3000), time.Unix(2000, 0), false)
			if verifyCode(err) != 4 {
				t.Fatalf("code=%d err=%v", verifyCode(err), err)
			}
		})
	}
}

func TestVerifyRefusalAndHelperFailure(t *testing.T) {
	f := makeVerifyFixture(t)
	asOf := time.Unix(2000, 0)
	secret := strings.Replace(colonFixture("u", 1000, 3000), "pub:", "sec:", 1)
	_, err := runVerifyFixture(t, f, secret, asOf, false)
	if verifyCode(err) != 3 {
		t.Fatalf("secret code=%d err=%v", verifyCode(err), err)
	}
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000)+"sec:::::\n", asOf, false)
	if verifyCode(err) != 3 {
		t.Fatalf("secret subkey code=%d err=%v", verifyCode(err), err)
	}
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000)+"pub:u:3072:1:"+testOtherID+":1000:3000:::::\nfpr:::::::::"+testOtherFP+":\n", asOf, false)
	if verifyCode(err) != 3 {
		t.Fatalf("multiple primary code=%d err=%v", verifyCode(err), err)
	}
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000)+"sub:e:3072:1:"+testSubkeyID+":1000:1500:::::\nfpr:::::::::"+testSubkeyFP+":\n", asOf, false)
	if err != nil {
		t.Fatalf("expired subkey changed primary: %v", err)
	}
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000)+"sub:r:3072:1:"+testSubkeyID+":1000:3000:::::\nfpr:::::::::"+testSubkeyFP+":\n", asOf, false)
	if err != nil {
		t.Fatalf("revoked subkey changed primary: %v", err)
	}
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000)+"sub:u:3072:1:"+testSubkeyID+":1000:3000:::::\nfpr:::::::::"+testSubkeyFP+":\n", asOf, false)
	if err != nil {
		t.Fatalf("normal subkey changed primary: %v", err)
	}

	_, err = Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{AsOf: asOf, GPGHelper: func(context.Context, []byte, time.Duration) (string, error) {
		return "", errors.New("helper with sensitive output")
	}})
	if verifyCode(err) != 2 || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("helper code=%d err=%v", verifyCode(err), err)
	}

	writeFixture(t, f.mini, []byte("minisign secret key\n"))
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000), asOf, false)
	if verifyCode(err) != 3 {
		t.Fatalf("minisign secret code=%d err=%v", verifyCode(err), err)
	}
}

func TestVerifyComparisonPrecedesValidityAndHelperFailure(t *testing.T) {
	f := makeVerifyFixture(t)
	instant := time.Unix(2000, 0)
	// The supplied public identity is different from the internally consistent
	// anchor pair. Expiry remains visible even though comparison wins the exit.
	other := strings.ReplaceAll(colonFixture("e", 1000, 1500), testPrimaryID, testOtherID)
	other = strings.ReplaceAll(other, testPrimaryFP, testOtherFP)
	result, err := runVerifyFixture(t, f, other, instant, true)
	if err != nil || result.ExitCode != 5 || result.Records[0].Status != "mismatch" || result.Records[0].Validity != "expired" {
		t.Fatalf("mismatch+expiry result=%+v err=%v", result, err)
	}
	// A helper failure cannot be reported as a mismatch or produce records.
	result, err = Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{
		AsOf:      instant,
		GPGHelper: func(context.Context, []byte, time.Duration) (string, error) { return "", errors.New("helper failed") },
	})
	if verifyCode(err) != 2 || len(result.Records) != 0 {
		t.Fatalf("helper result=%+v err=%v", result, err)
	}
	writePairRecords(t, f, func(records []map[string]any) {
		records[1]["fingerprint"] = strings.Repeat("a", 64)
	})
	writeFixture(t, f.txt, []byte("gpg "+testPrimaryFP+"\nminisign "+strings.Repeat("a", 64)+"\n"))
	result, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000), instant, false)
	if err != nil || result.ExitCode != 5 || result.Records[0].Status != "match" || result.Records[1].Status != "mismatch" {
		t.Fatalf("minisign mismatch result=%+v err=%v", result, err)
	}
}

func TestVerifyNeverReopensCallerPathAfterCapture(t *testing.T) {
	f := makeVerifyFixture(t)
	original, err := os.ReadFile(f.gpg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{
		AsOf: time.Unix(2000, 0),
		GPGHelper: func(_ context.Context, captured []byte, _ time.Duration) (string, error) {
			if string(captured) != string(original) {
				t.Fatal("helper did not receive captured bytes")
			}
			if err := os.Remove(f.gpg); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, f.gpg, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n"))
			return colonFixture("u", 1000, 3000), nil
		},
	})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("post-capture swap changed result: %+v %v", result, err)
	}
}

func TestVerifyPairExtraAndSwappedRecords(t *testing.T) {
	f := makeVerifyFixture(t)
	good, err := os.ReadFile(f.ndjson)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.ndjson, append(append([]byte{}, good...), good...))
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000), time.Unix(2000, 0), false)
	if verifyCode(err) != 4 {
		t.Fatalf("extra record code=%d err=%v", verifyCode(err), err)
	}
	lines := strings.Split(strings.TrimSuffix(string(good), "\n"), "\n")
	writeFixture(t, f.ndjson, []byte(lines[1]+"\n"+lines[0]+"\n"))
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000), time.Unix(2000, 0), false)
	if verifyCode(err) != 4 {
		t.Fatalf("swapped record code=%d err=%v", verifyCode(err), err)
	}
	writeFixture(t, f.ndjson, []byte(lines[0]+"\n"))
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000), time.Unix(2000, 0), false)
	if verifyCode(err) != 4 {
		t.Fatalf("missing record code=%d err=%v", verifyCode(err), err)
	}
	writeFixture(t, f.ndjson, []byte(strings.Replace(string(good), `"class":"public"`, `"class":"private","class":"public"`, 1)))
	_, err = runVerifyFixture(t, f, colonFixture("u", 1000, 3000), time.Unix(2000, 0), false)
	if verifyCode(err) != 4 {
		t.Fatalf("duplicate JSON field code=%d err=%v", verifyCode(err), err)
	}
}

func TestVerifyMissingGPGExecutableFailsClosed(t *testing.T) {
	f := makeVerifyFixture(t)
	t.Setenv("PATH", "")
	result, err := Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{AsOf: time.Unix(2000, 0)})
	if verifyCode(err) != 2 || len(result.Records) != 0 {
		t.Fatalf("missing GPG result=%+v err=%v", result, err)
	}
}

func TestVerifyUnclassifiedGPGHelperOutcome(t *testing.T) {
	f := makeVerifyFixture(t)
	writeFixture(t, f.gpg, []byte("not an OpenPGP key\n"))
	for _, tc := range []struct {
		name   string
		reason string
		code   int
	}{
		{"helper-rejected", "parse-unsupported", 3},
		{"helper-unavailable", "helper-unavailable", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{
				AsOf: time.Unix(2000, 0),
				GPGHelper: func(context.Context, []byte, time.Duration) (string, error) {
					return "", &verifyGPGHelperError{reason: scanner.ArtifactReason(tc.reason)}
				},
			})
			if verifyCode(err) != tc.code || len(result.Records) != 0 {
				t.Fatalf("helper %s result=%+v err=%v", tc.reason, result, err)
			}
		})
	}
}

func TestCaptureRegularRefusesReplacementAndSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "public.asc")
	writeFixture(t, path, []byte(syntheticPGPArmor()))
	if err := os.Symlink(path, filepath.Join(dir, "link.asc")); err == nil {
		_, got := captureRegular(filepath.Join(dir, "link.asc"), verifyMaxFileSize)
		if verifyCode(got) != 3 {
			t.Fatalf("symlink code=%d err=%v", verifyCode(got), got)
		}
	}
	_, got := captureRegular(dir, verifyMaxFileSize)
	if verifyCode(got) != 3 {
		t.Fatalf("directory code=%d err=%v", verifyCode(got), got)
	}
	_, got = captureRegular(path, 1)
	if verifyCode(got) != 2 {
		t.Fatalf("oversize code=%d err=%v", verifyCode(got), got)
	}
	_, got = captureRegularWithHook(path, verifyMaxFileSize, func() {
		_ = os.Rename(path, path+".old")
		writeFixture(t, path, []byte(syntheticPGPArmor()))
	})
	if verifyCode(got) != 3 {
		t.Fatalf("replacement code=%d err=%v", verifyCode(got), got)
	}
	if runtime.GOOS != "windows" {
		_, got = captureRegular("/dev/null", verifyMaxFileSize)
		if verifyCode(got) != 3 {
			t.Fatalf("device code=%d err=%v", verifyCode(got), got)
		}
	}
}
