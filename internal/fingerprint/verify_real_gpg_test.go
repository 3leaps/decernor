package fingerprint

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/3leaps/decernor/internal/scanner"
)

func TestVerifyRealSyntheticGPG(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg absent; captured-helper tests cover the logic in CI")
	}
	// Keep the homedir short: GPG agent sockets on macOS have a short path cap.
	home, err := os.MkdirTemp("/tmp", "dv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := "Synthetic Verify Test <verify@example.invalid>"
	args := []string{"--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", uid, "ed25519", "sign", "1d"}
	if out, err := exec.Command("gpg", args...).CombinedOutput(); err != nil {
		t.Fatalf("synthetic GPG setup failed: %v (%s)", err, strings.ReplaceAll(string(out), uid, "<synthetic-uid>"))
	}
	listing, err := exec.Command("gpg", "--homedir", home, "--batch", "--with-colons", "--list-keys", uid).Output()
	if err != nil {
		t.Fatal(err)
	}
	var fp string
	var created, expiry int64
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Split(line, ":")
		if fields[0] == "pub" && len(fields) > 6 {
			created, _ = strconv.ParseInt(fields[5], 10, 64)
			expiry, _ = strconv.ParseInt(fields[6], 10, 64)
		}
		if fields[0] == "fpr" && len(fields) > 9 && fp == "" {
			fp = fields[9]
		}
	}
	if len(fp) != 40 || created <= 0 || expiry <= created {
		t.Fatal("synthetic GPG oracle was incomplete")
	}
	f := makeVerifyFixture(t)
	public, err := exec.Command("gpg", "--homedir", home, "--batch", "--armor", "--export", uid).Output()
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.gpg, public)
	writeFixture(t, f.txt, []byte("gpg "+fp+"\nminisign "+f.miniFP+"\n"))
	writePairRecords(t, f, func(records []map[string]any) {
		records[0]["fingerprint"] = fp
		records[0]["key_id"] = fp[len(fp)-16:]
	})
	verifyAt := func(instant int64, wantCode int, wantValidity string) {
		t.Helper()
		result, err := Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{AsOf: time.Unix(instant, 0).UTC()})
		if err != nil || result.ExitCode != wantCode || len(result.Records) != 2 || result.Records[0].Validity != wantValidity {
			t.Fatalf("real GPG verify code=%d records=%d validity=%q err=%v", result.ExitCode, len(result.Records), func() string {
				if len(result.Records) == 0 {
					return ""
				}
				return result.Records[0].Validity
			}(), err)
		}
	}
	verifyAt(created, 0, "ok")
	verifyAt(expiry, 6, "expired")
	verifyAt(created-1, 6, "not_yet_valid")
	// This file is synthetic and temporary. No secret export enters the repo.
	secret, err := exec.Command("gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--armor", "--export-secret-keys", uid).Output()
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(filepath.Dir(f.gpg), "synthetic-secret.asc")
	writeFixture(t, secretPath, secret)
	_, err = Verify(context.Background(), f.txt, f.ndjson, secretPath, f.mini, VerifyConfig{AsOf: time.Unix(created, 0).UTC()})
	if verifyCode(err) != 3 {
		t.Fatalf("synthetic secret export code=%d err=%v", verifyCode(err), err)
	}
	binaryPublic, err := exec.Command("gpg", "--homedir", home, "--batch", "--export", uid).Output()
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(filepath.Dir(f.gpg), "synthetic-public.gpg")
	writeFixture(t, binaryPath, binaryPublic)
	result, err := Verify(context.Background(), f.txt, f.ndjson, binaryPath, f.mini, VerifyConfig{AsOf: time.Unix(created, 0).UTC()})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("binary public with helper result=%+v err=%v", result, err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"plain-text", []byte("not an OpenPGP key\n")},
		{"random-bytes", []byte{0x10, 0x27, 0x6e, 0x00, 0x59, 0xaa, 0x04, 0xff}},
	} {
		path := filepath.Join(filepath.Dir(f.gpg), "non-key-"+tc.name+".gpg")
		writeFixture(t, path, tc.data)
		result, err := Verify(context.Background(), f.txt, f.ndjson, path, f.mini, VerifyConfig{AsOf: time.Unix(created, 0).UTC()})
		if verifyCode(err) != 3 || len(result.Records) != 0 {
			t.Fatalf("non-key %s result=%+v err=%v", tc.name, result, err)
		}
	}
	if out, err := exec.Command("gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-add-key", fp, "cv25519", "encr", "1d").CombinedOutput(); err != nil {
		t.Fatalf("synthetic subkey setup failed: %v (%s)", err, string(out))
	}
	revokeSubkey := exec.Command("gpg", "--homedir", home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--command-fd", "0", "--edit-key", fp)
	revokeSubkey.Stdin = strings.NewReader("key 1\nrevkey\ny\n0\nSynthetic test\n\ny\nsave\n")
	if _, err := revokeSubkey.CombinedOutput(); err != nil {
		t.Fatalf("synthetic subkey revocation failed: %v", err)
	}
	listing, err = exec.Command("gpg", "--homedir", home, "--batch", "--with-colons", "--list-keys", uid).Output()
	if err != nil || !strings.Contains(string(listing), "sub:r:") {
		t.Fatal("synthetic subkey did not become revoked")
	}
	publicWithRevokedSubkey, err := exec.Command("gpg", "--homedir", home, "--batch", "--armor", "--export", uid).Output()
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.gpg, publicWithRevokedSubkey)
	result, err = Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{AsOf: time.Unix(created, 0).UTC()})
	if err != nil || result.ExitCode != 0 || result.Records[0].Validity != "ok" {
		t.Fatalf("revoked subkey changed primary result=%+v err=%v", result, err)
	}
	t.Setenv("PATH", "")
	result, err = Verify(context.Background(), f.txt, f.ndjson, binaryPath, f.mini, VerifyConfig{AsOf: time.Unix(created, 0).UTC()})
	if verifyCode(err) != 2 || len(result.Records) != 0 {
		t.Fatalf("binary public without helper result=%+v err=%v", result, err)
	}
}

func TestVerifyRealRevokedGPG(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg absent; captured-helper tests cover the logic in CI")
	}
	home, err := os.MkdirTemp("/tmp", "dv-rev-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := "Synthetic Revoked Verify <revoked@example.invalid>"
	if out, err := exec.Command("gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", uid, "ed25519", "sign", "1d").CombinedOutput(); err != nil {
		t.Fatalf("synthetic GPG setup failed: %v (%s)", err, strings.ReplaceAll(string(out), uid, "<synthetic-uid>"))
	}
	listing, err := exec.Command("gpg", "--homedir", home, "--batch", "--with-colons", "--list-keys", uid).Output()
	if err != nil {
		t.Fatal(err)
	}
	var fp string
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Split(line, ":")
		if fields[0] == "fpr" && len(fields) > 9 {
			fp = fields[9]
			break
		}
	}
	if len(fp) != 40 {
		t.Fatal("synthetic GPG fingerprint missing")
	}
	certPath := filepath.Join(home, "openpgp-revocs.d", fp+".rev")
	cert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	cert = bytes.Replace(cert, []byte(":-----BEGIN PGP PUBLIC KEY BLOCK-----"), []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----"), 1)
	if bytes.Contains(cert, []byte(":-----BEGIN")) {
		t.Fatal("synthetic revocation certificate marker was not removed")
	}
	certFile := filepath.Join(t.TempDir(), "revocation-cert.asc")
	writeFixture(t, certFile, cert)
	if out, err := exec.Command("gpg", "--homedir", home, "--batch", "--yes", "--import", certFile).CombinedOutput(); err != nil {
		t.Fatalf("synthetic revocation import failed: %v (%s)", err, string(out))
	}
	public, err := exec.Command("gpg", "--homedir", home, "--batch", "--armor", "--export", uid).Output()
	if err != nil {
		t.Fatal(err)
	}
	f := makeVerifyFixture(t)
	writeFixture(t, f.gpg, public)
	writeFixture(t, f.txt, []byte("gpg "+fp+"\nminisign "+f.miniFP+"\n"))
	writePairRecords(t, f, func(records []map[string]any) {
		records[0]["fingerprint"] = fp
		records[0]["key_id"] = fp[len(fp)-16:]
	})
	verify := func(cfg VerifyConfig, wantCode int, wantValidity string) VerifyResult {
		t.Helper()
		result, err := Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, cfg)
		if err != nil || result.ExitCode != wantCode || len(result.Records) != 2 || result.Records[0].Validity != wantValidity {
			t.Fatalf("revoked public result=%+v err=%v", result, err)
		}
		return result
	}
	verify(VerifyConfig{}, 6, "revoked")
	verify(VerifyConfig{AllowExpired: true}, 6, "revoked")
	verify(VerifyConfig{AsOf: time.Time{}, AsOfSet: true}, 6, "revoked")
	writeFixture(t, f.txt, []byte("gpg "+testOtherFP+"\nminisign "+f.miniFP+"\n"))
	writePairRecords(t, f, func(records []map[string]any) {
		records[0]["fingerprint"] = testOtherFP
		records[0]["key_id"] = testOtherID
	})
	mismatch := verify(VerifyConfig{}, 5, "revoked")
	if mismatch.Records[0].Status != "mismatch" || mismatch.Records[0].Reason != "fingerprint_mismatch" {
		t.Fatalf("revoked mismatch precedence result=%+v", mismatch)
	}
	writeFixture(t, f.gpg, cert)
	_, err = Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{})
	if verifyCode(err) != 3 {
		t.Fatalf("revocation certificate alone code=%d err=%v", verifyCode(err), err)
	}
	writeFixture(t, f.gpg, public)
	secret, err := exec.Command("gpg", "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--armor", "--export-secret-keys", uid).Output()
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, f.gpg, secret)
	_, err = Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{})
	if verifyCode(err) != 3 {
		t.Fatalf("revoked secret export code=%d err=%v", verifyCode(err), err)
	}
	binaryRevoked, err := exec.Command("gpg", "--homedir", home, "--batch", "--export", uid).Output()
	if err != nil || len(binaryRevoked) < 8 {
		t.Fatal("synthetic binary revoked export missing")
	}
	corrupt := bytes.Clone(binaryRevoked)
	corrupt[len(corrupt)-6] ^= 0xff
	corrupt[len(corrupt)-7] ^= 0x55
	armorCmd := exec.Command("gpg", "--batch", "--enarmor")
	armorCmd.Stdin = bytes.NewReader(corrupt)
	armoredCorrupt, err := armorCmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	armoredCorrupt = bytes.ReplaceAll(armoredCorrupt, []byte("PGP ARMORED FILE"), []byte("PGP PUBLIC KEY BLOCK"))
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"binary", corrupt},
		{"armored", armoredCorrupt},
	} {
		artifact, ok := scanner.ClassifyCaptured(context.Background(), "gpg-input.gpg", tc.data, scanner.Config{EnableGPG: true})
		if !ok || artifact.Classification != scanner.ClassRevocation {
			t.Fatalf("%s corrupted revocation did not reach admission", tc.name)
		}
		writeFixture(t, f.gpg, tc.data)
		_, err = Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{})
		if verifyCode(err) != 3 {
			t.Fatalf("%s corrupted revocation signature code=%d err=%v", tc.name, verifyCode(err), err)
		}
	}
	writeFixture(t, f.gpg, public)
	colon, helperErr := verifyGPGHelper(context.Background(), public, 10*time.Second)
	if helperErr != nil {
		t.Fatal(helperErr)
	}
	_, err = Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{
		GPGHelper: func(context.Context, []byte, time.Duration) (string, error) {
			return strings.Replace(colon, "pub:", "sec:", 1), nil
		},
	})
	if verifyCode(err) != 3 {
		t.Fatalf("revoked colon secret code=%d err=%v", verifyCode(err), err)
	}
	_, err = Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{
		GPGHelper: func(context.Context, []byte, time.Duration) (string, error) {
			return "", &verifyGPGHelperError{reason: "helper-unavailable"}
		},
	})
	if verifyCode(err) != 2 {
		t.Fatalf("revoked helper failure code=%d err=%v", verifyCode(err), err)
	}
	_, err = Verify(context.Background(), f.txt, f.ndjson, f.gpg, f.mini, VerifyConfig{
		GPGHelper: func(context.Context, []byte, time.Duration) (string, error) {
			return "", &verifyGPGHelperError{reason: "parse-unsupported"}
		},
	})
	if verifyCode(err) != 3 {
		t.Fatalf("revoked helper rejection code=%d err=%v", verifyCode(err), err)
	}
}
