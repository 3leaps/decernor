package scanner

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakePacketLister struct {
	output map[string]string
	err    error
}

func (f fakePacketLister) ListPackets(_ context.Context, path string, _ time.Duration) (string, error) {
	return f.output[filepath.Base(path)], f.err
}

func TestScanFlagsKeyringInternalsAndHeaders(t *testing.T) {
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, ".gnupg"))
	mustMkdir(t, filepath.Join(dir, "private-keys-v1.d"))
	mustWrite(t, filepath.Join(dir, "ssh.key"), openSSHPrivateKey("none"))

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}

	if result.Unsafes != 3 {
		t.Fatalf("unsafes = %d, findings = %#v", result.Unsafes, result.Findings)
	}
}

func TestScanClassifiesSSHAndMinisignKeys(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "ssh.key"), openSSHPrivateKey("aes256-ctr"))
	mustWrite(t, filepath.Join(dir, "minisign.key"), "untrusted comment: "+minisignEncryptedSecretMarker()+"\n")
	mustWrite(t, filepath.Join(dir, "maybe.minisign.secret"), "untrusted comment: "+minisignSecretMarker()+"\n")

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}

	counts := map[Classification]int{}
	for _, finding := range result.Findings {
		counts[finding.Classification]++
		if finding.Code == "" || finding.Priority == "" || finding.Rank == 0 || finding.Retention == "" || finding.Exposure == "" || finding.Sensitivity == "" || finding.Confidence == "" {
			t.Fatalf("finding missing guidance fields: %#v", finding)
		}
	}

	if counts[ClassSSHPrivateKey] != 1 {
		t.Fatalf("ssh-private-key count = %d findings=%#v", counts[ClassSSHPrivateKey], result.Findings)
	}
	if counts[ClassMinisignSecret] != 2 {
		t.Fatalf("minisign-secret count = %d findings=%#v", counts[ClassMinisignSecret], result.Findings)
	}
	if result.Warns != 2 || result.Unsafes != 1 {
		t.Fatalf("warns=%d unsafes=%d findings=%#v", result.Warns, result.Unsafes, result.Findings)
	}
}

func TestScanClassifiesMinisignSecretByCommonFilename(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "minisign.key"), "not enough content to prove format\n")

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}

	if result.Warns != 1 || result.Unsafes != 0 {
		t.Fatalf("warns=%d unsafes=%d findings=%#v", result.Warns, result.Unsafes, result.Findings)
	}
	if result.Findings[0].Code != "MINISIGN-SECRET-FILE" {
		t.Fatalf("code = %s", result.Findings[0].Code)
	}
}

func TestScanMinisignPublicRejectsColonBearingExtraPayload(t *testing.T) {
	dir := t.TempDir()
	payload := append([]byte("Ed"), []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}...)
	payload = append(payload, make([]byte, 32)...)
	body := "untrusted comment: synthcorpus generated-real TEST KEY - DO NOT USE\n" +
		base64.StdEncoding.EncodeToString(payload) + "\n" +
		"opaque: additional non-public material\n"
	mustWrite(t, filepath.Join(dir, "mixed.pub"), body)

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.Code == "MINISIGN-PUBLIC-KEY" || f.Classification == ClassPublic || f.Retention == RetentionAllowed {
			t.Fatalf("colon-bearing mixed file must not be public/allowed: %#v", f)
		}
	}
}

func TestScanMinisignPublicRejectsPayloadBeyondPrefix(t *testing.T) {
	// Production scan only feeds the first prefixBytes into the classifier.
	// A valid public-key shape near the start with opaque payload after the
	// structural max (and after prefix) must not stamp public/allowed.
	dir := t.TempDir()
	payload := append([]byte("Ed"), []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}...)
	payload = append(payload, make([]byte, 32)...)
	head := "untrusted comment: synthcorpus generated-real TEST KEY - DO NOT USE\n" +
		base64.StdEncoding.EncodeToString(payload) + "\n"
	// Build a file larger than scan prefixBytes with junk after a public-looking head.
	// Size bound fails closed on the 32 KiB prefix itself (>= 4 KiB max).
	buf := make([]byte, prefixBytes+1024)
	copy(buf, head)
	for i := len(head); i < len(buf); i++ {
		buf[i] = 'x'
	}
	mustWrite(t, filepath.Join(dir, "huge.pub"), string(buf))

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.Code == "MINISIGN-PUBLIC-KEY" || (f.Classification == ClassPublic && f.Retention == RetentionAllowed) {
			t.Fatalf("oversized/truncated-prefix candidate must not be public/allowed: %#v", f)
		}
	}
}

func TestScanMinisignCompletePublicStillClassifies(t *testing.T) {
	dir := t.TempDir()
	payload := append([]byte("Ed"), []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}...)
	payload = append(payload, make([]byte, 32)...)
	body := "untrusted comment: synthcorpus generated-real TEST KEY - DO NOT USE\n" +
		base64.StdEncoding.EncodeToString(payload) + "\n"
	mustWrite(t, filepath.Join(dir, "minisign-plain.pub"), body)

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Code != "MINISIGN-PUBLIC-KEY" {
		t.Fatalf("findings=%#v", result.Findings)
	}
	if result.Findings[0].Classification != ClassPublic || result.Findings[0].Retention != RetentionAllowed {
		t.Fatalf("finding=%#v", result.Findings[0])
	}
}

func TestScanClassifiesEncryptedPEMWithoutSSHKeygenRecommendation(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "encrypted.pem"), privateHeader("ENCRYPTED")+"\n")

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}

	if result.Warns != 1 || result.Unsafes != 0 {
		t.Fatalf("warns=%d unsafes=%d findings=%#v", result.Warns, result.Unsafes, result.Findings)
	}
	finding := result.Findings[0]
	if finding.Code != "PEM-ENCRYPTED-PRIVATE-KEY" {
		t.Fatalf("code = %s", finding.Code)
	}
	if finding.Classification != ClassPrivateKey {
		t.Fatalf("classification = %s", finding.Classification)
	}
	if strings.Contains(finding.Recommendation, "ssh-keygen") {
		t.Fatalf("unexpected ssh-keygen recommendation: %s", finding.Recommendation)
	}
}

func TestScanDoesNotParseKnownKeyringInternalFilesAgain(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "trustdb.gpg"), "not openpgp packets\n")

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{
		output: map[string]string{"trustdb.gpg": "not packet output"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Unsafes != 1 || result.Warns != 0 || len(result.Findings) != 1 {
		t.Fatalf("warns=%d unsafes=%d findings=%#v", result.Warns, result.Unsafes, result.Findings)
	}
	if result.Findings[0].Classification != ClassKeyringInternal {
		t.Fatalf("classification = %s", result.Findings[0].Classification)
	}
}

func TestScanUsesPacketClassification(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "secret.asc"), pgpArmor(joinWords("PRIVATE", "KEY", "BLOCK")))

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{
		output: map[string]string{
			"secret.asc": ":secret key packet:\nskey[0]: [v4 protected]\nprotect algo: 9\n",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Warns != 1 || result.Unsafes != 0 {
		t.Fatalf("warns=%d unsafes=%d findings=%#v", result.Warns, result.Unsafes, result.Findings)
	}
}

func TestScanEmitsAllowedProtectedSecretKeyAsInfo(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "secret.asc"), pgpArmor(joinWords("PRIVATE", "KEY", "BLOCK")))

	result, err := scanWithPacketLister(context.Background(), dir, Config{AllowProtectedSecretKeys: true}, fakePacketLister{
		output: map[string]string{
			"secret.asc": ":secret key packet:\nskey[0]: [v4 protected]\nprotect algo: 9\n",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Warns != 0 || result.Unsafes != 0 || len(result.Findings) != 1 {
		t.Fatalf("warns=%d unsafes=%d findings=%#v", result.Warns, result.Unsafes, result.Findings)
	}
	if result.Findings[0].Severity != SeverityInfo {
		t.Fatalf("severity = %s", result.Findings[0].Severity)
	}
}

func TestScanFlagsPrivateArmorWhenPacketParsingIsAmbiguous(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "secret.asc"), pgpArmor(joinWords("PRIVATE", "KEY", "BLOCK")))

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{
		output: map[string]string{"secret.asc": "not packet output"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Unsafes != 1 {
		t.Fatalf("unsafes=%d findings=%#v", result.Unsafes, result.Findings)
	}
}

func TestScanClassifiesRevocationCertificateByFilenameFallback(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "subject-revoke.asc"), pgpArmor(joinWords("PUBLIC", "KEY", "BLOCK")))

	result, err := scanWithPacketLister(context.Background(), dir, Config{}, fakePacketLister{
		output: map[string]string{"subject-revoke.asc": "not packet output"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if result.Warns != 1 || result.Unsafes != 0 {
		t.Fatalf("warns=%d unsafes=%d findings=%#v", result.Warns, result.Unsafes, result.Findings)
	}
	if result.Findings[0].Classification != ClassRevocation {
		t.Fatalf("classification = %s", result.Findings[0].Classification)
	}
}

func TestClassifyPrefixFallsBackForGPGPublicArmorWhenPacketListingFails(t *testing.T) {
	artifact, ok := classifyPrefixWithPacketLister(context.Background(), "release-key.asc", []byte(pgpArmor(joinWords("PUBLIC", "KEY", "BLOCK"))), Config{}, fakePacketLister{
		err: errors.New("gpg unavailable"),
	})
	if !ok {
		t.Fatal("expected artifact")
	}
	if artifact.Kind != ArtifactKindGPG || artifact.Class != ArtifactClassPublic {
		t.Fatalf("kind/class = %s/%s artifact=%#v", artifact.Kind, artifact.Class, artifact)
	}
	if artifact.Confidence != ConfidenceMedium {
		t.Fatalf("confidence = %s", artifact.Confidence)
	}
}

func mustWrite(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func pgpArmor(kind string) string {
	return "-----" + joinWords("BEGIN", "PGP") + " " + kind + "-----\ncomment\n-----" + joinWords("END", "PGP") + " " + kind + "-----\n"
}

func privateHeader(kind string) string {
	return "-----" + joinWords("BEGIN", kind, "PRIVATE", "KEY") + "-----"
}

func openSSHPrivateKey(cipher string) string {
	var payload []byte
	payload = append(payload, []byte("openssh-key-v1\x00")...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(cipher)))
	payload = append(payload, length[:]...)
	payload = append(payload, []byte(cipher)...)
	encoded := base64.StdEncoding.EncodeToString(payload)
	return "-----" + sshPrivateHeader() + "-----\n" + encoded + "\n-----" + joinWords("END", "OPENSSH", "PRIVATE", "KEY") + "-----\n"
}
