package scanner

import (
	"encoding/base64"
	"testing"
)

func TestClassifyProtectedSecretKey(t *testing.T) {
	finding, ok := classifyPacketOutput("key.asc", ":secret key packet:\nskey[0]: [v4 protected]\nprotect algo: 9\nprotect count: 65011712\n", false)
	if !ok {
		t.Fatal("expected classification")
	}
	if finding.Classification != ClassProtectedSecret {
		t.Fatalf("classification = %s", finding.Classification)
	}
	if finding.Severity != SeverityWarn {
		t.Fatalf("severity = %s", finding.Severity)
	}
}

func TestClassifyAllowedProtectedSecretKey(t *testing.T) {
	finding, ok := classifyPacketOutput("key.asc", ":secret sub key packet:\nskey[0]: [v4 protected]\nprotect algo: 9\n", true)
	if !ok {
		t.Fatal("expected classification")
	}
	if finding.Severity != SeverityInfo {
		t.Fatalf("severity = %s", finding.Severity)
	}
}

func TestClassifyUnsafeSecretKey(t *testing.T) {
	finding, ok := classifyPacketOutput("key.asc", ":secret key packet:\nskey[0]: [mpi]\n", false)
	if !ok {
		t.Fatal("expected classification")
	}
	if finding.Classification != ClassUnsafeSecret {
		t.Fatalf("classification = %s", finding.Classification)
	}
	if finding.Severity != SeverityUnsafe {
		t.Fatalf("severity = %s", finding.Severity)
	}
}

func TestClassifyEncryptedContainer(t *testing.T) {
	finding, ok := classifyPacketOutput("msg.gpg", ":pubkey enc packet:\n:encrypted data packet:\n", false)
	if !ok {
		t.Fatal("expected classification")
	}
	if finding.Classification != ClassEncrypted {
		t.Fatalf("classification = %s", finding.Classification)
	}
}

func TestClassifyRevocationCertificateFromPacketOutput(t *testing.T) {
	finding, ok := classifyPacketOutput("subject-revoke.asc", ":signature packet: algo 1, keyid ABCD\n\tversion 4, created 0, md5len 0, sigclass 0x20\n", false)
	if !ok {
		t.Fatal("expected classification")
	}
	if finding.Classification != ClassRevocation {
		t.Fatalf("classification = %s", finding.Classification)
	}
	if finding.Severity != SeverityWarn {
		t.Fatalf("severity = %s", finding.Severity)
	}
}

func TestClassifyBufferFindsEmbeddedSSHPublicKey(t *testing.T) {
	artifact, ok := ClassifyBuffer(
		t.Context(),
		"notes.txt",
		[]byte("ordinary note\nssh-ed25519 AAAA operator@example.invalid\n"),
		Config{EnableSSH: true},
	)
	if !ok {
		t.Fatal("expected embedded SSH public key classification")
	}
	finding := artifact.Finding()
	if finding.Code != "SSH-PUBLIC-KEY" {
		t.Fatalf("code = %s", finding.Code)
	}
}

func TestClassifyBufferFindsMalformedEmbeddedSSHPublicKeyShape(t *testing.T) {
	artifact, ok := ClassifyBuffer(
		t.Context(),
		"notes.txt",
		[]byte("ordinary note\nssh-ed25519 AAAA=== operator@example.invalid\n"),
		Config{EnableSSH: true},
	)
	if !ok {
		t.Fatal("expected malformed SSH public key shape classification")
	}
	finding := artifact.Finding()
	if finding.Code != "SSH-PUBLIC-KEY" {
		t.Fatalf("code = %s", finding.Code)
	}
}

func minisignPublicPayloadForTest() []byte {
	payload := append([]byte("Ed"), []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}...)
	return append(payload, make([]byte, 32)...)
}

func TestClassifyMinisignPublicByCompleteFileIgnoresUntrustedComment(t *testing.T) {
	// synthcorpus / ceremony fixtures stamp non-canonical untrusted-comment
	// lines; classification requires a complete public-key file, not the comment.
	body := "untrusted comment: synthcorpus generated-real TEST KEY - DO NOT USE\n" +
		base64.StdEncoding.EncodeToString(minisignPublicPayloadForTest()) + "\n"

	artifact, ok := ClassifyBuffer(
		t.Context(),
		"minisign-plain.pub",
		[]byte(body),
		Config{EnableMinisign: true},
	)
	if !ok {
		t.Fatal("expected minisign public key classification from complete file")
	}
	finding := artifact.Finding()
	if finding.Code != "MINISIGN-PUBLIC-KEY" {
		t.Fatalf("code = %s", finding.Code)
	}
	if finding.Classification != ClassPublic || finding.Retention != RetentionAllowed {
		t.Fatalf("classification/retention = %s/%s", finding.Classification, finding.Retention)
	}
	if artifact.Kind != ArtifactKindMinisign || artifact.Class != ArtifactClassPublic {
		t.Fatalf("kind/class = %s/%s", artifact.Kind, artifact.Class)
	}
}

func TestClassifyMinisignSecretPathWinsOverPublicShapedBlob(t *testing.T) {
	// Valid public-shaped blob under a common secret path must remain secret
	// (fail-closed), including when the historical public comment is present.
	body := "untrusted comment: minisign public key\n" +
		base64.StdEncoding.EncodeToString(minisignPublicPayloadForTest()) + "\n"

	for _, path := range []string{
		"minisign.key",
		"minisign.sec",
		"keys/minisign/operator.key",
	} {
		artifact, ok := ClassifyBuffer(
			t.Context(),
			path,
			[]byte(body),
			Config{EnableMinisign: true},
		)
		if !ok {
			t.Fatalf("%s: expected secret-path classification", path)
		}
		finding := artifact.Finding()
		if finding.Classification != ClassMinisignSecret {
			t.Fatalf("%s: classification = %s code=%s", path, finding.Classification, finding.Code)
		}
		if finding.Code == "MINISIGN-PUBLIC-KEY" || finding.Retention == RetentionAllowed {
			t.Fatalf("%s: must not be public/allowed: %#v", path, finding)
		}
	}
}

func TestClassifyMinisignMixedExtraPayloadNotPublic(t *testing.T) {
	// Extra non-comment payload means the whole file is not a complete public key.
	body := "untrusted comment: synthcorpus generated-real TEST KEY - DO NOT USE\n" +
		base64.StdEncoding.EncodeToString(minisignPublicPayloadForTest()) + "\n" +
		"opaque-extra-payload-line\n"

	_, ok := ClassifyBuffer(
		t.Context(),
		"minisign-plain.pub",
		[]byte(body),
		Config{EnableMinisign: true},
	)
	if ok {
		t.Fatal("mixed extra payload must not classify as complete public key")
	}
}

func TestClassifyMinisignColonBearingExtraPayloadNotPublic(t *testing.T) {
	// Arbitrary colon lines are not minisign untrusted-comment framing.
	body := "untrusted comment: synthcorpus generated-real TEST KEY - DO NOT USE\n" +
		base64.StdEncoding.EncodeToString(minisignPublicPayloadForTest()) + "\n" +
		"opaque: additional non-public material\n"

	artifact, ok := ClassifyBuffer(
		t.Context(),
		"minisign-plain.pub",
		[]byte(body),
		Config{EnableMinisign: true},
	)
	if ok && artifact.Finding().Classification == ClassPublic {
		t.Fatalf("colon-bearing extra payload must not be public/allowed: %#v", artifact.Finding())
	}
	if _, parseOK := ParseMinisignPublicKeyFile([]byte(body)); parseOK {
		t.Fatal("ParseMinisignPublicKeyFile must reject colon-bearing extra payload")
	}
}

func TestParseMinisignPublicKeyFileRejectsOversizedInput(t *testing.T) {
	// Bound is below scan prefixBytes so a truncated large prefix cannot prove
	// whole-file public completeness.
	line := base64.StdEncoding.EncodeToString(minisignPublicPayloadForTest())
	body := "untrusted comment: minisign public key\n" + line + "\n"
	padded := make([]byte, minisignPublicKeyFileMaxBytes)
	copy(padded, body)
	if _, ok := ParseMinisignPublicKeyFile(padded); ok {
		t.Fatal("input at/over max structural size must fail closed")
	}
}

func TestParseMinisignPublicKeyFileRejectsCommentAfterBlob(t *testing.T) {
	line := base64.StdEncoding.EncodeToString(minisignPublicPayloadForTest())
	body := line + "\nuntrusted comment: minisign public key\n"
	if _, ok := ParseMinisignPublicKeyFile([]byte(body)); ok {
		t.Fatal("comment after blob must fail closed")
	}
}

func TestClassifyMinisignPublicMarkerWithoutBlobIsNotAllowed(t *testing.T) {
	body := "untrusted comment: minisign public key\nnot-a-valid-blob\n"
	artifact, ok := ClassifyBuffer(
		t.Context(),
		"broken.pub",
		[]byte(body),
		Config{EnableMinisign: true},
	)
	if !ok {
		t.Fatal("expected malformed public-marker classification")
	}
	finding := artifact.Finding()
	if finding.Code != "MINISIGN-PUBLIC-KEY-MALFORMED" {
		t.Fatalf("code = %s", finding.Code)
	}
	if finding.Classification != ClassParseError || finding.Retention == RetentionAllowed {
		t.Fatalf("expected parse-error non-allowed, got %#v", finding)
	}
	if artifact.Class == ArtifactClassPublic {
		t.Fatalf("artifact class must not be public: %s", artifact.Class)
	}
}

func TestClassifyMinisignDoesNotMatchRandomBase64AsPublic(t *testing.T) {
	// 42 bytes that are not Ed/ED algorithm tags must not classify as minisign.
	payload := make([]byte, 42)
	copy(payload, []byte("XX"))
	body := "untrusted comment: something else entirely\n" +
		base64.StdEncoding.EncodeToString(payload) + "\n"

	_, ok := ClassifyBuffer(
		t.Context(),
		"random.pub",
		[]byte(body),
		Config{EnableMinisign: true},
	)
	if ok {
		t.Fatal("did not expect minisign classification for non-Ed public-sized blob")
	}
}

func TestParseMinisignPublicKeyFileRejectsMultipleBlobs(t *testing.T) {
	line := base64.StdEncoding.EncodeToString(minisignPublicPayloadForTest())
	body := "untrusted comment: minisign public key\n" + line + "\n" + line + "\n"
	if _, ok := ParseMinisignPublicKeyFile([]byte(body)); ok {
		t.Fatal("two public blobs must not parse as a single public-key file")
	}
}
