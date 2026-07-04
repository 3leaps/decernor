package scanner

import "testing"

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
