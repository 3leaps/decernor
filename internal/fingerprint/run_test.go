package fingerprint

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/3leaps/decernor/internal/scanner"
)

func TestRunFingerprintsSSHPublicKey(t *testing.T) {
	dir := t.TempDir()
	blob := testSSHPublicBlob()
	mustWrite(t, filepath.Join(dir, "id_ed25519.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(blob)+" operator@example.invalid\n")

	result, err := Run(context.Background(), []string{dir}, Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	record := result.Records[0]
	if record.Path != "id_ed25519.pub" {
		t.Fatalf("path = %q", record.Path)
	}
	if record.Kind != scanner.ArtifactKindSSH || record.Class != scanner.ArtifactClassPublic {
		t.Fatalf("kind/class = %s/%s", record.Kind, record.Class)
	}
	if record.Fingerprint == nil || *record.Fingerprint != sshSHA256(blob) {
		t.Fatalf("fingerprint = %#v", record.Fingerprint)
	}
	if strings.Contains(mustJSONLine(t, record), "operator@example.invalid") {
		t.Fatal("record leaked SSH public-key comment")
	}
}

func TestRunDerivesOpenSSHPrivatePublicBlobFingerprint(t *testing.T) {
	dir := t.TempDir()
	blob := testSSHPublicBlob()
	mustWrite(t, filepath.Join(dir, "id_ed25519"), testOpenSSHPrivate(blob, "none"))

	result, err := Run(context.Background(), []string{dir}, Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	record := result.Records[0]
	if record.Fingerprint == nil || *record.Fingerprint != sshSHA256(blob) {
		t.Fatalf("fingerprint = %#v", record.Fingerprint)
	}
	if record.Reason != "" {
		t.Fatalf("reason = %q", record.Reason)
	}
}

func TestRunEncryptedOpenSSHPrivateReturnsNullReason(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "id_ed25519"), testOpenSSHPrivate(testSSHPublicBlob(), "aes256-ctr"))

	result, err := Run(context.Background(), []string{dir}, Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	record := result.Records[0]
	if record.Fingerprint != nil {
		t.Fatalf("fingerprint = %#v", record.Fingerprint)
	}
	if record.Reason != scanner.ArtifactReasonEncryptedPrivateNoPublicCounterpart {
		t.Fatalf("reason = %q", record.Reason)
	}
}

func TestRunFingerprintsMinisignPublicKeyIDAndBlobSHA256(t *testing.T) {
	dir := t.TempDir()
	payload := append([]byte("Ed"), []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}...)
	payload = append(payload, bytes.Repeat([]byte{0x42}, 32)...)
	mustWrite(t, filepath.Join(dir, "minisign.pub"), "untrusted comment: minisign public key\n"+base64.StdEncoding.EncodeToString(payload)+"\n")

	result, err := Run(context.Background(), []string{dir}, Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("records=%#v", result.Records)
	}
	records := recordsByScheme(result.Records)
	keyIDRecord := records[SchemeMinisignKeyID]
	if keyIDRecord.Kind != scanner.ArtifactKindMinisign || keyIDRecord.KeyID != "0123456789ABCDEF" {
		t.Fatalf("key ID record=%#v", keyIDRecord)
	}
	if keyIDRecord.Fingerprint == nil || *keyIDRecord.Fingerprint != "0123456789ABCDEF" {
		t.Fatalf("key ID fingerprint=%#v", keyIDRecord.Fingerprint)
	}
	blobRecord := records[SchemeMinisignPublicBlobSHA256]
	if blobRecord.Kind != scanner.ArtifactKindMinisign || blobRecord.KeyID != "0123456789ABCDEF" {
		t.Fatalf("blob record=%#v", blobRecord)
	}
	if blobRecord.Algorithm != "sha256" || blobRecord.Fingerprint == nil || *blobRecord.Fingerprint != minisignPublicBlobSHA256(payload) {
		t.Fatalf("blob fingerprint record=%#v", blobRecord)
	}
}

func TestRunFingerprintsMinisignPublicWithNonCanonicalUntrustedComment(t *testing.T) {
	// Ceremony/synthcorpus fixtures use editable untrusted-comment stamps that
	// are not the historical "minisign public key" marker. DDR-0001 excludes
	// comment text from the trust surface; blob-sha256 must still emit.
	dir := t.TempDir()
	payload := append([]byte("Ed"), []byte{0x38, 0x46, 0x0d, 0x22, 0xb3, 0x78, 0x01, 0xaa}...)
	payload = append(payload, bytes.Repeat([]byte{0x11}, 32)...)
	mustWrite(t, filepath.Join(dir, "minisign-plain.pub"),
		"untrusted comment: synthcorpus generated-real TEST KEY - DO NOT USE (public plain)\n"+
			base64.StdEncoding.EncodeToString(payload)+"\n")

	result, err := Run(context.Background(), []string{dir}, Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("records=%#v", result.Records)
	}
	records := recordsByScheme(result.Records)
	if _, ok := records[SchemeMinisignKeyID]; !ok {
		t.Fatalf("missing key-id record: %#v", result.Records)
	}
	blobRecord := records[SchemeMinisignPublicBlobSHA256]
	if blobRecord.FingerprintScheme != SchemeMinisignPublicBlobSHA256 {
		t.Fatalf("blob scheme=%q", blobRecord.FingerprintScheme)
	}
	if blobRecord.Fingerprint == nil || *blobRecord.Fingerprint != minisignPublicBlobSHA256(payload) {
		t.Fatalf("blob fingerprint record=%#v", blobRecord)
	}
	if blobRecord.KeyID != "38460D22B37801AA" {
		t.Fatalf("key id = %q", blobRecord.KeyID)
	}
}

func TestRunMinisignMalformedPublicBlobIsNullReason(t *testing.T) {
	dir := t.TempDir()
	// Marker present without a complete public-key structure → not public/allowed;
	// fingerprint emits null with parse-unsupported (no trust-anchor mint).
	malformed := append([]byte("Ed"), bytes.Repeat([]byte{0x42}, 8)...) // 10 bytes, too short
	mustWrite(t, filepath.Join(dir, "minisign.pub"), "untrusted comment: minisign public key\n"+base64.StdEncoding.EncodeToString(malformed)+"\n")

	result, err := Run(context.Background(), []string{dir}, Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	record := result.Records[0]
	if record.Fingerprint != nil {
		t.Fatalf("expected no fingerprint, got %q", *record.Fingerprint)
	}
	if record.Class == scanner.ArtifactClassPublic {
		t.Fatalf("class must not be public: %s", record.Class)
	}
	if record.Reason != scanner.ArtifactReasonParseUnsupported {
		t.Fatalf("reason = %q", record.Reason)
	}
}

func TestRunMinisignMixedExtraPayloadEmitsNoPublicAnchor(t *testing.T) {
	dir := t.TempDir()
	payload := append([]byte("Ed"), []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}...)
	payload = append(payload, bytes.Repeat([]byte{0x42}, 32)...)
	mustWrite(t, filepath.Join(dir, "mixed.pub"),
		"untrusted comment: synthcorpus TEST KEY - DO NOT USE\n"+
			base64.StdEncoding.EncodeToString(payload)+"\n"+
			"opaque-extra-line\n")

	result, err := Run(context.Background(), []string{dir}, Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 0 {
		t.Fatalf("mixed payload must not mint fingerprint records: %#v", result.Records)
	}
}

func TestRunMinisignColonBearingExtraPayloadEmitsNoPublicAnchor(t *testing.T) {
	dir := t.TempDir()
	payload := append([]byte("Ed"), []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}...)
	payload = append(payload, bytes.Repeat([]byte{0x42}, 32)...)
	mustWrite(t, filepath.Join(dir, "mixed-colon.pub"),
		"untrusted comment: synthcorpus TEST KEY - DO NOT USE\n"+
			base64.StdEncoding.EncodeToString(payload)+"\n"+
			"opaque: additional non-public material\n")

	result, err := Run(context.Background(), []string{dir}, Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 0 {
		t.Fatalf("colon-bearing mixed payload must not mint fingerprint records: %#v", result.Records)
	}
}

func TestRunGPGPublicArmorEmitsNullRecordWhenHelperUnavailable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	mustWrite(t, filepath.Join(dir, "release-key.asc"), "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----\n")

	result, err := Run(context.Background(), []string{dir}, Config{
		Kinds: map[scanner.ArtifactKind]bool{scanner.ArtifactKindGPG: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	record := result.Records[0]
	if record.Kind != scanner.ArtifactKindGPG || record.Class != scanner.ArtifactClassPublic {
		t.Fatalf("kind/class = %s/%s", record.Kind, record.Class)
	}
	if record.Fingerprint != nil {
		t.Fatalf("fingerprint = %#v", record.Fingerprint)
	}
	if record.Reason != scanner.ArtifactReasonHelperUnavailable {
		t.Fatalf("reason = %q", record.Reason)
	}
	if record.FingerprintScheme != SchemeGPGOpenPGPFingerprint {
		t.Fatalf("scheme = %q", record.FingerprintScheme)
	}
}

func TestRunGPGRevocationIsUnsupportedKindWithoutHelper(t *testing.T) {
	// DDR-0001: revocation certificates are class other with unsupported-kind.
	// A present gpg must not re-label them helper-unavailable.
	dir := t.TempDir()
	// Filename + public armor header is enough for the classifier path;
	// content need not be a cryptographically valid rev cert.
	mustWrite(t, filepath.Join(dir, "revocation.asc"), "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-revocation\n-----END PGP PUBLIC KEY BLOCK-----\n")

	result, err := Run(context.Background(), []string{dir}, Config{
		Kinds: map[scanner.ArtifactKind]bool{scanner.ArtifactKindGPG: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	record := result.Records[0]
	if record.Kind != scanner.ArtifactKindGPG || record.Class != scanner.ArtifactClassOther {
		t.Fatalf("kind/class = %s/%s", record.Kind, record.Class)
	}
	if record.Fingerprint != nil {
		t.Fatalf("fingerprint = %#v", record.Fingerprint)
	}
	if record.Reason != scanner.ArtifactReasonUnsupportedKind {
		t.Fatalf("reason = %q (want unsupported-kind)", record.Reason)
	}
	if record.FingerprintScheme != SchemeGPGOpenPGPFingerprint {
		t.Fatalf("scheme = %q", record.FingerprintScheme)
	}
}

func TestRunGPGMalformedPublicIsParseUnsupportedWhenHelperPresent(t *testing.T) {
	// When gpg is on PATH but rejects the material, reason is parse-unsupported
	// (not helper-unavailable). Skip if this host has no gpg.
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not available")
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "release-key.asc"), "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnot-a-real-key\n-----END PGP PUBLIC KEY BLOCK-----\n")

	result, err := Run(context.Background(), []string{dir}, Config{
		Kinds: map[scanner.ArtifactKind]bool{scanner.ArtifactKindGPG: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	record := result.Records[0]
	if record.Class != scanner.ArtifactClassPublic {
		t.Fatalf("class = %s", record.Class)
	}
	if record.Fingerprint != nil {
		t.Fatalf("fingerprint = %#v", record.Fingerprint)
	}
	if record.Reason != scanner.ArtifactReasonParseUnsupported {
		t.Fatalf("reason = %q (want parse-unsupported)", record.Reason)
	}
}

func TestRunGPGNonExecutableHelperIsHelperUnavailable(t *testing.T) {
	// LookPath succeeds for an executable-bit file that is not a valid OS
	// image; the helper never starts, so reason must be helper-unavailable.
	if runtime.GOOS == "windows" {
		t.Skip("invalid-image exec failure shape differs on Windows")
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "gpg")
	mustWrite(t, helper, "not-a-valid-gpg-binary\n")
	if err := os.Chmod(helper, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	mustWrite(t, filepath.Join(dir, "release-key.asc"), "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----\n")

	result, err := Run(context.Background(), []string{dir}, Config{
		Kinds: map[scanner.ArtifactKind]bool{scanner.ArtifactKindGPG: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	record := result.Records[0]
	if record.Class != scanner.ArtifactClassPublic {
		t.Fatalf("class = %s", record.Class)
	}
	if record.Fingerprint != nil {
		t.Fatalf("fingerprint = %#v", record.Fingerprint)
	}
	if record.Reason != scanner.ArtifactReasonHelperUnavailable {
		t.Fatalf("reason = %q (want helper-unavailable)", record.Reason)
	}
}

func TestRunFiltersByKind(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "id_ed25519.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testSSHPublicBlob())+"\n")
	mustWrite(t, filepath.Join(dir, "minisign.pub"), "untrusted comment: minisign public key\n"+base64.StdEncoding.EncodeToString(append([]byte("Ed12345678"), bytes.Repeat([]byte{0x42}, 32)...))+"\n")

	result, err := Run(context.Background(), []string{dir}, Config{Kinds: map[scanner.ArtifactKind]bool{scanner.ArtifactKindMinisign: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("records=%#v", result.Records)
	}
	for _, record := range result.Records {
		if record.Kind != scanner.ArtifactKindMinisign {
			t.Fatalf("record kind = %s", record.Kind)
		}
	}
}

func TestRunOversizedNonKeyDoesNotBypassKindClassFilters(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "large.txt"), "not key material\n")

	var diagnostics bytes.Buffer
	result, err := Run(context.Background(), []string{dir}, Config{
		MaxFileSize: 1,
		Kinds:       map[scanner.ArtifactKind]bool{scanner.ArtifactKindSSH: true},
		Classes:     map[scanner.ArtifactClass]bool{scanner.ArtifactClassPublic: true},
	}, &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Empty || len(result.Records) != 0 {
		t.Fatalf("result=%#v", result)
	}
	if !strings.Contains(diagnostics.String(), string(scanner.ArtifactReasonTooLarge)) {
		t.Fatalf("diagnostics = %q", diagnostics.String())
	}
	if strings.Contains(diagnostics.String(), dir) {
		t.Fatalf("diagnostics leaked absolute temp path: %q", diagnostics.String())
	}
}

func TestRunOversizedKeyDoesNotBypassClassFilter(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "id_ed25519.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testSSHPublicBlob())+"\n")

	result, err := Run(context.Background(), []string{dir}, Config{
		MaxFileSize: 1,
		Kinds:       map[scanner.ArtifactKind]bool{scanner.ArtifactKindSSH: true},
		Classes:     map[scanner.ArtifactClass]bool{scanner.ArtifactClassPrivate: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Empty || len(result.Records) != 0 {
		t.Fatalf("result=%#v", result)
	}
}

func TestRunUnreadableDiagnosticUsesPathPrivacy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions vary on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.pub")
	mustWrite(t, path, "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testSSHPublicBlob())+"\n")
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chmod(path, 0600)
	}()
	// Root (common in CI containers) ignores mode bits and can still read the
	// file; the unreadable path is not exercisable under those privileges.
	if f, err := os.Open(path); err == nil {
		_ = f.Close()
		t.Skip("process can still read mode-0000 file (e.g. root in CI)")
	}

	var diagnostics bytes.Buffer
	result, err := Run(context.Background(), []string{dir}, Config{PathMode: PathModeHash}, &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Empty || len(result.Records) != 0 {
		t.Fatalf("result=%#v", result)
	}
	if !strings.Contains(diagnostics.String(), string(scanner.ArtifactReasonUnreadable)) {
		t.Fatalf("diagnostics = %q", diagnostics.String())
	}
	if strings.Contains(diagnostics.String(), dir) || strings.Contains(diagnostics.String(), "secret.pub") {
		t.Fatalf("diagnostics leaked local path metadata: %q", diagnostics.String())
	}
}

func TestRunReportsWalkSymlinkToDiagnosticsOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "id_ed25519.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testSSHPublicBlob())+"\n")
	if err := os.Symlink(filepath.Join(dir, "id_ed25519.pub"), filepath.Join(dir, "link.pub")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	var diagnostics bytes.Buffer
	result, err := Run(context.Background(), []string{dir}, Config{}, &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	if !strings.Contains(diagnostics.String(), "symlink-not-traversed") {
		t.Fatalf("diagnostics = %q", diagnostics.String())
	}
	if strings.Contains(diagnostics.String(), dir) {
		t.Fatalf("diagnostics leaked absolute temp path: %q", diagnostics.String())
	}
}

func TestRunDefaultPathModeUsesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "detail", "red", "secretfile.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testSSHPublicBlob())+"\n")
	mustWrite(t, filepath.Join(dir, "detail", "blue", "secretfile.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testSSHPublicBlob())+"\n")

	result, err := Run(context.Background(), []string{dir}, Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]bool{}
	for _, record := range result.Records {
		values[record.Path] = true
	}
	if !values["detail/red/secretfile.pub"] || !values["detail/blue/secretfile.pub"] {
		t.Fatalf("path values = %#v", values)
	}
}

func TestRunNonePathModeOmitsPath(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "nested", "id_ed25519.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testSSHPublicBlob())+"\n")

	result, err := Run(context.Background(), []string{dir}, Config{PathMode: PathModeNone}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 {
		t.Fatalf("records=%#v", result.Records)
	}
	if result.Records[0].Path != "" {
		t.Fatalf("path = %q", result.Records[0].Path)
	}
	if strings.Contains(mustJSONLine(t, result.Records[0]), "id_ed25519") {
		t.Fatal("none path mode leaked path-like value")
	}
	if strings.Contains(mustJSONLine(t, result.Records[0]), `"path"`) {
		t.Fatal("none path mode emitted path field")
	}
}

func TestRunHashPathModeIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "nested", "id_ed25519.pub"), "ssh-ed25519 "+base64.StdEncoding.EncodeToString(testSSHPublicBlob())+"\n")

	first, err := Run(context.Background(), []string{dir}, Config{PathMode: PathModeHash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(context.Background(), []string{dir}, Config{PathMode: PathModeHash}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Records) != 1 || len(second.Records) != 1 {
		t.Fatalf("first=%#v second=%#v", first.Records, second.Records)
	}
	a := first.Records[0].Path
	b := second.Records[0].Path
	if a == "" || a != b || strings.Contains(a, "id_ed25519") {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func testSSHPublicBlob() []byte {
	var out []byte
	out = appendSSHString(out, []byte("ssh-ed25519"))
	out = appendSSHString(out, bytes.Repeat([]byte{0x11}, 32))
	return out
}

func testOpenSSHPrivate(publicBlob []byte, cipher string) string {
	var payload []byte
	payload = append(payload, []byte("openssh-key-v1\x00")...)
	payload = appendSSHString(payload, []byte(cipher))
	payload = appendSSHString(payload, []byte("none"))
	payload = appendSSHString(payload, nil)
	payload = appendUint32(payload, 1)
	payload = appendSSHString(payload, publicBlob)
	payload = appendSSHString(payload, []byte("synthetic-private-section"))
	encoded := base64.StdEncoding.EncodeToString(payload)
	return "-----" + strings.Join([]string{"BEGIN", "OPENSSH", "PRIVATE", "KEY"}, " ") + "-----\n" + encoded + "\n-----" + strings.Join([]string{"END", "OPENSSH", "PRIVATE", "KEY"}, " ") + "-----\n"
}

func appendSSHString(out []byte, value []byte) []byte {
	out = appendUint32(out, uint32(len(value)))
	return append(out, value...)
}

func appendUint32(out []byte, value uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return append(out, raw[:]...)
}

func mustWrite(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func mustJSONLine(t *testing.T, record Record) string {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func recordsByScheme(records []Record) map[Scheme]Record {
	out := map[Scheme]Record{}
	for _, record := range records {
		out[record.FingerprintScheme] = record
	}
	return out
}
