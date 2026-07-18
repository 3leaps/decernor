package scanner

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"path/filepath"
	"strings"
)

func classifyPacketOutput(path string, packets string, allowProtected bool) (Finding, bool) {
	artifact, ok := classifyPacketArtifact(path, packets, allowProtected)
	if !ok {
		return Finding{}, false
	}
	return artifact.Finding(), true
}

func classifyPacketArtifact(path string, packets string, allowProtected bool) (Artifact, bool) {
	lower := strings.ToLower(packets)

	if containsAny(lower, packetRevocationIndicators) ||
		strings.Contains(lower, ":signature packet:") && strings.Contains(lower, "sigclass 0x20") {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-REVOCATION-CERT",
			Priority:       PriorityP3,
			Classification: ClassRevocation,
			Severity:       SeverityWarn,
			Retention:      RetentionRetainControlled,
			Exposure:       ExposureSensitive,
			Confidence:     ConfidenceHigh,
			Evidence:       "OpenPGP revocation certificate material detected",
			Recommendation: "Treat as sensitive operational material; store only where revocation authority is intended.",
		})
	}

	if containsAny(lower, packetSecretIndicators) {
		protected := strings.Contains(packets, protectedPacketMarker) && strings.Contains(lower, packetProtectionIndicators[1])
		if protected {
			severity := SeverityWarn
			if allowProtected {
				severity = SeverityInfo
			}
			return mustArtifact(Finding{
				Path:           path,
				Code:           "GPG-PROTECTED-SECRET",
				Priority:       PriorityP3,
				Classification: ClassProtectedSecret,
				Severity:       severity,
				Retention:      RetentionRetainControlled,
				Exposure:       ExposureSecret,
				Confidence:     ConfidenceHigh,
				Evidence:       "OpenPGP secret key packets are passphrase-protected",
				Recommendation: "Potentially retainable for local signing with strong passphrase and disk protections; prefer hardware-backed keys when policy requires them.",
			})
		}
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-UNPROTECTED-SECRET",
			Priority:       PriorityP0,
			Classification: ClassUnsafeSecret,
			Severity:       SeverityUnsafe,
			Retention:      RetentionRemove,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceHigh,
			Evidence:       "OpenPGP secret key packets lack expected protection metadata",
			Recommendation: "Remove the file or re-export the secret key with a passphrase.",
		})
	}

	if containsAny(lower, packetEncryptedIndicators) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-ENCRYPTED-CONTAINER",
			Priority:       PriorityP5,
			Classification: ClassEncrypted,
			Severity:       SeverityInfo,
			Retention:      RetentionAllowed,
			Exposure:       ExposureSensitive,
			Confidence:     ConfidenceHigh,
			Evidence:       "OpenPGP encrypted container packets detected",
			Recommendation: "No action required unless encrypted containers are disallowed by local policy.",
		})
	}

	if containsAny(lower, packetPublicIndicators) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-PUBLIC-MATERIAL",
			Priority:       PriorityP5,
			Classification: ClassPublic,
			Severity:       SeverityInfo,
			Retention:      RetentionAllowed,
			Exposure:       ExposurePublic,
			Confidence:     ConfidenceHigh,
			Evidence:       "OpenPGP public material detected",
			Recommendation: "No action required.",
		})
	}

	return Artifact{}, false
}

func classifyHeaderArtifact(path string, prefix []byte, cfg Config) (Artifact, bool) {
	if cfg.EnableGPG && isRevocationPath(path) && containsASCII(prefix, pgpPublicHeader()) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-REVOCATION-CERT",
			Priority:       PriorityP3,
			Classification: ClassRevocation,
			Severity:       SeverityWarn,
			Retention:      RetentionRetainControlled,
			Exposure:       ExposureSensitive,
			Confidence:     ConfidenceMedium,
			Evidence:       "OpenPGP revocation certificate filename and public armor detected",
			Recommendation: "Treat as sensitive operational material; store only where revocation authority is intended.",
		})
	}

	if cfg.EnableGPG && containsASCII(prefix, pgpPrivateHeader()) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-PRIVATE-ARMOR-UNVERIFIED",
			Priority:       PriorityP1,
			Classification: ClassParseError,
			Severity:       SeverityUnsafe,
			Retention:      RetentionInspectManually,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceMedium,
			Evidence:       "OpenPGP private-key armor detected but packet parsing did not confirm protection",
			Recommendation: "Inspect with gpg --batch --list-packets and remove or re-export if unprotected.",
		})
	}

	if cfg.EnableGPG && containsASCII(prefix, pgpPublicHeader()) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-PUBLIC-MATERIAL",
			Priority:       PriorityP5,
			Classification: ClassPublic,
			Severity:       SeverityInfo,
			Retention:      RetentionAllowed,
			Exposure:       ExposurePublic,
			Confidence:     ConfidenceMedium,
			Evidence:       "OpenPGP public armor detected",
			Recommendation: "No action required.",
		})
	}

	if cfg.EnableSSH {
		if artifact, ok := classifySSHHeaderArtifact(path, prefix); ok {
			return artifact, true
		}
	}

	if cfg.EnableMinisign {
		if artifact, ok := classifyMinisignArtifact(path, prefix); ok {
			return artifact, true
		}
	}

	if cfg.EnableSSH {
		for _, header := range genericPrivateHeaders() {
			if containsASCII(prefix, header) {
				return mustArtifact(Finding{
					Path:           path,
					Code:           "PEM-UNPROTECTED-PRIVATE-KEY",
					Priority:       PriorityP1,
					Classification: ClassPrivateKey,
					Severity:       SeverityUnsafe,
					Retention:      RetentionRemove,
					Exposure:       ExposureSecret,
					Confidence:     ConfidenceHigh,
					Evidence:       "private-key header detected",
					Recommendation: "Remove the file or store it only in an approved secret store.",
				})
			}
		}
	}

	return Artifact{}, false
}

func classifySSHHeaderArtifact(path string, prefix []byte) (Artifact, bool) {
	if containsASCII(prefix, sshPrivateHeader()) {
		cipher, cipherOK := openSSHCipherName(prefix)
		if cipherOK && cipher == "none" {
			return mustArtifact(Finding{
				Path:           path,
				Code:           "SSH-UNPROTECTED-PRIVATE-KEY",
				Priority:       PriorityP0,
				Classification: ClassSSHPrivateKey,
				Severity:       SeverityUnsafe,
				Retention:      RetentionRemove,
				Exposure:       ExposureSecret,
				Confidence:     ConfidenceHigh,
				Evidence:       "OpenSSH private key is not encrypted",
				Recommendation: "Add a passphrase with ssh-keygen -p -f PATH or replace with a hardware-backed key.",
			})
		}
		if cipherOK {
			return mustArtifact(Finding{
				Path:           path,
				Code:           "SSH-ENCRYPTED-PRIVATE-KEY",
				Priority:       PriorityP3,
				Classification: ClassSSHPrivateKey,
				Severity:       SeverityWarn,
				Retention:      RetentionRetainControlled,
				Exposure:       ExposureSecret,
				Confidence:     ConfidenceHigh,
				Evidence:       "OpenSSH private key is encrypted with cipher " + cipher,
				Recommendation: "Potentially retainable with strong passphrase and local controls; prefer hardware-backed keys when policy requires them.",
			})
		}
		return mustArtifact(Finding{
			Path:           path,
			Code:           "SSH-PRIVATE-KEY-UNVERIFIED",
			Priority:       PriorityP2,
			Classification: ClassSSHPrivateKey,
			Severity:       SeverityWarn,
			Retention:      RetentionRetainControlled,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceMedium,
			Evidence:       "OpenSSH private-key header detected; passphrase status requires ssh-keygen inspection",
			Recommendation: "Verify encryption with ssh-keygen -y -f PATH; retain only with strong passphrase or hardware-backed/private key policy controls.",
		})
	}

	if containsASCII(prefix, encryptedPrivateHeader()) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "PEM-ENCRYPTED-PRIVATE-KEY",
			Priority:       PriorityP3,
			Classification: ClassPrivateKey,
			Severity:       SeverityWarn,
			Retention:      RetentionRetainControlled,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceHigh,
			Evidence:       "encrypted PEM private-key header detected",
			Recommendation: "Use format-specific tooling such as openssl pkey -in PATH -noout to verify access; retain only when policy permits passphrase-protected software keys.",
		})
	}

	if looksSSHPublicKey(prefix) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "SSH-PUBLIC-KEY",
			Priority:       PriorityP5,
			Classification: ClassPublic,
			Severity:       SeverityInfo,
			Retention:      RetentionAllowed,
			Exposure:       ExposurePublic,
			Confidence:     ConfidenceHigh,
			Evidence:       "SSH public key material detected",
			Recommendation: "No action required.",
		})
	}

	return Artifact{}, false
}

func openSSHCipherName(prefix []byte) (string, bool) {
	text := string(prefix)
	begin := "-----" + sshPrivateHeader() + "-----"
	end := "-----" + joinWords("END", "OPENSSH", "PRIVATE", "KEY") + "-----"
	start := strings.Index(text, begin)
	stop := strings.Index(text, end)
	if start < 0 || stop <= start {
		return "", false
	}
	body := text[start+len(begin) : stop]
	var encoded strings.Builder
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, ":") {
			continue
		}
		encoded.WriteString(line)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return "", false
	}
	if !bytes.HasPrefix(decoded, []byte(openSSHMagic)) {
		return "", false
	}
	rest := decoded[len(openSSHMagic):]
	if len(rest) < 4 {
		return "", false
	}
	n := int(binary.BigEndian.Uint32(rest[:4]))
	rest = rest[4:]
	if n < 0 || len(rest) < n {
		return "", false
	}
	return string(rest[:n]), true
}

func looksSSHPublicKey(prefix []byte) bool {
	line := firstNonEmptyLine(string(prefix))
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	if !strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa-") && fields[0] != "sk-ssh-ed25519@openssh.com" && fields[0] != "sk-ecdsa-sha2-nistp256@openssh.com" {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	return err == nil && len(decoded) > 0
}

func classifyEmbeddedSSHPublicKey(path string, data []byte) (Artifact, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		if !looksSSHPublicKeyLineShape(line) {
			continue
		}
		return mustArtifact(Finding{
			Path:           path,
			Code:           "SSH-PUBLIC-KEY",
			Priority:       PriorityP5,
			Classification: ClassPublic,
			Severity:       SeverityInfo,
			Retention:      RetentionAllowed,
			Exposure:       ExposurePublic,
			Confidence:     ConfidenceHigh,
			Evidence:       "SSH public key material detected",
			Recommendation: "No action required.",
		})
	}
	return Artifact{}, false
}

func looksSSHPublicKeyLineShape(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	if !strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa-") && fields[0] != "sk-ssh-ed25519@openssh.com" && fields[0] != "sk-ecdsa-sha2-nistp256@openssh.com" {
		return false
	}
	if len(fields[1]) < 4 {
		return false
	}
	for _, r := range fields[1] {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=' {
			continue
		}
		return false
	}
	return true
}

func firstNonEmptyLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func classifyMinisignArtifact(path string, prefix []byte) (Artifact, bool) {
	lowerName := strings.ToLower(filepath.Base(path))
	lowerPrefix := strings.ToLower(string(prefix))
	if strings.HasSuffix(lowerName, ".minisig") {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "MINISIGN-SIGNATURE",
			Priority:       PriorityP5,
			Classification: ClassPublic,
			Severity:       SeverityInfo,
			Retention:      RetentionAllowed,
			Exposure:       ExposurePublic,
			Confidence:     ConfidenceHigh,
			Evidence:       "minisign signature file detected",
			Recommendation: "No action required.",
		})
	}
	// All secret signals win before any public classification so mixed or
	// misnamed material is never stamped public/allowed.
	if strings.Contains(lowerPrefix, minisignEncryptedSecretMarker()) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "MINISIGN-ENCRYPTED-SECRET",
			Priority:       PriorityP3,
			Classification: ClassMinisignSecret,
			Severity:       SeverityWarn,
			Retention:      RetentionRetainControlled,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceHigh,
			Evidence:       "encrypted minisign secret material detected",
			Recommendation: "Potentially retainable with strong passphrase and local controls; keep out of artifact bundles unless policy allows it.",
		})
	}
	if strings.Contains(lowerPrefix, minisignSecretMarker()) || isMinisignExplicitSecretFilename(lowerName) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "MINISIGN-POSSIBLE-UNPROTECTED-SECRET",
			Priority:       PriorityP1,
			Classification: ClassMinisignSecret,
			Severity:       SeverityUnsafe,
			Retention:      RetentionRemove,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceMedium,
			Evidence:       "possible unprotected minisign secret material detected",
			Recommendation: "Remove the file or regenerate/export the minisign signing secret with passphrase protection.",
		})
	}
	if isMinisignSecretPath(path) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "MINISIGN-SECRET-FILE",
			Priority:       PriorityP2,
			Classification: ClassMinisignSecret,
			Severity:       SeverityWarn,
			Retention:      RetentionInspectManually,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceMedium,
			Evidence:       "file path matches common minisign secret-key location or name",
			Recommendation: "Verify this is the intended minisign signing secret and that it is encrypted before retaining it.",
		})
	}
	// Public key: require a complete public-key file structure. Untrusted-comment
	// text is editable (DDR-0001) and is not a trust signal; only the single
	// canonical 42-byte Ed25519 public blob payload is.
	if _, ok := ParseMinisignPublicKeyFile(prefix); ok {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "MINISIGN-PUBLIC-KEY",
			Priority:       PriorityP5,
			Classification: ClassPublic,
			Severity:       SeverityInfo,
			Retention:      RetentionAllowed,
			Exposure:       ExposurePublic,
			Confidence:     ConfidenceHigh,
			Evidence:       "minisign public key material detected",
			Recommendation: "No action required.",
		})
	}
	// Historical comment marker without a complete public-key structure is not
	// high-confidence public/allowed material.
	if strings.Contains(lowerPrefix, minisignPublicMarker()) {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "MINISIGN-PUBLIC-KEY-MALFORMED",
			Priority:       PriorityP3,
			Classification: ClassParseError,
			Severity:       SeverityWarn,
			Retention:      RetentionInspectManually,
			Exposure:       ExposureUnknown,
			Confidence:     ConfidenceLow,
			Evidence:       "minisign public-key comment marker present without a complete public-key file structure",
			Recommendation: "Inspect the file; a valid minisign public key is one untrusted-comment framing plus a single 42-byte Ed25519 public blob line.",
		})
	}
	return Artifact{}, false
}

// minisignPublicBlobLen is the byte length of a minisign Ed25519 public-key
// blob: 2-byte algorithm tag + 8-byte key ID + 32-byte public key.
const minisignPublicBlobLen = 2 + 8 + 32

// minisignPublicKeyFileMaxBytes bounds complete public-key files well above a
// real minisign .pub (~100B) and strictly below scan prefixBytes (32 KiB). Any
// candidate at or above this size fails closed so a truncated scan prefix
// cannot prove whole-file public/allowed completeness.
const minisignPublicKeyFileMaxBytes = 4 * 1024

// minisignUntrustedCommentPrefix is the only permitted framing line on a
// complete minisign public-key file (minisign grammar). Arbitrary colon-bearing
// lines are not comments for structural purposes.
const minisignUntrustedCommentPrefix = "untrusted comment:"

// ParseMinisignPublicKeyFile reports whether data is a complete minisign
// public-key file and returns its public blob. A complete file has:
//   - total size strictly under minisignPublicKeyFileMaxBytes
//   - zero or more empty lines
//   - at most one line whose trimmed form begins with "untrusted comment:"
//     (must appear before the blob when present)
//   - exactly one payload line that base64-decodes to a canonical 42-byte
//     Ed/ED public-key blob
//
// Any other non-empty line (including arbitrary "key: value" payloads) fails
// closed. Shared by scan classification and fingerprint extraction.
func ParseMinisignPublicKeyFile(data []byte) ([]byte, bool) {
	if len(data) == 0 || len(data) >= minisignPublicKeyFileMaxBytes {
		return nil, false
	}
	var blob []byte
	foundBlob := false
	foundComment := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if isMinisignUntrustedCommentLine(line) {
			if foundBlob || foundComment {
				// Comment after blob, or more than one comment, is not a
				// single public-key file.
				return nil, false
			}
			foundComment = true
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(line)
		if err != nil || !validMinisignPublicKeyBlob(decoded) {
			return nil, false
		}
		if foundBlob {
			return nil, false
		}
		blob = decoded
		foundBlob = true
	}
	if !foundBlob {
		return nil, false
	}
	return blob, true
}

func isMinisignUntrustedCommentLine(line string) bool {
	return strings.HasPrefix(strings.ToLower(line), minisignUntrustedCommentPrefix)
}

func validMinisignPublicKeyBlob(blob []byte) bool {
	if len(blob) != minisignPublicBlobLen {
		return false
	}
	switch string(blob[:2]) {
	case "Ed", "ED":
		return true
	default:
		return false
	}
}

func isMinisignSecretPath(path string) bool {
	clean := filepath.ToSlash(strings.ToLower(path))
	base := filepath.Base(clean)
	if _, ok := minisignSecretFilenames[base]; ok {
		return true
	}
	if strings.Contains(clean, "/minisign/") && strings.HasSuffix(base, ".key") {
		return true
	}
	return false
}

func isMinisignExplicitSecretFilename(base string) bool {
	return strings.HasSuffix(base, ".minisign.key") || strings.HasSuffix(base, ".minisign.secret")
}

func looksOpenPGP(path string, prefix []byte) bool {
	if containsASCII(prefix, pgpArmorPrefix()) {
		return true
	}
	if _, ok := openPGPExtensions[strings.ToLower(filepath.Ext(path))]; ok {
		return true
	}
	return false
}

func isRevocationPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.Contains(base, "revoke") || strings.Contains(base, "revocation")
}

func containsASCII(haystack []byte, needle string) bool {
	return bytes.Contains(bytes.ToUpper(haystack), []byte(strings.ToUpper(needle)))
}

func containsAny(haystack string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

func keyringInternalArtifact(path string, isDir bool) (Artifact, bool) {
	name := filepath.Base(path)
	if _, ok := keyringInternalDirs[name]; isDir && ok {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-KEYRING-INTERNAL-DIR",
			Priority:       PriorityP1,
			Classification: ClassKeyringInternal,
			Severity:       SeverityUnsafe,
			Retention:      RetentionRemove,
			Exposure:       ExposureSecret,
			Confidence:     ConfidenceHigh,
			Evidence:       "GPG keyring internal directory detected",
			Recommendation: "Do not ship copied keyring internals; export only approved artifacts.",
		})
	}

	if _, ok := keyringInternalFiles[name]; ok {
		return mustArtifact(Finding{
			Path:           path,
			Code:           "GPG-KEYRING-INTERNAL-FILE",
			Priority:       PriorityP2,
			Classification: ClassKeyringInternal,
			Severity:       SeverityUnsafe,
			Retention:      RetentionRemove,
			Exposure:       ExposureSensitive,
			Confidence:     ConfidenceHigh,
			Evidence:       "GPG keyring internal file detected",
			Recommendation: "Remove copied keyring internals from the artifact folder.",
		})
	}
	return Artifact{}, false
}

func mustArtifact(f Finding) (Artifact, bool) {
	artifact, ok := artifactFromFinding(withDefaults(f))
	if !ok {
		return Artifact{}, false
	}
	return artifact, true
}
