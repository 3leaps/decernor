package scanner

import "strings"

// Detection corpus constants live in this file so reviewers can audit scanner
// search material separately from classification policy.
const (
	protectedPacketMarker = "[v4 protected]"
	openSSHMagic          = "openssh-key-v1\x00"
)

var (
	packetRevocationIndicators = []string{
		"reason for revocation",
		"revocation key packet",
	}
	packetSecretIndicators = []string{
		":secret key packet:",
		":secret sub key packet:",
	}
	packetProtectionIndicators = []string{
		protectedPacketMarker,
		"protect algo:",
	}
	packetEncryptedIndicators = []string{
		":symkey enc packet:",
		":pubkey enc packet:",
		":encrypted data packet:",
		":encrypted packet:",
	}
	packetPublicIndicators = []string{
		":public key packet:",
		":signature packet:",
	}
	openPGPExtensions = map[string]struct{}{
		".asc": {},
		".gpg": {},
		".pgp": {},
		".sig": {},
	}
	keyringInternalDirs = map[string]struct{}{
		".gnupg":            {},
		"private-keys-v1.d": {},
	}
	keyringInternalFiles = map[string]struct{}{
		"secring.gpg":    {},
		"pubring.kbx":    {},
		"trustdb.gpg":    {},
		"gpg-agent.conf": {},
	}
	minisignSecretFilenames = map[string]struct{}{
		"minisign.key": {},
		"minisign.sec": {},
	}
)

func pgpPrivateHeader() string {
	return joinWords("BEGIN", "PGP", "PRIVATE", "KEY", "BLOCK")
}

func pgpPublicHeader() string {
	return joinWords("BEGIN", "PGP", "PUBLIC", "KEY", "BLOCK")
}

func sshPrivateHeader() string {
	return joinWords("BEGIN", "OPENSSH", "PRIVATE", "KEY")
}

func encryptedPrivateHeader() string {
	return joinWords("BEGIN", "ENCRYPTED", "PRIVATE", "KEY")
}

func genericPrivateHeaders() []string {
	return []string{
		joinWords("BEGIN", "RSA", "PRIVATE", "KEY"),
		joinWords("BEGIN", "EC", "PRIVATE", "KEY"),
		joinWords("BEGIN", "DSA", "PRIVATE", "KEY"),
		joinWords("BEGIN", "PRIVATE", "KEY"),
	}
}

func pgpArmorPrefix() string {
	return joinWords("BEGIN", "PGP")
}

func minisignEncryptedSecretMarker() string {
	return joinWords("minisign", "encrypted", "secret", "key")
}

func minisignPublicMarker() string {
	return joinWords("minisign", "public", "key")
}

func minisignSecretMarker() string {
	return joinWords("minisign", "secret", "key")
}

func joinWords(words ...string) string {
	return strings.Join(words, " ")
}
