package fingerprint

import (
	"fmt"
	"strings"
)

const openPGPFingerprintHexLen = 40
const openPGPLongKeyIDHexLen = 16

type openPGPIdentity struct {
	Fingerprint string
	KeyRole     KeyRole
	KeyID       string
}

func parseOpenPGPColonIdentities(output string) ([]openPGPIdentity, error) {
	var (
		pendingRole  KeyRole
		pendingKeyID string
		havePending  bool
		seen         = map[string]bool{}
		out          []openPGPIdentity
	)

	flushMissing := func() error {
		if havePending {
			return fmt.Errorf("openpgp colon: missing fingerprint after %s packet", pendingRole)
		}
		return nil
	}

	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "pub", "sec":
			if err := flushMissing(); err != nil {
				return nil, err
			}
			havePending = true
			pendingRole = KeyRolePrimary
			pendingKeyID = colonKeyID(fields)
		case "sub", "ssb":
			if err := flushMissing(); err != nil {
				return nil, err
			}
			havePending = true
			pendingRole = KeyRoleSubkey
			pendingKeyID = colonKeyID(fields)
		case "fpr":
			if !havePending {
				return nil, fmt.Errorf("openpgp colon: orphan fingerprint record")
			}
			if len(fields) < 10 {
				return nil, fmt.Errorf("openpgp colon: fingerprint record too short")
			}
			value := strings.ToUpper(strings.TrimSpace(fields[9]))
			if !isOpenPGPFingerprint(value) {
				return nil, fmt.Errorf("openpgp colon: fingerprint is not uppercase 40-hex")
			}
			keyID := value[len(value)-openPGPLongKeyIDHexLen:]
			if isOpenPGPLongKeyID(pendingKeyID) && pendingKeyID != keyID {
				return nil, fmt.Errorf("openpgp colon: key id does not match fingerprint")
			}
			if seen[value] {
				return nil, fmt.Errorf("openpgp colon: duplicate identity")
			}
			seen[value] = true
			out = append(out, openPGPIdentity{
				Fingerprint: value,
				KeyRole:     pendingRole,
				KeyID:       keyID,
			})
			havePending = false
			pendingRole = ""
			pendingKeyID = ""
		}
	}
	if err := flushMissing(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("openpgp colon: no identities")
	}
	return out, nil
}

func colonKeyID(fields []string) string {
	if len(fields) < 5 {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(fields[4]))
}

func isOpenPGPLongKeyID(value string) bool {
	if len(value) != openPGPLongKeyIDHexLen {
		return false
	}
	for _, r := range value {
		if !isUpperHexRune(r) {
			return false
		}
	}
	return true
}

func isOpenPGPFingerprint(value string) bool {
	if len(value) != openPGPFingerprintHexLen {
		return false
	}
	for _, r := range value {
		if !isUpperHexRune(r) {
			return false
		}
	}
	return true
}

func isUpperHexRune(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'A' && r <= 'F'
}
