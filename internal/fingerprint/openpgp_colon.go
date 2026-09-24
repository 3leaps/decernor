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
	Secret      bool
	Validity    string
	CreatedRaw  string
	ExpiryRaw   string
}

func parseOpenPGPColonIdentities(output string) ([]openPGPIdentity, error) {
	var (
		pendingRole     KeyRole
		pendingKeyID    string
		pendingSecret   bool
		pendingValidity string
		pendingCreated  string
		pendingExpiry   string
		havePending     bool
		seen            = map[string]bool{}
		out             []openPGPIdentity
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
			pendingSecret = fields[0] == "sec"
			pendingValidity = colonField(fields, 1)
			pendingCreated = colonField(fields, 5)
			pendingExpiry = colonField(fields, 6)
		case "sub", "ssb":
			if err := flushMissing(); err != nil {
				return nil, err
			}
			havePending = true
			pendingRole = KeyRoleSubkey
			pendingKeyID = colonKeyID(fields)
			pendingSecret = fields[0] == "ssb"
			pendingValidity = colonField(fields, 1)
			pendingCreated = colonField(fields, 5)
			pendingExpiry = colonField(fields, 6)
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
			if pendingKeyID != "" && (!isOpenPGPLongKeyID(pendingKeyID) || pendingKeyID != keyID) {
				return nil, fmt.Errorf("openpgp colon: key id is malformed or does not match fingerprint")
			}
			if seen[value] {
				return nil, fmt.Errorf("openpgp colon: duplicate identity")
			}
			seen[value] = true
			out = append(out, openPGPIdentity{
				Fingerprint: value,
				KeyRole:     pendingRole,
				KeyID:       keyID,
				Secret:      pendingSecret,
				Validity:    pendingValidity,
				CreatedRaw:  pendingCreated,
				ExpiryRaw:   pendingExpiry,
			})
			havePending = false
			pendingRole = ""
			pendingKeyID = ""
			pendingSecret = false
			pendingValidity = ""
			pendingCreated = ""
			pendingExpiry = ""
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

func colonField(fields []string, index int) string {
	if len(fields) <= index {
		return ""
	}
	return fields[index]
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
