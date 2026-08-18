package fingerprint

import (
	"errors"
	"time"

	"github.com/3leaps/decernor/internal/scanner"
)

const SchemaVersion = "v0"

type Scheme string

const (
	SchemeGPGOpenPGPFingerprint    Scheme = "openpgp-fingerprint-v1"
	SchemeMinisignKeyID            Scheme = "minisign-key-id-v1"
	SchemeMinisignPublicBlobSHA256 Scheme = "minisign-public-blob-sha256-v1"
	SchemeSSHPublicBlobSHA256      Scheme = "ssh-rfc4253-public-blob-sha256-v1"
)

type PathMode string

const (
	PathModeHash     PathMode = "hash"
	PathModeNone     PathMode = "none"
	PathModeRelative PathMode = "relative"
)

type KeyRole string

const (
	KeyRolePrimary KeyRole = "primary"
	KeyRoleSubkey  KeyRole = "subkey"
)

// SelectionError is a contract-token refusal: no unique selectable value.
// The CLI maps it to exit 3 and must not emit a stdout artifact.
type SelectionError struct {
	Detail string
}

func (e *SelectionError) Error() string {
	if e == nil || e.Detail == "" {
		return "fingerprint selection refused"
	}
	return e.Detail
}

func IsSelectionError(err error) bool {
	var sel *SelectionError
	return errors.As(err, &sel)
}

type pathSource struct {
	InputIndex int
	RelPath    string
	Basename   string
	Hash       string
}

type Config struct {
	MaxFileSize int64
	Include     []string
	Exclude     []string
	Kinds       map[scanner.ArtifactKind]bool
	Classes     map[scanner.ArtifactClass]bool
	PathMode    PathMode
	FailOnEmpty bool
	GPGRole     KeyRole
	GPGTimeout  time.Duration
	EnableGPG   bool
	EnableSSH   bool
	EnableMini  bool
}

type Record struct {
	SchemaVersion     string                 `json:"schema_version"`
	Path              string                 `json:"path,omitempty"`
	Kind              scanner.ArtifactKind   `json:"kind"`
	Class             scanner.ArtifactClass  `json:"class"`
	Algorithm         string                 `json:"algorithm"`
	Fingerprint       *string                `json:"fingerprint"`
	FingerprintScheme Scheme                 `json:"fingerprint_scheme"`
	KeyID             string                 `json:"key_id,omitempty"`
	KeyRole           KeyRole                `json:"key_role,omitempty"`
	Confidence        scanner.Confidence     `json:"confidence"`
	Reason            scanner.ArtifactReason `json:"reason,omitempty"`
	source            pathSource
}

type Result struct {
	Records []Record
	Empty   bool
}
