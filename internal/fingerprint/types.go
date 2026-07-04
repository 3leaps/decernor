package fingerprint

import (
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
	Confidence        scanner.Confidence     `json:"confidence"`
	Reason            scanner.ArtifactReason `json:"reason,omitempty"`
	source            pathSource
}

type Result struct {
	Records []Record
	Empty   bool
}
