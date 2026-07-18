package scanner

type ArtifactKind string

const (
	ArtifactKindGPG      ArtifactKind = "gpg"
	ArtifactKindSSH      ArtifactKind = "ssh"
	ArtifactKindMinisign ArtifactKind = "minisign"
)

type ArtifactClass string

const (
	ArtifactClassPublic  ArtifactClass = "public"
	ArtifactClassPrivate ArtifactClass = "private"
	ArtifactClassOther   ArtifactClass = "other"
)

type ArtifactReason string

const (
	ArtifactReasonEncryptedPrivateNoPublicCounterpart ArtifactReason = "encrypted-private-no-public-counterpart"
	ArtifactReasonHelperUnavailable                   ArtifactReason = "helper-unavailable"
	ArtifactReasonParseUnsupported                    ArtifactReason = "parse-unsupported"
	ArtifactReasonTooLarge                            ArtifactReason = "too-large"
	ArtifactReasonUnreadable                          ArtifactReason = "unreadable"
	ArtifactReasonUnsupportedKind                     ArtifactReason = "unsupported-kind"
	ArtifactReasonUnsupportedVersion                  ArtifactReason = "unsupported-version"
)

type Artifact struct {
	Path           string
	Kind           ArtifactKind
	Class          ArtifactClass
	Classification Classification
	Confidence     Confidence
	Reason         ArtifactReason
	finding        Finding
}

func (a Artifact) Finding() Finding {
	return a.finding
}

func artifactFromFinding(f Finding) (Artifact, bool) {
	kind, ok := artifactKindForFinding(f)
	if !ok {
		return Artifact{}, false
	}
	return Artifact{
		Path:           f.Path,
		Kind:           kind,
		Class:          artifactClassForFinding(f),
		Classification: f.Classification,
		Confidence:     f.Confidence,
		Reason:         artifactReasonForFinding(f),
		finding:        f,
	}, true
}

func artifactKindForFinding(f Finding) (ArtifactKind, bool) {
	if hasCodePrefix(f.Code, "SSH-") || hasCodePrefix(f.Code, "PEM-") {
		return ArtifactKindSSH, true
	}
	if hasCodePrefix(f.Code, "MINISIGN-") {
		return ArtifactKindMinisign, true
	}
	if hasCodePrefix(f.Code, "GPG-") {
		return ArtifactKindGPG, true
	}
	switch f.Classification {
	case ClassSSHPrivateKey, ClassPrivateKey:
		return ArtifactKindSSH, true
	case ClassMinisignSecret:
		return ArtifactKindMinisign, true
	case ClassParseError:
		if hasCodePrefix(f.Code, "MINISIGN-") {
			return ArtifactKindMinisign, true
		}
		if hasCodePrefix(f.Code, "SSH-") || hasCodePrefix(f.Code, "PEM-") {
			return ArtifactKindSSH, true
		}
		if hasCodePrefix(f.Code, "GPG-") {
			return ArtifactKindGPG, true
		}
	case ClassEncrypted, ClassKeyringInternal, ClassProtectedSecret, ClassPublic, ClassRevocation, ClassUnsafeSecret:
		if hasCodePrefix(f.Code, "MINISIGN-") {
			return ArtifactKindMinisign, true
		}
		return ArtifactKindGPG, true
	}
	return "", false
}

func artifactClassForFinding(f Finding) ArtifactClass {
	switch f.Classification {
	case ClassPublic:
		return ArtifactClassPublic
	case ClassEncrypted, ClassKeyringInternal, ClassRevocation:
		return ArtifactClassOther
	default:
		if f.Exposure == ExposurePublic {
			return ArtifactClassPublic
		}
		if f.Exposure == ExposureSecret {
			return ArtifactClassPrivate
		}
		return ArtifactClassOther
	}
}

func artifactReasonForFinding(f Finding) ArtifactReason {
	switch f.Classification {
	case ClassEncrypted, ClassKeyringInternal, ClassRevocation:
		return ArtifactReasonUnsupportedKind
	case ClassParseError:
		return ArtifactReasonParseUnsupported
	case ClassProtectedSecret:
		return ArtifactReasonEncryptedPrivateNoPublicCounterpart
	default:
		return ""
	}
}

func hasCodePrefix(code string, prefix string) bool {
	if len(code) < len(prefix) {
		return false
	}
	return code[:len(prefix)] == prefix
}
