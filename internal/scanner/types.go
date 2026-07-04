package scanner

import "time"

type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityWarn   Severity = "warn"
	SeverityUnsafe Severity = "unsafe"
)

type Priority string

const (
	PriorityP0 Priority = "P0"
	PriorityP1 Priority = "P1"
	PriorityP2 Priority = "P2"
	PriorityP3 Priority = "P3"
	PriorityP4 Priority = "P4"
	PriorityP5 Priority = "P5"
)

type Classification string

const (
	ClassEncrypted       Classification = "encrypted"
	ClassKeyringInternal Classification = "keyring-internal"
	ClassMinisignSecret  Classification = "minisign-secret"
	ClassParseError      Classification = "parse-error"
	ClassPrivateKey      Classification = "private-key"
	ClassProtectedSecret Classification = "protected-secret"
	ClassPublic          Classification = "public"
	ClassRevocation      Classification = "revocation"
	ClassSSHPrivateKey   Classification = "ssh-private-key"
	ClassSkipped         Classification = "skipped"
	ClassUnsafeSecret    Classification = "unsafe-secret"
	ClassUnknown         Classification = "unknown"
)

type Retention string

const (
	RetentionAllowed          Retention = "allowed"
	RetentionInspectManually  Retention = "inspect-manually"
	RetentionRemove           Retention = "remove"
	RetentionRetainControlled Retention = "retain-with-controls"
)

type Exposure string

const (
	ExposurePublic    Exposure = "public"
	ExposureSensitive Exposure = "sensitive"
	ExposureSecret    Exposure = "secret"
	ExposureUnknown   Exposure = "unknown"
)

type Sensitivity string

const (
	SensitivityUnknown      Sensitivity = "unknown"
	SensitivityPublic       Sensitivity = "0-public"
	SensitivityConfidential Sensitivity = "1-confidential"
	SensitivityBlinded      Sensitivity = "2-blinded"
	SensitivityProprietary  Sensitivity = "3-proprietary"
	SensitivityPersonal     Sensitivity = "4-personal"
	SensitivityPrivileged   Sensitivity = "5-privileged"
	SensitivityEyesOnly     Sensitivity = "6-eyes-only"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Profile string

const (
	ProfileArtifact    Profile = "artifact"
	ProfileWorkstation Profile = "workstation"
)

type Config struct {
	MaxFileSize              int64
	GPGTimeout               time.Duration
	AllowProtectedSecretKeys bool
	Profile                  Profile
	EnableGPG                bool
	EnableSSH                bool
	EnableMinisign           bool
}

type Result struct {
	Root      string    `json:"root"`
	Scanned   int       `json:"scanned"`
	Skipped   int       `json:"skipped"`
	Findings  []Finding `json:"findings"`
	Warns     int       `json:"warns"`
	Unsafes   int       `json:"unsafes"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

type Finding struct {
	Path           string         `json:"path"`
	Code           string         `json:"code"`
	Priority       Priority       `json:"priority"`
	Rank           int            `json:"rank"`
	Classification Classification `json:"classification"`
	Severity       Severity       `json:"severity"`
	Retention      Retention      `json:"retention"`
	Exposure       Exposure       `json:"exposure"`
	Sensitivity    Sensitivity    `json:"sensitivity"`
	Confidence     Confidence     `json:"confidence"`
	Evidence       string         `json:"evidence"`
	Recommendation string         `json:"recommendation"`
}

func (r *Result) AddFinding(f Finding) {
	f = withDefaults(f)
	r.Findings = append(r.Findings, f)
	switch f.Severity {
	case SeverityWarn:
		r.Warns++
	case SeverityUnsafe:
		r.Unsafes++
	}
}

func withDefaults(f Finding) Finding {
	if f.Code == "" {
		f.Code = "DECERNOR-UNKNOWN"
	}
	if f.Priority == "" {
		switch f.Severity {
		case SeverityUnsafe:
			f.Priority = PriorityP1
		case SeverityWarn:
			f.Priority = PriorityP3
		default:
			f.Priority = PriorityP5
		}
	}
	if f.Rank == 0 {
		f.Rank = priorityRank(f.Priority)
	}
	if f.Sensitivity == "" {
		f.Sensitivity = sensitivityForExposure(f.Exposure)
	}
	return f
}

func priorityRank(priority Priority) int {
	switch priority {
	case PriorityP0:
		return 600
	case PriorityP1:
		return 500
	case PriorityP2:
		return 400
	case PriorityP3:
		return 300
	case PriorityP4:
		return 200
	default:
		return 100
	}
}

func sensitivityForExposure(exposure Exposure) Sensitivity {
	switch exposure {
	case ExposurePublic:
		return SensitivityPublic
	case ExposureSensitive:
		return SensitivityProprietary
	case ExposureSecret:
		return SensitivityPrivileged
	default:
		return SensitivityUnknown
	}
}
