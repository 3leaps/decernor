package readiness

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	SchemaVersion                      string       `json:"schema_version"`
	Name                               string       `json:"name"`
	Description                        string       `json:"description,omitempty"`
	Mode                               string       `json:"mode,omitempty"`
	SensitivityFloor                   string       `json:"sensitivity_floor,omitempty"`
	AllowSoftwareKeys                  bool         `json:"allow_software_keys"`
	HardwarePreferred                  bool         `json:"hardware_preferred"`
	HardwareRequired                   bool         `json:"hardware_required"`
	RequireStrongPassphraseAttestation bool         `json:"require_strong_passphrase_attestation"`
	Capabilities                       []Capability `json:"capabilities"`
}

type Capability struct {
	ID                           string   `json:"id"`
	Provider                     string   `json:"provider"`
	Verb                         string   `json:"verb"`
	Required                     bool     `json:"required,omitempty"`
	Description                  string   `json:"description,omitempty"`
	AcceptedMaterial             []string `json:"accepted_material,omitempty"`
	RequirePublicCounterpart     bool     `json:"require_public_counterpart,omitempty"`
	RequireRevocationCertificate bool     `json:"require_revocation_certificate,omitempty"`
	StaticChecks                 []string `json:"static_checks,omitempty"`
	ProofChecks                  []string `json:"proof_checks,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != "v0" {
		return fmt.Errorf("schema_version must be v0")
	}
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}
	if c.Mode != "" && !oneOf(c.Mode, "artifact", "workstation", "handoff") {
		return fmt.Errorf("unsupported mode %q", c.Mode)
	}
	if c.SensitivityFloor != "" && !oneOf(c.SensitivityFloor, "unknown", "0-public", "1-confidential", "2-blinded", "3-proprietary", "4-personal", "5-privileged", "6-eyes-only") {
		return fmt.Errorf("unsupported sensitivity_floor %q", c.SensitivityFloor)
	}
	if len(c.Capabilities) == 0 {
		return fmt.Errorf("at least one capability is required")
	}
	seen := map[string]bool{}
	for i, capability := range c.Capabilities {
		if capability.ID == "" {
			return fmt.Errorf("capabilities[%d].id is required", i)
		}
		if seen[capability.ID] {
			return fmt.Errorf("duplicate capability id %q", capability.ID)
		}
		seen[capability.ID] = true
		if !oneOf(capability.Provider, "gpg", "ssh", "minisign") {
			return fmt.Errorf("capabilities[%d].provider is unsupported: %q", i, capability.Provider)
		}
		if !oneOf(capability.Verb, "sign", "encrypt", "decrypt", "auth") {
			return fmt.Errorf("capabilities[%d].verb is unsupported: %q", i, capability.Verb)
		}
		for _, material := range capability.AcceptedMaterial {
			if !oneOf(material, "public-key", "encrypted-private-key", "protected-secret-key", "hardware-backed-key", "revocation-certificate") {
				return fmt.Errorf("capabilities[%d].accepted_material contains unsupported value %q", i, material)
			}
		}
		for _, check := range append(capability.StaticChecks, capability.ProofChecks...) {
			if !oneOf(check, "material-present", "not-plaintext", "public-counterpart", "revocation-present", "sign-and-verify", "encrypt-and-decrypt", "derive-public-key", "remote-auth") {
				return fmt.Errorf("capabilities[%d] contains unsupported check %q", i, check)
			}
		}
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
