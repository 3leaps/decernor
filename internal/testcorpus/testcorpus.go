// Package testcorpus locates the pinned external fixture corpus that supplies
// key-shaped test inputs. Decernor does not construct key material; tests read
// specimens and expected verdicts from the corpus.
package testcorpus

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// RootEnv overrides the corpus checkout location.
	RootEnv = "DECERNOR_SYNTHCORPUS_ROOT"
	// UnpinnedEnv permits an exploratory run against an unpinned checkout.
	// Such a run is not evidence and says so.
	UnpinnedEnv = "DECERNOR_SYNTHCORPUS_UNPINNED"
)

// Pin is the parsed testdata/synthcorpus.pin.
type Pin struct {
	Repository     string
	Commit         string
	Manifest       string
	ManifestSHA256 string
}

// Corpus is a verified corpus checkout.
type Corpus struct {
	Root     string
	Pin      Pin
	Manifest Manifest
	// Unpinned is true when the pin check was waived by UnpinnedEnv.
	Unpinned bool
}

// Manifest is the expected-verdict manifest owned by the corpus.
type Manifest struct {
	SchemaVersion   string              `json:"schema_version"`
	Kind            string              `json:"kind"`
	FixturesRoot    string              `json:"fixtures_root"`
	InvariantRules  map[string]string   `json:"invariant_rules"`
	ClassInvariants map[string][]string `json:"class_invariants"`
	Fixtures        map[string]Fixture  `json:"fixtures"`
}

// Fixture is one specimen's expected verdict.
type Fixture struct {
	Class      string        `json:"class"`
	Placement  string        `json:"placement"`
	Expect     *Expectation  `json:"expect"`
	AlsoExpect []Expectation `json:"also_expect"`
	Guardread  string        `json:"guardread"`
	SHA256     string        `json:"sha256"`
}

// Expectation is a finding code with its severity per profile.
type Expectation struct {
	Code     string            `json:"code"`
	Severity map[string]string `json:"severity"`
}

// Load resolves, verifies, and parses the pinned corpus. Any missing or
// mismatched piece is an error; callers must fail, never skip.
func Load() (Corpus, error) {
	repo, err := repoRoot()
	if err != nil {
		return Corpus{}, err
	}
	pin, err := readPin(filepath.Join(repo, "testdata", "synthcorpus.pin"))
	if err != nil {
		return Corpus{}, err
	}
	root := os.Getenv(RootEnv)
	if root == "" {
		root = filepath.Join(filepath.Dir(repo), "synthcorpus")
	}
	// #nosec G703 -- the corpus root is the operator's own checkout; its
	// contents are verified against the pin below.
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return Corpus{}, fmt.Errorf("fixture corpus not found at %s (set %s): key-shaped tests cannot run without it", root, RootEnv)
	}
	unpinned := os.Getenv(UnpinnedEnv) == "1"
	if !unpinned {
		head, err := gitHead(root)
		if err != nil {
			return Corpus{}, fmt.Errorf("corpus commit: %w", err)
		}
		if head != pin.Commit {
			return Corpus{}, fmt.Errorf("corpus at %s is %s, pin requires %s (set %s=1 for a non-evidence exploratory run)", root, head, pin.Commit, UnpinnedEnv)
		}
	}
	if !filepath.IsLocal(filepath.FromSlash(pin.Manifest)) {
		return Corpus{}, fmt.Errorf("pin manifest path %q must stay inside the corpus", pin.Manifest)
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(pin.Manifest))) // #nosec G703 -- local path under the corpus root, checked above.
	if err != nil {
		return Corpus{}, err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != pin.ManifestSHA256 && !unpinned {
		return Corpus{}, fmt.Errorf("manifest digest %s does not match pin %s", got, pin.ManifestSHA256)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Corpus{}, err
	}
	if m.SchemaVersion != "v0" || m.Kind != "synthcorpus-decernor-scan-verdicts" || len(m.Fixtures) == 0 {
		return Corpus{}, fmt.Errorf("unexpected manifest %q/%q with %d fixtures", m.SchemaVersion, m.Kind, len(m.Fixtures))
	}
	if err := validateVocabulary(m); err != nil {
		return Corpus{}, err
	}
	if err := validatePaths(m); err != nil {
		return Corpus{}, err
	}
	for rel, f := range m.Fixtures {
		body, err := os.ReadFile(filepath.Join(root, m.FixturesRoot, filepath.FromSlash(rel))) // #nosec G703 -- local paths under the corpus root, checked by validatePaths.
		if err != nil {
			return Corpus{}, err
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return Corpus{}, fmt.Errorf("fixture %s does not match its manifest digest", rel)
		}
	}
	return Corpus{Root: root, Pin: pin, Manifest: m, Unpinned: unpinned}, nil
}

// FixturePath returns the absolute path of a manifest fixture.
func (c Corpus) FixturePath(rel string) string {
	return filepath.Join(c.Root, c.Manifest.FixturesRoot, filepath.FromSlash(rel))
}

func readPin(path string) (Pin, error) {
	file, err := os.Open(path)
	if err != nil {
		return Pin{}, err
	}
	defer func() { _ = file.Close() }()
	var pin Pin
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Pin{}, fmt.Errorf("malformed pin line %q", line)
		}
		switch key {
		case "repository":
			pin.Repository = value
		case "commit":
			pin.Commit = value
		case "manifest":
			pin.Manifest = value
		case "manifest_sha256":
			pin.ManifestSHA256 = value
		default:
			return Pin{}, fmt.Errorf("unknown pin key %q", key)
		}
	}
	if err := scanner.Err(); err != nil {
		return Pin{}, err
	}
	if len(pin.Commit) != 40 || pin.Manifest == "" || len(pin.ManifestSHA256) != 64 {
		return Pin{}, errors.New("pin requires a 40-hex commit, a manifest path, and a 64-hex manifest digest")
	}
	return pin, nil
}

func gitHead(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output() // #nosec G702 -- fixed argv, no shell; dir is the corpus root.
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..")), nil
}

// Supported manifest v0 vocabulary. The corpus owns these closed sets; this
// harness implements them and rejects any value it does not support. A
// shared name does not prove shared meaning: rule semantics are exercised by
// the harness's own negative controls, not by this check.
var (
	supportedPlacements = map[string]bool{"agent-key-dir": true, "keyring-home": true, "root": true}
	supportedClasses    = map[string]bool{"plaintext": true, "protected": true, "hardware-stub": true, "malformed": true, "benign": true, "keyring-internal": true}
	supportedProfiles   = map[string]bool{"artifact": true, "workstation": true}
	supportedGuardread  = map[string]bool{"refuse": true, "pass": true}
	// SupportedRules is the rule vocabulary this harness enforces.
	SupportedRules = map[string]bool{
		"has-finding": true, "not-hardware-stub": true, "unsafe-every-profile": true,
		"guardread-refuse": true, "guardread-pass": true, "no-secret-exposure": true, "no-finding": true,
	}
)

func validateVocabulary(m Manifest) error {
	for rule := range m.InvariantRules {
		if !SupportedRules[rule] {
			return fmt.Errorf("manifest declares unsupported rule %q", rule)
		}
	}
	for class, rules := range m.ClassInvariants {
		if !supportedClasses[class] {
			return fmt.Errorf("manifest declares unsupported class %q", class)
		}
		seen := map[string]bool{}
		for _, rule := range rules {
			if !SupportedRules[rule] {
				return fmt.Errorf("class %s names unsupported rule %q", class, rule)
			}
			if seen[rule] {
				return fmt.Errorf("class %s repeats rule %q", class, rule)
			}
			seen[rule] = true
		}
		if len(rules) == 0 {
			return fmt.Errorf("class %s has no rules", class)
		}
	}
	for rel, f := range m.Fixtures {
		if !supportedClasses[f.Class] {
			return fmt.Errorf("%s: unsupported class %q", rel, f.Class)
		}
		if !supportedPlacements[f.Placement] {
			return fmt.Errorf("%s: unsupported placement %q", rel, f.Placement)
		}
		if !supportedGuardread[f.Guardread] {
			return fmt.Errorf("%s: unsupported guardread %q", rel, f.Guardread)
		}
		expectations := append([]Expectation{}, f.AlsoExpect...)
		if f.Expect != nil {
			expectations = append(expectations, *f.Expect)
		}
		for _, e := range expectations {
			if len(e.Severity) != len(supportedProfiles) {
				return fmt.Errorf("%s: %s must give a severity for exactly %d profiles", rel, e.Code, len(supportedProfiles))
			}
			for profile := range e.Severity {
				if !supportedProfiles[profile] {
					return fmt.Errorf("%s: %s names unsupported profile %q", rel, e.Code, profile)
				}
			}
		}
	}
	return nil
}

// validatePaths keeps every manifest path inside the corpus checkout, so an
// unpinned run cannot read outside it.
func validatePaths(m Manifest) error {
	if !filepath.IsLocal(filepath.FromSlash(m.FixturesRoot)) {
		return fmt.Errorf("fixtures_root %q must stay inside the corpus", m.FixturesRoot)
	}
	for rel := range m.Fixtures {
		if !filepath.IsLocal(filepath.FromSlash(rel)) {
			return fmt.Errorf("fixture path %q must stay inside the corpus", rel)
		}
	}
	return nil
}
