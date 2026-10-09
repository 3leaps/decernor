package testcorpus

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type scanFinding struct {
	Path           string `json:"path"`
	Code           string `json:"code"`
	Severity       string `json:"severity"`
	Classification string `json:"classification"`
	Exposure       string `json:"exposure"`
}

type scanReport struct {
	Profile  string        `json:"profile"`
	Findings []scanFinding `json:"findings"`
}

var profiles = []string{"artifact", "workstation"}

// TestAgentKeyCorpusVerdicts runs the built decernor binary over every corpus
// specimen staged at its manifest placement, and asserts the manifest's
// expected findings, guardread verdicts, and per-class invariants.
func TestAgentKeyCorpusVerdicts(t *testing.T) {
	corpus, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if corpus.Unpinned {
		t.Log("NOT EVIDENCE: corpus pin check waived by " + UnpinnedEnv)
	}
	bin := buildDecernor(t)

	rels := make([]string, 0, len(corpus.Manifest.Fixtures))
	for rel := range corpus.Manifest.Fixtures {
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	for _, rel := range rels {
		fixture := corpus.Manifest.Fixtures[rel]
		t.Run(rel, func(t *testing.T) {
			staged, scanRoot := stage(t, corpus.FixturePath(rel), fixture.Placement)
			for _, profile := range profiles {
				report := scan(t, bin, scanRoot, profile)
				own := findingsFor(report, staged)
				checkExpected(t, profile, fixture, own)
				checkClassInvariants(t, profile, corpus.Manifest.ClassInvariants[fixture.Class], own)
			}
			checkGuardread(t, bin, staged, fixture, corpus.Manifest.ClassInvariants[fixture.Class])
		})
	}
}

// TestScanReportsProfile asserts the report names the profile it ran under.
func TestScanReportsProfile(t *testing.T) {
	bin := buildDecernor(t)
	dir := t.TempDir()
	for _, profile := range profiles {
		if got := scan(t, bin, dir, profile).Profile; got != profile {
			t.Errorf("report profile = %q, want %q", got, profile)
		}
	}
}

func checkExpected(t *testing.T, profile string, fixture Fixture, own []scanFinding) {
	t.Helper()
	want := []Expectation{}
	if fixture.Expect != nil {
		want = append(want, *fixture.Expect)
	}
	want = append(want, fixture.AlsoExpect...)
	if len(want) == 0 {
		if len(own) != 0 {
			t.Errorf("%s: want no finding, got %v", profile, own)
		}
		return
	}
	for _, w := range want {
		found := false
		for _, f := range own {
			if f.Code == w.Code {
				found = true
				if f.Severity != w.Severity[profile] {
					t.Errorf("%s: %s severity = %s, want %s", profile, f.Code, f.Severity, w.Severity[profile])
				}
			}
		}
		if !found {
			t.Errorf("%s: missing %s; got %v", profile, w.Code, own)
		}
	}
	if len(own) != len(want) {
		t.Errorf("%s: %d findings, want %d: %v", profile, len(own), len(want), own)
	}
}

// scanRules implements the manifest's scan-side invariant rules. Each rule
// returns a failure message, or "" when the specimen's findings satisfy it.
var scanRules = map[string]func(own []scanFinding) string{
	"has-finding": func(own []scanFinding) string {
		if len(own) == 0 {
			return "no finding"
		}
		return ""
	},
	"not-hardware-stub": func(own []scanFinding) string {
		for _, f := range own {
			if f.Classification == "hardware-stub" {
				return "classified as hardware-stub"
			}
		}
		return ""
	},
	"unsafe-every-profile": func(own []scanFinding) string {
		if !anySeverity(own, "unsafe") {
			return "no unsafe finding"
		}
		return ""
	},
	"no-secret-exposure": func(own []scanFinding) string {
		for _, f := range own {
			if f.Exposure == "secret" {
				return "finding reports secret exposure"
			}
		}
		return ""
	},
	"no-finding": func(own []scanFinding) string {
		if len(own) != 0 {
			return "unexpected findings"
		}
		return ""
	},
}

// guardreadRules implements the manifest's guardread-side invariant rules.
var guardreadRules = map[string]bool{
	"guardread-refuse": true,
	"guardread-pass":   false,
}

// checkClassInvariants enforces exactly the rules the manifest names for the
// specimen's class, independent of its per-specimen expectation.
func checkClassInvariants(t *testing.T, profile string, rules []string, own []scanFinding) {
	t.Helper()
	for _, rule := range rules {
		check, ok := scanRules[rule]
		if !ok {
			continue
		}
		if msg := check(own); msg != "" {
			t.Errorf("%s: invariant %s: %s: %v", profile, rule, msg, own)
		}
	}
}

// TestManifestRulesMatchHarness fails when the manifest declares a rule the
// harness does not enforce, or the harness enforces a rule the manifest does
// not declare, or a class names an undeclared rule.
func TestManifestRulesMatchHarness(t *testing.T) {
	corpus, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	implemented := map[string]bool{}
	for rule := range scanRules {
		implemented[rule] = true
	}
	for rule := range guardreadRules {
		implemented[rule] = true
	}
	for rule := range corpus.Manifest.InvariantRules {
		if !implemented[rule] {
			t.Errorf("manifest rule %q is not enforced by the harness", rule)
		}
	}
	for rule := range implemented {
		if _, ok := corpus.Manifest.InvariantRules[rule]; !ok {
			t.Errorf("harness rule %q is not declared in the manifest", rule)
		}
	}
	for class, rules := range corpus.Manifest.ClassInvariants {
		for _, rule := range rules {
			if _, ok := corpus.Manifest.InvariantRules[rule]; !ok {
				t.Errorf("class %s names undeclared rule %q", class, rule)
			}
		}
	}
	for rel, f := range corpus.Manifest.Fixtures {
		if _, ok := corpus.Manifest.ClassInvariants[f.Class]; !ok {
			t.Errorf("%s: class %q has no invariants", rel, f.Class)
		}
	}
}

func checkGuardread(t *testing.T, bin, staged string, fixture Fixture, rules []string) {
	t.Helper()
	cmd := exec.Command(bin, "guardread", staged)
	out, err := cmd.Output()
	refused := false
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 3 {
		refused = true
	} else if err != nil {
		t.Fatalf("guardread: %v", err)
	}
	switch fixture.Guardread {
	case "refuse":
		if !refused || len(out) != 0 {
			t.Errorf("guardread: want refusal with empty stdout, got refused=%v stdout=%d bytes", refused, len(out))
		}
	case "pass":
		if refused {
			t.Errorf("guardread: want pass, got refusal")
		}
	default:
		t.Fatalf("manifest guardread %q", fixture.Guardread)
	}
	for _, rule := range rules {
		wantRefuse, ok := guardreadRules[rule]
		if !ok {
			continue
		}
		if refused != wantRefuse || (wantRefuse && len(out) != 0) {
			t.Errorf("invariant %s: refused=%v stdout=%d bytes", rule, refused, len(out))
		}
	}
}

func anySeverity(fs []scanFinding, severity string) bool {
	for _, f := range fs {
		if f.Severity == severity {
			return true
		}
	}
	return false
}

// stage copies a specimen into a fresh tree at its manifest placement and
// returns the staged file path and the directory to scan.
func stage(t *testing.T, src, placement string) (string, string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	var dir string
	switch placement {
	case "agent-key-dir":
		dir = filepath.Join(root, "home", "private-keys-v1.d")
	case "keyring-home":
		dir = filepath.Join(root, "home")
	case "root":
		dir = filepath.Join(root, "root")
	default:
		t.Fatalf("unknown placement %q", placement)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, filepath.Base(src))
	if err := os.WriteFile(staged, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return staged, dir
}

func scan(t *testing.T, bin, dir, profile string) scanReport {
	t.Helper()
	out, err := exec.Command(bin, "scan", "--profile", profile, "--format", "json", "--fail-on", "none", dir).Output()
	if err != nil {
		t.Fatalf("scan %s: %v", profile, err)
	}
	var report scanReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("scan %s: decode: %v", profile, err)
	}
	return report
}

func findingsFor(report scanReport, staged string) []scanFinding {
	var own []scanFinding
	for _, f := range report.Findings {
		if f.Path == staged {
			own = append(own, f)
		}
	}
	return own
}

func buildDecernor(t *testing.T) string {
	t.Helper()
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "decernor")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/decernor")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build decernor: %v\n%s", err, out)
	}
	return bin
}

// TestCIPinMatchesTestdataPin asserts the CI corpus checkout and the test pin
// name the same commit.
func TestCIPinMatchesTestdataPin(t *testing.T) {
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	pin, err := readPin(filepath.Join(repo, "testdata", "synthcorpus.pin"))
	if err != nil {
		t.Fatal(err)
	}
	ci, err := os.ReadFile(filepath.Join(repo, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	want := "SYNTHCORPUS_COMMIT: " + pin.Commit
	if !strings.Contains(string(ci), want) {
		t.Fatalf("ci.yml does not pin %s", want)
	}
}
