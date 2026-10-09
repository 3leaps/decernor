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
				checkClassInvariants(t, profile, fixture.Class, own)
			}
			checkGuardread(t, bin, staged, fixture)
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

// checkClassInvariants enforces per-class rules that every specimen inherits,
// independent of its individual expectation.
func checkClassInvariants(t *testing.T, profile, class string, own []scanFinding) {
	t.Helper()
	switch class {
	case "plaintext", "protected", "malformed":
		if len(own) == 0 {
			t.Errorf("%s: class %s produced no finding", profile, class)
		}
		for _, f := range own {
			if f.Classification == "hardware-stub" {
				t.Errorf("%s: class %s classified as hardware-stub", profile, class)
			}
		}
		if class != "protected" && !anySeverity(own, "unsafe") {
			t.Errorf("%s: class %s not unsafe: %v", profile, class, own)
		}
	case "hardware-stub":
		for _, f := range own {
			if f.Exposure == "secret" {
				t.Errorf("%s: hardware stub reported secret exposure", profile)
			}
		}
	case "benign":
		if len(own) != 0 {
			t.Errorf("%s: benign specimen produced findings %v", profile, own)
		}
	}
}

func checkGuardread(t *testing.T, bin, staged string, fixture Fixture) {
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
	if fixture.Class != "benign" && fixture.Class != "keyring-internal" && !refused {
		t.Errorf("guardread passed a %s specimen", fixture.Class)
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
