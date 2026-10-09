package scanner

import (
	"context"
	"path/filepath"
	"testing"
)

// Agent key classification is exercised against the external fixture corpus
// by internal/testcorpus (PDR-0002). The tests here use non-key inputs only.

func TestAgentKeyFormForNonKeyInputs(t *testing.T) {
	cases := map[string]string{
		"empty":                "",
		"plain text":           "hello world\n",
		"yaml key line":        "key: value\nother: thing\n  nested: x\n",
		"other sexp":           "(foo (bar))",
		"extended without key": "Created: 20260101T000000\nLabel: hello\n",
		"key item other sexp":  "Key: (foo (bar))\n",
		"prose naming key dir": "agent key files (" + gpgAgentPrivateDir + "/*.key)\n",
		"json field name":      `{"type": "` + agentKeyTokenPlain + `"}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if got := agentKeyFormFor([]byte(data)); got != agentKeyFormNone {
				t.Fatalf("form = %q, want none", got)
			}
		})
	}
}

func TestAgentKeyUnparseableUnderKeyDirFailsClosed(t *testing.T) {
	path := filepath.Join("home", gpgAgentPrivateDir, "ABC.key")
	artifact, ok := classifyAgentKeyArtifact(path, []byte("garbage"), Config{EnableGPG: true})
	if !ok {
		t.Fatal("unparseable key file under the agent key directory was not reported")
	}
	if f := artifact.Finding(); f.Code != "GPG-AGENT-KEY-UNRECOGNIZED" || f.Severity != SeverityUnsafe {
		t.Fatalf("got %s/%s", f.Code, f.Severity)
	}
	if _, ok := classifyAgentKeyArtifact("elsewhere/ABC.key", []byte("garbage"), Config{EnableGPG: true}); ok {
		t.Fatal("non-agent path should not be classified")
	}
}

func TestAgentKeyHugeCanonicalLengthDoesNotPanic(t *testing.T) {
	for _, in := range []string{
		"(9223372036854775806:x)",
		"(18446744073709551615:x)",
		"(99999999999999999999:",
	} {
		_ = agentKeyFormFor([]byte(in))
	}
}

func TestKeyringNamesByProfile(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".gnupg")
	mustMkdir(t, filepath.Join(home, gpgAgentPrivateDir))
	mustWrite(t, filepath.Join(home, "pubring.kbx"), "kbx placeholder")
	mustWrite(t, filepath.Join(home, "trustdb.gpg"), "trustdb placeholder")
	mustWrite(t, filepath.Join(home, "gpg-agent.conf"), "default-cache-ttl 60\n")
	mustWrite(t, filepath.Join(home, "secring.gpg"), "legacy placeholder")

	for _, tc := range []struct {
		profile Profile
		unsafes int
	}{
		// .gnupg dir, private-keys-v1.d dir, three internal files, secring.
		{ProfileArtifact, 6},
		// Only secring stays unsafe; internals are info.
		{ProfileWorkstation, 1},
	} {
		result, err := scanWithPacketLister(context.Background(), home, Config{Profile: tc.profile}, fakePacketLister{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Unsafes != tc.unsafes || result.Profile != tc.profile {
			t.Fatalf("%s: unsafes=%d profile=%q findings=%#v", tc.profile, result.Unsafes, result.Profile, result.Findings)
		}
		for _, f := range result.Findings {
			if f.Code == "GPG-KEYRING-SECRET-FILE" && f.Severity != SeverityUnsafe {
				t.Fatalf("%s: secring severity = %s", tc.profile, f.Severity)
			}
			if f.Code != "GPG-KEYRING-SECRET-FILE" && f.Exposure == ExposureSecret {
				t.Fatalf("%s: name-only finding claims secret exposure: %#v", tc.profile, f)
			}
		}
	}
}

// TestAgentKeyArtifactsHaveNoFingerprintScheme asserts every agent-key finding
// maps to unsupported-kind, so fingerprint emits a reason-bearing null record.
func TestAgentKeyArtifactsHaveNoFingerprintScheme(t *testing.T) {
	cases := []struct {
		code  string
		class Classification
	}{
		{"GPG-AGENT-UNPROTECTED-KEY", ClassUnsafeSecret},
		{"GPG-AGENT-PROTECTED-KEY", ClassProtectedSecret},
		{"GPG-AGENT-SHADOWED-KEY", ClassHardwareStub},
		{"GPG-AGENT-KEY-UNRECOGNIZED", ClassParseError},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			artifact, ok := mustArtifact(Finding{Path: "k", Code: tc.code, Classification: tc.class, Severity: SeverityWarn})
			if !ok {
				t.Fatal("finding did not map to an artifact")
			}
			if artifact.Kind != ArtifactKindGPG || artifact.Reason != ArtifactReasonUnsupportedKind {
				t.Fatalf("kind/reason = %s/%q, want gpg/unsupported-kind", artifact.Kind, artifact.Reason)
			}
		})
	}
}
