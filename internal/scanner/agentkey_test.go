package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic agent key bodies are built at runtime from corpus tokens. They
// carry placeholder parameters only and are not real keys.
func syntheticAdvancedKey(outer string, inner string) string {
	return fmt.Sprintf("(%s (ecc (curve Ed25519)(q #00#)%s))", outer, inner)
}

func syntheticExtendedKey(expr string) string {
	return "Created: 20260101T000000\nKey: " + expr + "\n"
}

func syntheticShadowedKey() string {
	return syntheticExtendedKey(syntheticAdvancedKey(agentKeyTokenShadowed, "(shadowed t1-v1 (#00# OPENPGP.1))")) +
		"Token: 0000000000000000 OPENPGP.1 - - -\n"
}

func syntheticProtectedKey() string {
	return syntheticExtendedKey(syntheticAdvancedKey(agentKeyTokenProtected, "(protected openpgp-s2k3-ocb-aes ((sha1 #00# 1)#00#)#00#)"))
}

func syntheticPlainKey() string {
	return syntheticExtendedKey(syntheticAdvancedKey(agentKeyTokenPlain, "(d #00#)"))
}

func canonical(atoms ...string) string {
	var b strings.Builder
	for _, atom := range atoms {
		switch atom {
		case "(", ")":
			b.WriteString(atom)
		default:
			fmt.Fprintf(&b, "%d:%s", len(atom), atom)
		}
	}
	return b.String()
}

func TestAgentKeyFormFor(t *testing.T) {
	cases := []struct {
		name string
		data string
		want agentKeyForm
	}{
		{"extended plaintext", syntheticPlainKey(), agentKeyFormPlain},
		{"extended protected", syntheticProtectedKey(), agentKeyFormProtected},
		{"extended shadowed", syntheticShadowedKey(), agentKeyFormShadowed},
		{"extended continuation", "Created: 20260101T000000\nKey: (" + agentKeyTokenShadowed + " (ecc\n  (curve Ed25519)(q #00#)\n  (shadowed t1-v1 (#00# OPENPGP.1))))\n", agentKeyFormShadowed},
		{"trailing expression after stub", "Key: (" + agentKeyTokenShadowed + " (ecc (q #00#)\n  (shadowed t1-v1 #00#)))\n (" + agentKeyTokenPlain + " (ecc (d #00#)))\n", agentKeyFormUnrecognized},
		{"trailing protected after stub", syntheticExtendedKey(syntheticAdvancedKey(agentKeyTokenShadowed, "(shadowed t1-v1 #00#)") + syntheticAdvancedKey(agentKeyTokenProtected, "(protected x #00#)")), agentKeyFormUnrecognized},
		{"trailing data after plaintext", syntheticExtendedKey(syntheticAdvancedKey(agentKeyTokenPlain, "(d #00#)") + " junk"), agentKeyFormPlain},
		{"stub plus plaintext key item", syntheticShadowedKey() + "Key: " + syntheticAdvancedKey(agentKeyTokenPlain, "(d #00#)") + "\n", agentKeyFormPlain},
		{"truncated plaintext", "Key: (" + agentKeyTokenPlain + " (ecc (d #00", agentKeyFormPlain},
		{"canonical plaintext", canonical("(", agentKeyTokenPlain, "(", "rsa", "(", "n", "\x00\x01", ")", "(", "d", "\x00", ")", ")", ")"), agentKeyFormPlain},
		{"canonical protected", canonical("(", agentKeyTokenProtected, "(", "rsa", "(", "n", "\x00", ")", "(", "protected", "openpgp-s2k3-sha1-aes-cbc", ")", ")", ")"), agentKeyFormProtected},
		{"canonical shadowed", canonical("(", agentKeyTokenShadowed, "(", "rsa", "(", "n", "\x00", ")", "(", "shadowed", "t1-v1", ")", ")", ")"), agentKeyFormShadowed},
		{"canonical binary payload with parens", canonical("(", agentKeyTokenShadowed, "(", "ecc", "(", "q", "()(d", ")", "(", "shadowed", "t1-v1", ")", ")", ")"), agentKeyFormShadowed},
		{"shadowed carrying secret param", syntheticExtendedKey(syntheticAdvancedKey(agentKeyTokenShadowed, "(d #00#)(shadowed t1-v1 #00#)")), agentKeyFormUnrecognized},
		{"rsa stub carrying prime", syntheticExtendedKey("(" + agentKeyTokenShadowed + " (rsa (n #00#)(q #00#)(shadowed t1-v1 #00#)))"), agentKeyFormUnrecognized},
		{"ecc public point is not secret", syntheticExtendedKey("(" + agentKeyTokenShadowed + " (ecc (q #00#)(shadowed t1-v1 #00#)))"), agentKeyFormShadowed},
		{"protected carrying secret param", syntheticExtendedKey(syntheticAdvancedKey(agentKeyTokenProtected, "(d #00#)")), agentKeyFormUnrecognized},
		{"shadowed wrapping nested plaintext", syntheticExtendedKey(syntheticAdvancedKey(agentKeyTokenShadowed, "("+agentKeyTokenPlain+" (x))")), agentKeyFormPlain},
		{"shadowed unknown algorithm", syntheticExtendedKey("(" + agentKeyTokenShadowed + " (newalg (shadowed t1-v1 #00#)))"), agentKeyFormUnrecognized},
		{"two key items", syntheticShadowedKey() + "Key: " + syntheticAdvancedKey(agentKeyTokenShadowed, "") + "\n", agentKeyFormUnrecognized},
		{"yaml-like key line", "key: value\nother: thing\n  nested: x\n", agentKeyFormNone},
		{"key item other sexp", "Key: (foo (bar))\n", agentKeyFormNone},
		{"extended key item unbalanced", "Key: (" + agentKeyTokenShadowed + " (ecc\n", agentKeyFormUnrecognized},
		{"extended without key item", "Created: 20260101T000000\nLabel: hello\n", agentKeyFormNone},
		{"plain text", "hello world\n", agentKeyFormNone},
		{"other sexp", "(foo (bar))", agentKeyFormNone},
		{"empty", "", agentKeyFormNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentKeyFormFor([]byte(tc.data)); got != tc.want {
				t.Fatalf("form = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAgentKeyFindingsByProfile(t *testing.T) {
	cases := []struct {
		name     string
		data     string
		profile  Profile
		allow    bool
		code     string
		severity Severity
		class    Classification
	}{
		{"plaintext artifact", syntheticPlainKey(), ProfileArtifact, false, "GPG-AGENT-UNPROTECTED-KEY", SeverityUnsafe, ClassUnsafeSecret},
		{"plaintext workstation", syntheticPlainKey(), ProfileWorkstation, false, "GPG-AGENT-UNPROTECTED-KEY", SeverityUnsafe, ClassUnsafeSecret},
		{"protected artifact", syntheticProtectedKey(), ProfileArtifact, false, "GPG-AGENT-PROTECTED-KEY", SeverityWarn, ClassProtectedSecret},
		{"protected workstation", syntheticProtectedKey(), ProfileWorkstation, false, "GPG-AGENT-PROTECTED-KEY", SeverityWarn, ClassProtectedSecret},
		{"protected allowed", syntheticProtectedKey(), ProfileArtifact, true, "GPG-AGENT-PROTECTED-KEY", SeverityInfo, ClassProtectedSecret},
		{"shadowed artifact", syntheticShadowedKey(), ProfileArtifact, false, "GPG-AGENT-SHADOWED-KEY", SeverityWarn, ClassHardwareStub},
		{"shadowed workstation", syntheticShadowedKey(), ProfileWorkstation, false, "GPG-AGENT-SHADOWED-KEY", SeverityInfo, ClassHardwareStub},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Profile: tc.profile, EnableGPG: true, AllowProtectedSecretKeys: tc.allow}
			artifact, ok := classifyAgentKeyArtifact("k.key", []byte(tc.data), cfg)
			if !ok {
				t.Fatal("agent key not classified")
			}
			f := artifact.Finding()
			if f.Code != tc.code || f.Severity != tc.severity || f.Classification != tc.class {
				t.Fatalf("got %s/%s/%s", f.Code, f.Severity, f.Classification)
			}
			if f.Classification == ClassHardwareStub && f.Exposure != ExposureSensitive {
				t.Fatalf("stub exposure = %s, want sensitive", f.Exposure)
			}
			if artifact.Reason != ArtifactReasonUnsupportedKind {
				t.Fatalf("artifact reason = %q, want unsupported-kind", artifact.Reason)
			}
		})
	}
}

func TestAgentKeyUnrecognizedUnderKeyDirFailsClosed(t *testing.T) {
	path := filepath.Join("home", gpgAgentPrivateDir, "ABC.key")
	artifact, ok := classifyAgentKeyArtifact(path, []byte("garbage"), Config{EnableGPG: true})
	if !ok {
		t.Fatal("unrecognized key file under agent key dir was not reported")
	}
	if f := artifact.Finding(); f.Code != "GPG-AGENT-KEY-UNRECOGNIZED" || f.Severity != SeverityUnsafe {
		t.Fatalf("got %s/%s", f.Code, f.Severity)
	}
	if _, ok := classifyAgentKeyArtifact("elsewhere/ABC.key", []byte("garbage"), Config{EnableGPG: true}); ok {
		t.Fatal("non-agent path should not be classified")
	}
}

func TestClassifyBufferRefusesAgentKeys(t *testing.T) {
	for name, data := range map[string]string{
		"plain":     syntheticPlainKey(),
		"protected": syntheticProtectedKey(),
		"shadowed":  syntheticShadowedKey(),
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := classifyBufferWithPacketLister(context.Background(), "x.txt", []byte(data), Config{}, fakePacketLister{})
			if !ok {
				t.Fatal("agent key buffer not classified")
			}
		})
	}
}

func liveGnuPGHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), ".gnupg")
	keys := filepath.Join(home, gpgAgentPrivateDir)
	mustMkdir(t, keys)
	mustWrite(t, filepath.Join(keys, "A.key"), syntheticShadowedKey())
	mustWrite(t, filepath.Join(keys, "B.key"), syntheticShadowedKey())
	mustWrite(t, filepath.Join(home, "pubring.kbx"), "kbx placeholder")
	mustWrite(t, filepath.Join(home, "trustdb.gpg"), "trustdb placeholder")
	mustWrite(t, filepath.Join(home, "gpg-agent.conf"), "default-cache-ttl 60\n")
	return home
}

func TestScanSmartcardHomeWorkstationProfilePasses(t *testing.T) {
	home := liveGnuPGHome(t)
	result, err := scanWithPacketLister(context.Background(), home, Config{Profile: ProfileWorkstation}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsafes != 0 || result.Warns != 0 {
		t.Fatalf("warns=%d unsafes=%d findings=%#v", result.Warns, result.Unsafes, result.Findings)
	}
	if result.Profile != ProfileWorkstation {
		t.Fatalf("profile = %q", result.Profile)
	}
	stubs := 0
	for _, f := range result.Findings {
		if f.Classification == ClassHardwareStub {
			stubs++
		}
		if f.Exposure == ExposureSecret {
			t.Fatalf("no finding may claim secret exposure: %#v", f)
		}
	}
	if stubs != 2 {
		t.Fatalf("hardware stubs = %d findings=%#v", stubs, result.Findings)
	}
}

func TestScanSmartcardHomeArtifactProfileFailsWithoutSecretClaim(t *testing.T) {
	home := liveGnuPGHome(t)
	result, err := scanWithPacketLister(context.Background(), home, Config{}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile != ProfileArtifact {
		t.Fatalf("profile = %q", result.Profile)
	}
	// .gnupg dir, private-keys-v1.d dir, three internal files.
	if result.Unsafes != 5 || result.Warns != 2 {
		t.Fatalf("warns=%d unsafes=%d findings=%#v", result.Warns, result.Unsafes, result.Findings)
	}
	for _, f := range result.Findings {
		if f.Exposure == ExposureSecret {
			t.Fatalf("no finding may claim secret exposure: %#v", f)
		}
	}
}

func TestScanWorkstationProfileStillFlagsSecrets(t *testing.T) {
	home := liveGnuPGHome(t)
	mustWrite(t, filepath.Join(home, gpgAgentPrivateDir, "C.key"), syntheticPlainKey())
	mustWrite(t, filepath.Join(home, gpgAgentPrivateDir, "D.key"), syntheticProtectedKey())
	mustWrite(t, filepath.Join(home, gpgAgentPrivateDir, "E.key"), "not a key")
	mustWrite(t, filepath.Join(home, "secring.gpg"), "legacy placeholder")
	mustWrite(t, filepath.Join(home, "export.asc"), "-----"+pgpPrivateHeader()+"-----\n")

	result, err := scanWithPacketLister(context.Background(), home, Config{Profile: ProfileWorkstation}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]Severity{}
	for _, f := range result.Findings {
		codes[f.Code] = f.Severity
	}
	want := map[string]Severity{
		"GPG-AGENT-UNPROTECTED-KEY":    SeverityUnsafe,
		"GPG-AGENT-PROTECTED-KEY":      SeverityWarn,
		"GPG-AGENT-KEY-UNRECOGNIZED":   SeverityUnsafe,
		"GPG-KEYRING-SECRET-FILE":      SeverityUnsafe,
		"GPG-PRIVATE-ARMOR-UNVERIFIED": SeverityUnsafe,
	}
	for code, severity := range want {
		if codes[code] != severity {
			t.Fatalf("%s severity = %q, want %q; findings=%#v", code, codes[code], severity, result.Findings)
		}
	}
}

func TestScanFindsPlainAgentKeyOutsideKeyDir(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "copied.key"), syntheticPlainKey())
	result, err := scanWithPacketLister(context.Background(), dir, Config{Profile: ProfileWorkstation}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsafes != 1 || result.Findings[0].Code != "GPG-AGENT-UNPROTECTED-KEY" {
		t.Fatalf("findings=%#v", result.Findings)
	}
}

func TestAgentKeyAdversarialInputsFailClosed(t *testing.T) {
	stub := syntheticAdvancedKey(agentKeyTokenShadowed, "(shadowed t1-v1 #00#)")
	plain := "(" + agentKeyTokenPlain + " (ecc (d #00#)))"
	cases := []struct {
		name string
		data string
		want agentKeyForm
	}{
		{"hex secret param in stub", "Key: (" + agentKeyTokenShadowed + " (ecc (q #00#)(#64# #00#)(shadowed t1-v1 #00#)))\n", agentKeyFormUnrecognized},
		{"base64 secret param in stub", "Key: (" + agentKeyTokenShadowed + " (ecc (q #00#)(|ZA==| #00#)(shadowed t1-v1 #00#)))\n", agentKeyFormUnrecognized},
		{"hex secret param in protected", "Key: (" + agentKeyTokenProtected + " (ecc (q #00#)(#64# #00#)(protected x #00#)))\n", agentKeyFormUnrecognized},
		{"hex outer plaintext token", "(#707269766174652d6b6579# (ecc (d #00#)))", agentKeyFormPlain},
		{"base64 outer plaintext token", "(|cHJpdmF0ZS1rZXk=| (ecc (d #00#)))", agentKeyFormPlain},
		{"display hint before outer token", "([h]" + agentKeyTokenPlain + " (ecc (d #00#)))", agentKeyFormPlain},
		{"continuation after blank line", "Key: " + stub + "\n\n " + plain + "\n", agentKeyFormUnrecognized},
		{"plaintext in other item", "Key: " + stub + "\nLabel: " + plain + "\n", agentKeyFormUnrecognized},
		{"plaintext in comment", "Key: " + stub + "\n# " + plain + "\n", agentKeyFormUnrecognized},
		{"utf8 bom", "\xef\xbb\xbf" + plain, agentKeyFormPlain},
		{"form feed", "\f" + plain, agentKeyFormPlain},
		{"cr-only lines", "Created: 1\rKey: " + plain + "\r", agentKeyFormPlain},
		{"preamble line", "garbage line\nKey: " + plain + "\n", agentKeyFormUnrecognized},
		{"junk before sexp in item", "Key: x " + plain + "\n", agentKeyFormUnrecognized},
		{"directory name in prose is not a key", "// agent key files (" + gpgAgentPrivateDir + "/*.key)\n", agentKeyFormNone},
		{"stub label naming key dir", "Key: " + stub + "\nLabel: (" + gpgAgentPrivateDir + ")\n", agentKeyFormShadowed},
		{"json mention is not a key", `{"type": "` + agentKeyTokenPlain + `"}`, agentKeyFormNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentKeyFormFor([]byte(tc.data)); got != tc.want {
				t.Fatalf("form = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScanAgentKeyPastPrefixIsNotStub(t *testing.T) {
	home := filepath.Join(t.TempDir(), gpgAgentPrivateDir)
	mustMkdir(t, home)
	stub := "Key: " + syntheticAdvancedKey(agentKeyTokenShadowed, "(shadowed t1-v1 #00#)") + "\n"
	padding := strings.Repeat("# padding line for prefix test\n", 2*prefixBytes/30)
	mustWrite(t, filepath.Join(home, "A.key"), stub+padding+"Key: ("+agentKeyTokenPlain+" (ecc (d #00#)))\n")
	canonicalStub := canonical("(", agentKeyTokenShadowed, "(", "ecc", "(", "q", "x", ")", "(", "shadowed", "t1-v1", ")", ")", ")")
	mustWrite(t, filepath.Join(home, "B.key"), canonicalStub+strings.Repeat(" ", 2*prefixBytes)+canonical("(", agentKeyTokenPlain, "(", "ecc", "(", "d", "x", ")", ")", ")"))

	result, err := scanWithPacketLister(context.Background(), home, Config{Profile: ProfileWorkstation}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsafes != 2 {
		t.Fatalf("unsafes=%d findings=%#v", result.Unsafes, result.Findings)
	}
}

func TestScanKeyringInternalFileContentStillChecked(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".gnupg")
	mustMkdir(t, home)
	mustWrite(t, filepath.Join(home, "pubring.kbx"), syntheticPlainKey())
	mustWrite(t, filepath.Join(home, "trustdb.gpg"), openSSHPrivateKey("none"))

	result, err := scanWithPacketLister(context.Background(), home, Config{Profile: ProfileWorkstation}, fakePacketLister{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Unsafes != 2 {
		t.Fatalf("unsafes=%d findings=%#v", result.Unsafes, result.Findings)
	}
}
