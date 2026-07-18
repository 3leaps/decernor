package fingerprint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/3leaps/decernor/internal/scanner"
)

const defaultMaxFileSize = 25 * 1024 * 1024

func Run(ctx context.Context, inputs []string, cfg Config, diagnostics io.Writer) (Result, error) {
	if len(inputs) == 0 {
		return Result{}, fmt.Errorf("at least one path is required")
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = defaultMaxFileSize
	}
	if cfg.PathMode == "" {
		cfg.PathMode = PathModeRelative
	}
	if cfg.GPGTimeout <= 0 {
		cfg.GPGTimeout = 10 * time.Second
	}
	if !cfg.EnableGPG && !cfg.EnableSSH && !cfg.EnableMini {
		cfg.EnableGPG = true
		cfg.EnableSSH = true
		cfg.EnableMini = true
	}

	var records []Record
	for inputIndex, input := range inputs {
		rootRecords, err := walkInput(ctx, inputIndex, input, cfg, diagnostics)
		if err != nil {
			return Result{}, err
		}
		records = append(records, rootRecords...)
	}
	if err := applyRecordPaths(records, cfg.PathMode); err != nil {
		return Result{}, err
	}
	sortRecords(records)
	return Result{Records: records, Empty: len(records) == 0}, nil
}

func walkInput(ctx context.Context, inputIndex int, input string, cfg Config, diagnostics io.Writer) ([]Record, error) {
	rootAbs, err := filepath.Abs(input)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(rootAbs)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("named input is a symlink: %s", input)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("named input is not a regular file or directory: %s", input)
	}
	root := rootAbs
	if info.Mode().IsRegular() {
		root = filepath.Dir(rootAbs)
		return fingerprintFile(ctx, root, rootAbs, inputIndex, cfg, diagnostics)
	}

	var records []Record
	err = filepath.WalkDir(rootAbs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			writeDiagnostic(diagnostics, "walk-error", diagnosticPath(root, path, inputIndex, cfg.PathMode), "")
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			writeDiagnostic(diagnostics, "symlink-not-traversed", diagnosticPath(root, path, inputIndex, cfg.PathMode), "")
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			writeDiagnostic(diagnostics, "metadata-error", diagnosticPath(root, path, inputIndex, cfg.PathMode), "")
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		fileRecords, err := fingerprintFile(ctx, root, path, inputIndex, cfg, diagnostics)
		if err != nil {
			writeDiagnostic(diagnostics, "file-warning", diagnosticPath(root, path, inputIndex, cfg.PathMode), "")
			return nil
		}
		records = append(records, fileRecords...)
		return nil
	})
	return records, err
}

func fingerprintFile(ctx context.Context, root string, path string, inputIndex int, cfg Config, diagnostics io.Writer) ([]Record, error) {
	source := sourceForPath(root, path, inputIndex)
	if !matchesFilters(source.RelPath, cfg.Include, cfg.Exclude) {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		writeDiagnostic(diagnostics, string(scanner.ArtifactReasonUnreadable), diagnosticPath(root, path, inputIndex, cfg.PathMode), "")
		return nil, nil
	}
	if info.Size() > cfg.MaxFileSize {
		writeDiagnostic(diagnostics, string(scanner.ArtifactReasonTooLarge), diagnosticPath(root, path, inputIndex, cfg.PathMode), "")
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeDiagnostic(diagnostics, string(scanner.ArtifactReasonUnreadable), diagnosticPath(root, path, inputIndex, cfg.PathMode), "")
		return nil, nil
	}
	artifact, ok := scanner.ClassifyPrefix(ctx, path, prefix(data), scanner.Config{
		MaxFileSize:    cfg.MaxFileSize,
		EnableGPG:      cfg.EnableGPG,
		EnableSSH:      cfg.EnableSSH,
		EnableMinisign: cfg.EnableMini,
	})
	if !ok {
		return nil, nil
	}
	if !matchesKindClass(artifact, cfg) {
		return nil, nil
	}
	record := recordFromArtifact(source, artifact)
	return applyFingerprints(ctx, path, record, data, cfg), nil
}

func recordFromArtifact(source pathSource, artifact scanner.Artifact) Record {
	record := Record{
		SchemaVersion: SchemaVersion,
		Kind:          artifact.Kind,
		Class:         artifact.Class,
		Confidence:    artifact.Confidence,
		Reason:        artifact.Reason,
		source:        source,
	}
	switch artifact.Kind {
	case scanner.ArtifactKindSSH:
		record.Algorithm = "sha256"
		record.FingerprintScheme = SchemeSSHPublicBlobSHA256
	case scanner.ArtifactKindMinisign:
		record.Algorithm = "minisign-key-id"
		record.FingerprintScheme = SchemeMinisignKeyID
	case scanner.ArtifactKindGPG:
		record.Algorithm = "openpgp-fingerprint"
		record.FingerprintScheme = SchemeGPGOpenPGPFingerprint
	}
	if record.Reason == "" && artifact.Class == scanner.ArtifactClassOther {
		record.Reason = scanner.ArtifactReasonUnsupportedKind
	}
	return record
}

func applyFingerprints(ctx context.Context, path string, record Record, data []byte, cfg Config) []Record {
	switch record.Kind {
	case scanner.ArtifactKindSSH:
		blob, encrypted, ok := sshPublicBlob(data)
		if encrypted {
			record.Reason = scanner.ArtifactReasonEncryptedPrivateNoPublicCounterpart
			return []Record{record}
		}
		if !ok {
			record.Reason = scanner.ArtifactReasonParseUnsupported
			return []Record{record}
		}
		fingerprint := sshSHA256(blob)
		record.Fingerprint = &fingerprint
		record.Reason = ""
		return []Record{record}
	case scanner.ArtifactKindMinisign:
		if record.Class != scanner.ArtifactClassPublic {
			// Preserve classifier reasons (e.g. parse-unsupported on malformed
			// public markers); only default private material to the encrypted-
			// private reason when no reason was set.
			if record.Reason == "" {
				record.Reason = scanner.ArtifactReasonEncryptedPrivateNoPublicCounterpart
			}
			return []Record{record}
		}
		blob, ok := scanner.ParseMinisignPublicKeyFile(data)
		if !ok {
			record.Reason = scanner.ArtifactReasonParseUnsupported
			return []Record{record}
		}
		keyID := minisignKeyID(blob)
		record.KeyID = keyID
		fingerprint := keyID
		record.Fingerprint = &fingerprint
		record.Reason = ""

		blobRecord := record
		blobRecord.Algorithm = "sha256"
		blobRecord.FingerprintScheme = SchemeMinisignPublicBlobSHA256
		blobFingerprint := minisignPublicBlobSHA256(blob)
		blobRecord.Fingerprint = &blobFingerprint
		return []Record{record, blobRecord}
	case scanner.ArtifactKindGPG:
		// DDR-0001: class "other" (revocation certs, encrypted containers,
		// keyring internals, …) has no safe fingerprint scheme. Short-circuit
		// before the helper so a present gpg that rejects revocation-only
		// import is not mislabeled helper-unavailable.
		if record.Class == scanner.ArtifactClassOther || record.Reason == scanner.ArtifactReasonUnsupportedKind {
			if record.Reason == "" {
				record.Reason = scanner.ArtifactReasonUnsupportedKind
			}
			return []Record{record}
		}
		fingerprints, reason := openPGPFingerprints(ctx, path, cfg.GPGTimeout)
		if reason != "" {
			record.Reason = reason
			return []Record{record}
		}
		records := make([]Record, 0, len(fingerprints))
		for _, value := range fingerprints {
			next := record
			next.Reason = ""
			fingerprint := value
			next.Fingerprint = &fingerprint
			records = append(records, next)
		}
		return records
	default:
		record.Reason = scanner.ArtifactReasonUnsupportedKind
		return []Record{record}
	}
}

// openPGPFingerprints runs an isolated gpg dry-run import.
// On failure it returns a DDR-0001 reason:
//   - helper-unavailable: gpg missing from PATH, not startable, temp home setup
//     failed, or timeout (no material parse occurred)
//   - parse-unsupported: a started gpg process rejected the material or emitted
//     no usable fingerprint (ExitError path)
func openPGPFingerprints(ctx context.Context, path string, timeout time.Duration) ([]string, scanner.ArtifactReason) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		return nil, scanner.ArtifactReasonHelperUnavailable
	}
	home, err := os.MkdirTemp("", "decernor-gpg-fp-")
	if err != nil {
		return nil, scanner.ArtifactReasonHelperUnavailable
	}
	defer func() {
		_ = os.RemoveAll(home)
	}()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Isolated helper home only — never the operator default keyring.
	// Use the resolved LookPath result so PATH is not re-resolved at exec time.
	cmd := exec.CommandContext(ctx, gpgPath, "--batch", "--no-tty", "--homedir", home, "--with-colons", "--import-options", "show-only", "--dry-run", "--import", path)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, scanner.ArtifactReasonHelperUnavailable
		}
		// A process that actually started and exited nonzero is a parse/reject.
		// Start/setup failures (invalid image, permission, disappeared binary)
		// are helper-unavailable — no material parse occurred.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, scanner.ArtifactReasonParseUnsupported
		}
		return nil, scanner.ArtifactReasonHelperUnavailable
	}
	seen := map[string]bool{}
	var fingerprints []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			value := strings.ToUpper(strings.TrimSpace(fields[9]))
			if isHexFingerprint(value) && !seen[value] {
				seen[value] = true
				fingerprints = append(fingerprints, value)
			}
		}
	}
	if len(fingerprints) == 0 {
		return nil, scanner.ArtifactReasonParseUnsupported
	}
	return fingerprints, ""
}

func isHexFingerprint(value string) bool {
	if len(value) < 32 {
		return false
	}
	for _, r := range value {
		if r >= '0' && r <= '9' || r >= 'A' && r <= 'F' {
			continue
		}
		return false
	}
	return true
}

func sshPublicBlob(data []byte) ([]byte, bool, bool) {
	line := firstNonEmptyLine(string(data))
	fields := strings.Fields(line)
	if len(fields) >= 2 && (strings.HasPrefix(fields[0], "ssh-") || strings.HasPrefix(fields[0], "ecdsa-") || strings.HasPrefix(fields[0], "sk-")) {
		blob, err := base64.StdEncoding.DecodeString(fields[1])
		return blob, false, err == nil && len(blob) > 0
	}
	blob, encrypted, ok := openSSHPrivatePublicBlob(data)
	return blob, encrypted, ok
}

func openSSHPrivatePublicBlob(data []byte) ([]byte, bool, bool) {
	text := string(data)
	begin := "-----" + strings.Join([]string{"BEGIN", "OPENSSH", "PRIVATE", "KEY"}, " ") + "-----"
	end := "-----" + strings.Join([]string{"END", "OPENSSH", "PRIVATE", "KEY"}, " ") + "-----"
	start := strings.Index(text, begin)
	stop := strings.Index(text, end)
	if start < 0 || stop <= start {
		return nil, false, false
	}
	body := text[start+len(begin) : stop]
	var encoded strings.Builder
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, ":") {
			continue
		}
		encoded.WriteString(line)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil || !bytes.HasPrefix(decoded, []byte("openssh-key-v1\x00")) {
		return nil, false, false
	}
	reader := bytes.NewReader(decoded[len("openssh-key-v1\x00"):])
	cipher, ok := readSSHString(reader)
	if !ok {
		return nil, false, false
	}
	_, ok = readSSHString(reader)
	if !ok {
		return nil, false, false
	}
	_, ok = readSSHString(reader)
	if !ok {
		return nil, false, false
	}
	nkeys, ok := readUint32(reader)
	if !ok || nkeys == 0 {
		return nil, false, false
	}
	blob, ok := readSSHString(reader)
	if !ok {
		return nil, false, false
	}
	return blob, string(cipher) != "none", true
}

func readSSHString(reader *bytes.Reader) ([]byte, bool) {
	n, ok := readUint32(reader)
	if !ok || n > uint32(reader.Len()) {
		return nil, false
	}
	out := make([]byte, n)
	_, err := io.ReadFull(reader, out)
	return out, err == nil
}

func readUint32(reader *bytes.Reader) (uint32, bool) {
	var raw [4]byte
	_, err := io.ReadFull(reader, raw[:])
	if err != nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(raw[:]), true
}

func sshSHA256(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func minisignKeyID(blob []byte) string {
	return strings.ToUpper(hex.EncodeToString(blob[2:10]))
}

func minisignPublicBlobSHA256(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func firstNonEmptyLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func prefix(data []byte) []byte {
	if len(data) <= 32*1024 {
		return data
	}
	return data[:32*1024]
}

func sourceForPath(root string, path string, inputIndex int) pathSource {
	relPath := relativePath(root, path)
	return pathSource{
		InputIndex: inputIndex,
		RelPath:    relPath,
		Basename:   filepath.Base(relPath),
		Hash:       pathHash(inputIndex, relPath),
	}
}

func relativePath(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(filepath.Base(path))
	}
	if rel == "." {
		return filepath.ToSlash(filepath.Base(path))
	}
	return filepath.ToSlash(rel)
}

func pathHash(inputIndex int, relPath string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s", inputIndex, relPath)))
	return hex.EncodeToString(sum[:16])
}

func applyRecordPaths(records []Record, mode PathMode) error {
	if mode == "" {
		mode = PathModeRelative
	}
	switch mode {
	case PathModeHash:
		for i := range records {
			records[i].Path = records[i].source.Hash
		}
	case PathModeNone:
		for i := range records {
			records[i].Path = ""
		}
	case PathModeRelative:
		for i := range records {
			records[i].Path = records[i].source.RelPath
		}
	default:
		return fmt.Errorf("unsupported path_mode %q", mode)
	}
	return nil
}

func diagnosticPath(root string, path string, inputIndex int, mode PathMode) string {
	source := sourceForPath(root, path, inputIndex)
	switch mode {
	case PathModeNone:
		return ""
	case PathModeHash:
		return source.Hash
	case PathModeRelative:
		return source.RelPath
	default:
		return source.Basename
	}
}

func matchesFilters(path string, includes []string, excludes []string) bool {
	if len(includes) > 0 {
		matched := false
		for _, pattern := range includes {
			if globMatch(pattern, path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, pattern := range excludes {
		if globMatch(pattern, path) {
			return false
		}
	}
	return true
}

func globMatch(pattern string, path string) bool {
	pattern = filepath.ToSlash(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	ok, err := doublestar.PathMatch(pattern, path)
	return err == nil && ok
}

func matchesKindClass(artifact scanner.Artifact, cfg Config) bool {
	if len(cfg.Kinds) > 0 && !cfg.Kinds[artifact.Kind] {
		return false
	}
	if len(cfg.Classes) > 0 && !cfg.Classes[artifact.Class] {
		return false
	}
	return true
}

func writeDiagnostic(w io.Writer, code string, path string, target string) {
	if w == nil {
		return
	}
	if target == "" {
		_, _ = fmt.Fprintf(w, "diagnostic=%s path=%s\n", code, path)
		return
	}
	_, _ = fmt.Fprintf(w, "diagnostic=%s path=%s target=%s\n", code, path, target)
}

func sortRecords(records []Record) {
	sort.SliceStable(records, func(i, j int) bool {
		a := records[i]
		b := records[j]
		if a.source.RelPath != b.source.RelPath {
			return a.source.RelPath < b.source.RelPath
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		if a.FingerprintScheme != b.FingerprintScheme {
			return a.FingerprintScheme < b.FingerprintScheme
		}
		aID := recordSortID(a)
		bID := recordSortID(b)
		return aID < bID
	})
}

func recordSortID(record Record) string {
	if record.KeyID != "" {
		return record.KeyID
	}
	if record.Fingerprint != nil {
		return *record.Fingerprint
	}
	return string(record.Reason)
}
