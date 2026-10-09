package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const prefixBytes = 32 * 1024

func Scan(ctx context.Context, root string, cfg Config) (Result, error) {
	return scanWithPacketLister(ctx, root, cfg, gpgPacketLister{})
}

func scanWithPacketLister(ctx context.Context, root string, cfg Config, lister packetLister) (Result, error) {
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 25 * 1024 * 1024
	}
	if cfg.GPGTimeout <= 0 {
		cfg.GPGTimeout = 10 * time.Second
	}
	if cfg.Profile == "" {
		cfg.Profile = ProfileArtifact
	}
	if !cfg.EnableGPG && !cfg.EnableSSH && !cfg.EnableMinisign {
		cfg.EnableGPG = true
		cfg.EnableSSH = true
		cfg.EnableMinisign = true
	}

	result := Result{
		Root:      root,
		Profile:   cfg.Profile,
		Findings:  []Finding{},
		StartedAt: time.Now().UTC(),
	}
	finish := func(err error) (Result, error) {
		result.EndedAt = time.Now().UTC()
		return result, err
	}

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			result.AddFinding(Finding{
				Path:           path,
				Code:           "SCAN-PATH-ERROR",
				Priority:       PriorityP4,
				Classification: ClassParseError,
				Severity:       SeverityWarn,
				Retention:      RetentionInspectManually,
				Exposure:       ExposureUnknown,
				Confidence:     ConfidenceLow,
				Evidence:       walkErr.Error(),
				Recommendation: "Verify file permissions and rerun the scan.",
			})
			return nil
		}

		if cfg.EnableGPG {
			if artifact, ok := keyringInternalArtifact(path, entry.IsDir(), cfg.Profile); ok {
				result.AddFinding(artifact.Finding())
				if !entry.IsDir() {
					// A name-matched file is still checked by content, so a
					// lenient profile cannot clear key material by name.
					// Packet listing is skipped: keyring databases are not
					// OpenPGP packet streams.
					if artifact.Classification == ClassKeyringInternal && artifact.Finding().Code != "GPG-KEYRING-SECRET-FILE" {
						if content, ok := classifyKeyringFileContent(path, cfg); ok {
							result.AddFinding(content.Finding())
						}
					}
					return nil
				}
			}
		}

		if entry.IsDir() {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			result.AddFinding(Finding{
				Path:           path,
				Code:           "SCAN-METADATA-ERROR",
				Priority:       PriorityP4,
				Classification: ClassParseError,
				Severity:       SeverityWarn,
				Retention:      RetentionInspectManually,
				Exposure:       ExposureUnknown,
				Confidence:     ConfidenceLow,
				Evidence:       err.Error(),
				Recommendation: "Verify file metadata and rerun the scan.",
			})
			return nil
		}
		if !info.Mode().IsRegular() {
			result.Skipped++
			return nil
		}
		if info.Size() > cfg.MaxFileSize {
			result.Skipped++
			result.AddFinding(Finding{
				Path:           path,
				Code:           "SCAN-FILE-TOO-LARGE",
				Priority:       PriorityP4,
				Classification: ClassSkipped,
				Severity:       SeverityWarn,
				Retention:      RetentionInspectManually,
				Exposure:       ExposureUnknown,
				Confidence:     ConfidenceLow,
				Evidence:       fmt.Sprintf("file size %d exceeds max %d", info.Size(), cfg.MaxFileSize),
				Recommendation: "Increase --max-file-size or inspect manually if this may contain key material.",
			})
			return nil
		}

		result.Scanned++
		prefix, err := readPrefix(path, prefixBytes)
		if err != nil {
			result.AddFinding(Finding{
				Path:           path,
				Code:           "SCAN-READ-ERROR",
				Priority:       PriorityP4,
				Classification: ClassParseError,
				Severity:       SeverityWarn,
				Retention:      RetentionInspectManually,
				Exposure:       ExposureUnknown,
				Confidence:     ConfidenceLow,
				Evidence:       err.Error(),
				Recommendation: "Verify file permissions and rerun the scan.",
			})
			return nil
		}

		// A file larger than the prefix could hide an agent key past it.
		// Classify on full (size-bounded) content when the path or prefix
		// says agent key, or when an agent-key token appears anywhere.
		if cfg.EnableGPG && info.Size() > int64(len(prefix)) {
			full, err := readBounded(path, cfg.MaxFileSize)
			if err != nil {
				result.AddFinding(Finding{
					Path:           path,
					Code:           "SCAN-READ-ERROR",
					Priority:       PriorityP4,
					Classification: ClassParseError,
					Severity:       SeverityWarn,
					Retention:      RetentionInspectManually,
					Exposure:       ExposureUnknown,
					Confidence:     ConfidenceLow,
					Evidence:       err.Error(),
					Recommendation: "Verify file permissions and rerun the scan.",
				})
				return nil
			}
			if isAgentKeyPath(path) || agentKeyFormFor(prefix) != agentKeyFormNone || agentKeyTokenCount(full) > 0 {
				prefix = full
			}
		}

		if cfg.EnableGPG && looksOpenPGP(path, prefix) {
			packets, err := lister.ListPackets(ctx, path, cfg.GPGTimeout)
			if err == nil {
				if artifact, ok := classifyPacketArtifact(path, packets, cfg.AllowProtectedSecretKeys); ok {
					result.AddFinding(artifact.Finding())
					return nil
				}
			}

			if artifact, ok := classifyHeaderArtifact(path, prefix, cfg); ok {
				result.AddFinding(artifact.Finding())
				return nil
			}
			if err != nil {
				result.AddFinding(Finding{
					Path:           path,
					Code:           "GPG-PACKET-PARSE-ERROR",
					Priority:       PriorityP3,
					Classification: ClassParseError,
					Severity:       SeverityWarn,
					Retention:      RetentionInspectManually,
					Exposure:       ExposureUnknown,
					Confidence:     ConfidenceLow,
					Evidence:       "gpg packet parsing failed for OpenPGP-looking file",
					Recommendation: "Inspect manually with gpg --batch --list-packets.",
				})
			}
			return nil
		}

		if artifact, ok := classifyHeaderArtifact(path, prefix, cfg); ok {
			result.AddFinding(artifact.Finding())
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return finish(err)
	}
	return finish(err)
}

func ClassifyPrefix(ctx context.Context, path string, prefix []byte, cfg Config) (Artifact, bool) {
	return classifyPrefixWithPacketLister(ctx, path, prefix, cfg, gpgPacketLister{})
}

func ClassifyBuffer(ctx context.Context, path string, data []byte, cfg Config) (Artifact, bool) {
	return classifyBufferWithPacketLister(ctx, path, data, cfg, gpgPacketLister{})
}

// ClassifyCaptured inspects a single captured buffer. Its OpenPGP packet
// helper receives these bytes on stdin and never reopens the named input.
func ClassifyCaptured(ctx context.Context, name string, data []byte, cfg Config) (Artifact, bool) {
	return classifyBufferWithPacketLister(ctx, name, data, cfg, capturedPacketLister{data: data})
}

func classifyPrefixWithPacketLister(ctx context.Context, path string, prefix []byte, cfg Config, lister packetLister) (Artifact, bool) {
	if cfg.GPGTimeout <= 0 {
		cfg.GPGTimeout = 10 * time.Second
	}
	if cfg.Profile == "" {
		cfg.Profile = ProfileArtifact
	}
	if !cfg.EnableGPG && !cfg.EnableSSH && !cfg.EnableMinisign {
		cfg.EnableGPG = true
		cfg.EnableSSH = true
		cfg.EnableMinisign = true
	}
	if cfg.EnableGPG && looksOpenPGP(path, prefix) {
		packets, err := lister.ListPackets(ctx, path, cfg.GPGTimeout)
		if err == nil {
			if artifact, ok := classifyPacketArtifact(path, packets, cfg.AllowProtectedSecretKeys); ok {
				return artifact, true
			}
		}
	}
	return classifyHeaderArtifact(path, prefix, cfg)
}

func classifyBufferWithPacketLister(ctx context.Context, path string, data []byte, cfg Config, lister packetLister) (Artifact, bool) {
	if artifact, ok := classifyPrefixWithPacketLister(ctx, path, data, cfg, lister); ok {
		return artifact, true
	}
	if !cfg.EnableSSH {
		return Artifact{}, false
	}
	return classifyEmbeddedSSHPublicKey(path, data)
}

func readPrefix(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	buf := make([]byte, limit)
	n, err := io.ReadFull(file, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

func classifyKeyringFileContent(path string, cfg Config) (Artifact, bool) {
	data, err := readBounded(path, cfg.MaxFileSize)
	if err != nil {
		return Artifact{}, false
	}
	return classifyHeaderArtifact(path, data, cfg)
}

// readBounded reads at most limit bytes without preallocating the limit.
func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	return io.ReadAll(io.LimitReader(file, limit))
}
