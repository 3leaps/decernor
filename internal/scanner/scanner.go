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
			if artifact, ok := keyringInternalArtifact(path, entry.IsDir()); ok {
				result.AddFinding(artifact.Finding())
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
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

func classifyPrefixWithPacketLister(ctx context.Context, path string, prefix []byte, cfg Config, lister packetLister) (Artifact, bool) {
	if cfg.GPGTimeout <= 0 {
		cfg.GPGTimeout = 10 * time.Second
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
