package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/fulmenhq/gofulmen/logging"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// LoadConfig loads the layered configuration for the application.
// For microtools, config is optional - we provide simple defaults and env var support.
func LoadConfig(ctx context.Context, identity *appidentity.Identity, logger *logging.Logger) (*DecernorConfig, error) {
	// Default config
	cfg := &DecernorConfig{
		InputPath:  ".",
		OutputPath: "./output",
		MaxDepth:   10,
	}

	// Try to load user config file if it exists
	configPath := defaultConfigPath(identity)
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}

		logger.Info("loaded config from file", zap.String("path", configPath))
	}

	// Env var overrides
	if envInput := os.Getenv(identity.EnvPrefix + "INPUT_PATH"); envInput != "" {
		cfg.InputPath = envInput
	}
	if envOutput := os.Getenv(identity.EnvPrefix + "OUTPUT_PATH"); envOutput != "" {
		cfg.OutputPath = envOutput
	}

	logger.Info("configuration loaded successfully")
	return cfg, nil
}

// defaultConfigPath returns the default config file path for the application
func defaultConfigPath(identity *appidentity.Identity) string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".config", identity.Vendor, identity.ConfigName+".yaml")
}
