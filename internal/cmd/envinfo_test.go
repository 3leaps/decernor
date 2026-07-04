package cmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/fulmenhq/gofulmen/logging"

	"github.com/3leaps/decernor/internal/config"
)

func TestEnvinfoCommand_Executes(t *testing.T) {
	identity := &appidentity.Identity{
		BinaryName:  "decernor",
		Vendor:      "3leaps",
		EnvPrefix:   "DECERNOR_",
		ConfigName:  "decernor",
		Description: "Test tool",
	}
	logger, err := logging.NewCLI(identity.BinaryName)
	if err != nil {
		t.Fatalf("logger init failed: %v", err)
	}
	cfg := &config.DecernorConfig{}
	Initialize(context.Background(), identity, logger, cfg)

	cmd := newEnvinfoCmd(identity)
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("envinfo command returned error: %v", err)
	}
}
