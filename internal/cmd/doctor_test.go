package cmd

import (
	"context"
	"testing"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/fulmenhq/gofulmen/logging"

	"github.com/3leaps/decernor/internal/config"
)

func TestDoctorCommand_Succeeds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

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

	cmd := newDoctorCmd(identity)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("doctor command returned error: %v", err)
	}
}
