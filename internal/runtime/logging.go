package runtime

import (
	"fmt"
	"os"

	"github.com/fulmenhq/gofulmen/appidentity"
	"github.com/fulmenhq/gofulmen/foundry"
	"github.com/fulmenhq/gofulmen/logging"
)

// SetupLogging creates a CLI logger using the app identity.
func SetupLogging(identity *appidentity.Identity) *logging.Logger {
	logger, err := logging.NewCLI(identity.BinaryName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(foundry.ExitConfigInvalid)
	}
	logger.SetLevel(logging.NONE)
	return logger
}
