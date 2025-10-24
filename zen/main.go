// Package zen provides the main API for firewall-go, including user management,
// request blocking, and middleware integration for Go applications.
package zen

import (
	"os"
	"runtime"

	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
)

// Protect initializes and starts the firewall background process.
// This function must be called early in the application lifecycle to enable
// request monitoring and protection features.
func Protect() error {
	logLevel := "DEBUG"
	if err := log.SetLogLevel(logLevel); err != nil {
		return err
	}

	config.CollectAPISchema = true

	token := os.Getenv("AIKIDO_TOKEN")
	endpoint := os.Getenv("AIKIDO_ENDPOINT")
	configEndpoint := os.Getenv("AIKIDO_REALTIME_ENDPOINT")

	err := initAgent(config.CollectAPISchema, logLevel, token, endpoint, configEndpoint)
	if err != nil {
		return err
	}

	internal.Init()

	return nil
}

func initAgent(collectAPISchema bool, logLevel string, token string, endpoint string, configEndpoint string) error {
	environmentConfig := &aikido_types.EnvironmentConfigData{
		PlatformName:    "golang",
		PlatformVersion: runtime.Version(),
		Library:         "firewall-go",
		Endpoint:        endpoint,
		ConfigEndpoint:  configEndpoint,
		Version:         config.Version, // firewall-go version
	}
	aikidoConfig := &aikido_types.AikidoConfigData{
		LogLevel:         logLevel,
		Token:            token,
		CollectAPISchema: collectAPISchema,
	}

	go agent.Init(environmentConfig, aikidoConfig)
	return nil
}
