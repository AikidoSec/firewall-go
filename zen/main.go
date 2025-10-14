package zen

// This is the main module users will interact with : SetUser, ShouldBlockRequest, middleware, ...

import (
	"os"
	"runtime"

	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
)

// Init needs to be called in the user's app to start the background process
func Init() error {
	// Logger :
	logLevel := "DEBUG"
	log.Init()
	log.SetLogLevel(logLevel)

	config.CollectAPISchema = true

	// Agent Config :
	token := os.Getenv("AIKIDO_TOKEN")

	err := initAgent(config.CollectAPISchema, logLevel, token)
	if err != nil {
		return err
	}

	internal.Init()

	return nil
}

func initAgent(collectAPISchema bool, logLevel string, token string) error {
	environmentConfig := &aikido_types.EnvironmentConfigData{
		PlatformName:    "golang",
		PlatformVersion: runtime.Version(),
		Library:         "firewall-go",
		Endpoint:        "https://guard.aikido.dev/",
		ConfigEndpoint:  "https://runtime.aikido.dev/",
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
