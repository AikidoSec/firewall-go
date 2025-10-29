package config

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/log"
)

const (
	GuardEndpointEU = "https://guard.aikido.dev/"
	GuardEndpointUS = "https://guard.us.aikido.dev/"
	GuardEndpointME = "https://guard.me.aikido.dev/"
	RuntimeEndpoint = "https://runtime.aikido.dev/"
)

// extractRegionFromToken extracts the region from an Aikido token.
// New format: AIK_RUNTIME_{sys_group_id}_{service_id}_{region}_{random}
// Old format: AIK_RUNTIME_{sys_group_id}_{service_id}_{random}
// Returns "EU" by default for old format or invalid tokens.
func extractRegionFromToken(token string) string {
	if token == "" || !strings.HasPrefix(token, "AIK_RUNTIME_") {
		return "EU"
	}

	tokenWithoutPrefix := strings.TrimPrefix(token, "AIK_RUNTIME_")
	parts := strings.Split(tokenWithoutPrefix, "_")

	// New format has 4 parts, region is at index 2
	if len(parts) == 4 {
		return parts[2]
	}

	return "EU"
}

// getEndpointURL returns the appropriate endpoint URL based on the region extracted from the token.
func getEndpointURL(token string) string {
	region := extractRegionFromToken(token)

	switch region {
	case "US":
		return GuardEndpointUS
	case "ME":
		return GuardEndpointME
	default:
		return GuardEndpointEU
	}
}

func Init(environmentConfig *aikido_types.EnvironmentConfigData, aikidoConfig *aikido_types.AikidoConfigData) bool {
	globals.EnvironmentConfig = environmentConfig
	globals.AikidoConfig = aikidoConfig

	if globals.AikidoConfig.LogLevel != "" {
		if err := log.SetLogLevel(globals.AikidoConfig.LogLevel); err != nil {
			panic(fmt.Sprintf("Error setting log level: %s", err))
		}
	}

	if globals.EnvironmentConfig.Endpoint == "" {
		globals.EnvironmentConfig.Endpoint = getEndpointURL(aikidoConfig.Token)
	}

	if globals.EnvironmentConfig.RealtimeEndpoint == "" {
		globals.EnvironmentConfig.RealtimeEndpoint = RuntimeEndpoint
	}

	log.Info("Loaded local config", slog.Any("config", globals.EnvironmentConfig))

	if globals.AikidoConfig.Token == "" {
		log.Info("No token set!")
	}

	return true
}

func Uninit() {}

func IsBlockingEnabled() bool {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	return serviceConfig.Block
}
