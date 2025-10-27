// Package zen provides the main API for firewall-go, including user management,
// request blocking, and middleware integration for Go applications.
package zen

import (
	"log/slog"
	"os"
	"runtime"
	"sync"

	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
)

var (
	protectOnce sync.Once
	protectErr  error
)

// Config holds configuration options for the Zen firewall
type Config struct {
	// LogLevel sets the logging level (DEBUG, INFO, WARN, ERROR)
	LogLevel string
	// LogFormat sets the logging format (text, json)
	LogFormat string
	// Logger provides a custom slog instance that overrrides LogLevel and LogFormat
	Logger *slog.Logger
	// Debug enables debug logging (overrides LogLevel)
	Debug bool
	// Token is the Aikido API token
	Token string
	// Endpoint is the Aikido API endpoint
	Endpoint string
	// ConfigEndpoint is the Aikido real-time config endpoint
	ConfigEndpoint string
}

// Protect initializes and starts the firewall background process.
// This function must be called early in the application lifecycle to enable
// request monitoring and protection features.
func Protect() error {
	return ProtectWithConfig(nil)
}

// ProtectWithConfig initializes the Aikido firewall with explicit configuration.
// Empty config fields fall back to environment variables.
func ProtectWithConfig(cfg *Config) error {
	protectOnce.Do(func() {
		doProtect(cfg)
	})

	return protectErr
}

// doProtect performs the actual initialization work for Protect.
// It configures logging, loads environment variables, and initializes
// the agent. This is separated from Protect to maintain thread-safety
// with sync.Once while preserving readability.
func doProtect(cfg *Config) {
	// Fallback to environment variables for empty config fields
	mergedCfg := populateConfigFromEnv(cfg)

	// Logger configuration
	logLevel := mergedCfg.LogLevel
	if logLevel == "" {
		logLevel = "INFO" // fallback to default
	}

	// Debug takes precedence over LogLevel
	if mergedCfg.Debug {
		logLevel = "DEBUG"
	}

	if err := log.SetLogLevel(logLevel); err != nil {
		protectErr = err
		return
	}

	if mergedCfg.LogFormat != "" {
		if err := log.SetFormat(mergedCfg.LogFormat); err != nil {
			protectErr = err
			return
		}
	}

	if mergedCfg.Logger != nil {
		log.SetLogger(mergedCfg.Logger)
	}

	config.CollectAPISchema = true

	err := initAgent(config.CollectAPISchema, logLevel, mergedCfg.Token, mergedCfg.Endpoint, mergedCfg.ConfigEndpoint)
	if err != nil {
		protectErr = err
		return
	}

	internal.Init()
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

// populateConfigFromEnv fills zero-value config fields from environment variables.
// Config values take precedence over env vars. Returns a new Config without modifying the input.
func populateConfigFromEnv(cfg *Config) *Config {
	// Start with empty config if nil, otherwise copy the input
	result := Config{}
	if cfg != nil {
		result = *cfg
	}

	if result.LogLevel == "" {
		result.LogLevel = os.Getenv("AIKIDO_LOG_LEVEL")
	}
	if result.LogFormat == "" {
		result.LogFormat = os.Getenv("AIKIDO_LOG_FORMAT")
	}
	if !result.Debug {
		result.Debug = os.Getenv("AIKIDO_DEBUG") == "true"
	}
	if result.Token == "" {
		result.Token = os.Getenv("AIKIDO_TOKEN")
	}
	if result.Endpoint == "" {
		result.Endpoint = os.Getenv("AIKIDO_ENDPOINT")
	}
	if result.ConfigEndpoint == "" {
		result.ConfigEndpoint = os.Getenv("AIKIDO_REALTIME_ENDPOINT")
	}

	return &result
}
