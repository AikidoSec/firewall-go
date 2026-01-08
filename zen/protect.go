// Package zen provides the main API for firewall-go, including user management,
// request blocking, and middleware integration for Go applications.
package zen

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
)

// AttackKind represents the type of attack that was detected.
type AttackKind string

const (
	// KindSQLInjection indicates a SQL injection attack was detected.
	KindSQLInjection AttackKind = "sql_injection"
	// KindPathTraversal indicates a path traversal attack was detected.
	KindPathTraversal AttackKind = "path_traversal"
	// KindShellInjection indicates a shell injection attack was detected.
	KindShellInjection AttackKind = "shell_injection"
	// KindSSRF indicates a server-side request forgery attack was detected.
	KindSSRF AttackKind = "ssrf"
)

// AttackBlockedError represents an error when an attack is blocked by Zen.
type AttackBlockedError struct {
	Kind AttackKind
}

func (e *AttackBlockedError) Error() string {
	return fmt.Sprintf("zen blocked %s attack", e.Kind)
}

// ErrAttackBlocked returns an error indicating that an attack was blocked.
// The error includes the attack type and can be checked using errors.As
// with *AttackBlockedError to extract the attack kind.
func ErrAttackBlocked(kind vulnerabilities.AttackKind) error {
	return &AttackBlockedError{Kind: AttackKind(kind)}
}

var (
	protectOnce sync.Once
	protectErr  error
)

func init() {
	// Initialize the disabled flag at package load time, before Protect is called.
	// This early initialization is critical because:
	// 1. Instrumentation packages (sources/sinks) call IsDisabled() on every middleware/examine call
	// 	  to short-circuit when disabled
	// 2. When disabled, ProtectWithConfig returns early before initializing the cloud client,
	//    agent infrastructure, and logging
	config.SetZenDisabled(getEnvBool("AIKIDO_DISABLE"))
}

// SetDisabled controls whether Zen firewall processing is enabled or disabled.
// When disabled is true, all Zen security checks are bypassed, including instrumentation
// and middleware processing. This overrides the AIKIDO_DISABLE environment variable.
//
// This is commonly used in testing to verify application behavior with the firewall disabled.
func SetDisabled(disabled bool) {
	config.SetZenDisabled(disabled)
}

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
	// RealtimeEndpoint is the Aikido real-time config endpoint (default: https://runtime.aikido.dev/)
	RealtimeEndpoint string
	// Block will block any requests with suspected attacks
	// Once cloud config is retrieved, Zen will use the configured mode from the dashboard.
	Block bool
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
		if config.IsZenDisabled() {
			// Do not run any Zen features when the disabled flag is on
			return
		}
		doProtect(cfg)
	})

	return protectErr
}

// doProtect performs the actual initialization work for Protect.
// It configures logging, loads environment variables, and initializes
// the agent. This is separated from Protect to maintain thread-safety
// with sync.Once while preserving readability.
func doProtect(cfg *Config) {
	internal.SetupTransits()

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

	err := initAgent(config.CollectAPISchema, logLevel, mergedCfg.Token, mergedCfg.Endpoint, mergedCfg.RealtimeEndpoint, mergedCfg.Block)
	if err != nil {
		protectErr = err
		return
	}

	err = internal.Init()
	if err != nil {
		protectErr = err
		return
	}

	log.Info("Aikido Zen loaded!",
		slog.String("version", globals.EnvironmentConfig.Version))
}

func initAgent(collectAPISchema bool, logLevel string, token string, endpoint string, realtimeEndpoint string, block bool) error {
	environmentConfig := &aikido_types.EnvironmentConfigData{
		PlatformName:     "golang",
		PlatformVersion:  runtime.Version(),
		Library:          "firewall-go",
		Endpoint:         endpoint,
		RealtimeEndpoint: realtimeEndpoint,
		Version:          config.Version, // firewall-go version
	}
	aikidoConfig := &aikido_types.AikidoConfigData{
		LogLevel:         logLevel,
		Token:            token,
		CollectAPISchema: collectAPISchema,
		Blocking:         block,
	}

	return agent.Init(environmentConfig, aikidoConfig)
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
		result.Debug = getEnvBool("AIKIDO_DEBUG")
	}
	if !result.Block {
		result.Block = getEnvBool("AIKIDO_BLOCK")
	}
	if result.Token == "" {
		result.Token = os.Getenv("AIKIDO_TOKEN")
	}
	if result.Endpoint == "" {
		result.Endpoint = os.Getenv("AIKIDO_ENDPOINT")
	}
	if result.RealtimeEndpoint == "" {
		result.RealtimeEndpoint = os.Getenv("AIKIDO_REALTIME_ENDPOINT")
	}

	return &result
}

func getEnvBool(name string) bool {
	v := strings.ToLower(os.Getenv(name))
	return v == "true" || v == "1"
}

// IsDisabled returns true if Zen firewall processing is currently disabled.
// The disabled state is determined by the AIKIDO_DISABLE environment variable at startup.
func IsDisabled() bool {
	return config.IsZenDisabled()
}
