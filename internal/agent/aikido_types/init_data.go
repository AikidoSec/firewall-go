package aikido_types

import (
	"sync"
	"time"
)

type EnvironmentConfigData struct {
	PlatformName     string // Platform name (fpm-fcgi, cli-server, ...)
	PlatformVersion  string // Language version
	Endpoint         string // default: 'https://guard.aikido.dev/'
	RealtimeEndpoint string // default: 'https://runtime.aikido.dev/'
	Library          string // default: 'firewall-php'
	Version          string // Version of the agent
	ZenDisabled      bool
}

type AikidoConfigData struct {
	ConfigMutex               sync.Mutex
	Token                     string `json:"token,omitempty"`                        // default: ''
	LogLevel                  string `json:"log_level,omitempty"`                    // default: 'INFO'
	Blocking                  bool   `json:"blocking,omitempty"`                     // default: false
	LocalhostAllowedByDefault bool   `json:"localhost_allowed_by_default,omitempty"` // default: true
	CollectAPISchema          bool   `json:"collect_api_schema,omitempty"`           // default: true
}

type RateLimiting struct {
	Enabled        bool `json:"enabled"`
	MaxRequests    int  `json:"maxRequests"`
	WindowSizeInMS int  `json:"windowSizeInMS"`
}

type Endpoint struct {
	Method             string       `json:"method"`
	Route              string       `json:"route"`
	ForceProtectionOff bool         `json:"forceProtectionOff"`
	Graphql            any          `json:"graphql"`
	AllowedIPAddresses []string     `json:"allowedIPAddresses"`
	RateLimiting       RateLimiting `json:"rateLimiting"`
}

type OutboundDomain struct {
	Hostname string `json:"hostname"`
	Mode     string `json:"mode"`
}

type CloudConfigData struct {
	Success                  bool             `json:"success"`
	ServiceID                int              `json:"serviceId"`
	ConfigUpdatedAt          int64            `json:"configUpdatedAt"`
	HeartbeatIntervalInMS    int              `json:"heartbeatIntervalInMS"`
	Endpoints                []Endpoint       `json:"endpoints"`
	BlockedUserIds           []string         `json:"blockedUserIds"`
	BypassedIPs              []string         `json:"allowedIPAddresses"`
	ReceivedAnyStats         bool             `json:"receivedAnyStats"`
	Block                    *bool            `json:"block,omitempty"`
	BlockNewOutgoingRequests bool             `json:"blockNewOutgoingRequests"`
	Domains                  []OutboundDomain `json:"domains"`
}

func (c *CloudConfigData) UpdatedAt() time.Time {
	return time.UnixMilli(c.ConfigUpdatedAt)
}

type IPList struct {
	Source      string   `json:"source"`
	Description string   `json:"description"`
	IPs         []string `json:"ips"`
}

type ListsConfigData struct {
	Success            bool     `json:"success"`
	ServiceID          int      `json:"serviceId"`
	BlockedIPAddresses []IPList `json:"blockedIPAddresses"`
	BlockedUserAgents  string   `json:"blockedUserAgents"`
	AllowedIPAddresses []IPList `json:"allowedIPAddresses"`
}

type CloudConfigUpdatedAt struct {
	ServiceID       int   `json:"serviceId"`
	ConfigUpdatedAt int64 `json:"configUpdatedAt"`
}
