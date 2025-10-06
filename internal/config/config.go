package config

import (
	"regexp"

	"github.com/AikidoSec/zen-internals-agent/aikido_types"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

var CollectAPISchema bool

type RateLimiting struct {
	Enabled        bool
	MaxRequests    int
	WindowSizeInMS int
}

type EndpointData struct {
	ForceProtectionOff bool
	RateLimiting       RateLimiting
	AllowedIPAddresses map[string]bool
}

type EndpointKey struct {
	Method string
	Route  string
}

type IPBlockList struct {
	Description string
	TrieV4      *ipaddr.IPv4AddressTrie
	TrieV6      *ipaddr.IPv6AddressTrie
}

type CloudConfigData struct {
	ConfigUpdatedAt   int64
	Endpoints         []aikido_types.Endpoint
	BlockedUserIDs    map[string]bool
	BypassedIps       map[string]bool
	BlockedIps        map[string]IPBlockList
	BlockedUserAgents *regexp.Regexp
	Block             int
}
