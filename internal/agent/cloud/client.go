package cloud

import (
	"net/http"
	"time"
)

const unknownHeaderValue = "unknown"

type ClientConfig struct {
	APIEndpoint string
	Token       string
	Platform    string
	Version     string
	Hostname    string
	IPAddress   string
	SessionID   string
}

type Client struct {
	httpClient  *http.Client
	apiEndpoint string
	token       string
	platform    string
	version     string
	hostname    string
	ipAddress   string
	sessionID   string
}

func NewClient(cfg *ClientConfig) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiEndpoint: cfg.APIEndpoint,
		token:       cfg.Token,
		platform:    cfg.Platform,
		version:     cfg.Version,
		hostname:    cfg.Hostname,
		ipAddress:   cfg.IPAddress,
		sessionID:   cfg.SessionID,
	}
}

func (c *Client) setAgentHeaders(req *http.Request) {
	req.Header.Set("X-Agent-Platform", c.platform)
	req.Header.Set("X-Agent-Library", "firewall-go")
	req.Header.Set("X-Agent-Version", c.version)
	req.Header.Set("X-Agent-Hostname", valueOrUnknown(c.hostname))
	req.Header.Set("X-Agent-IP-Address", valueOrUnknown(c.ipAddress))
	req.Header.Set("X-Agent-Session-Id", c.sessionID)
}

func valueOrUnknown(v string) string {
	if v == "" {
		return unknownHeaderValue
	}
	return v
}
