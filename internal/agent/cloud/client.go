package cloud

import (
	"net/http"
	"time"
)

type ClientConfig struct {
	APIEndpoint      string
	RealtimeEndpoint string
	Token            string
	Platform         string
	Version          string
}

type Client struct {
	httpClient       *http.Client
	apiEndpoint      string
	realtimeEndpoint string
	token            string
	platform         string
	version          string
}

func NewClient(cfg *ClientConfig) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiEndpoint:      cfg.APIEndpoint,
		realtimeEndpoint: cfg.RealtimeEndpoint,
		token:            cfg.Token,
		platform:         cfg.Platform,
		version:          cfg.Version,
	}
}
