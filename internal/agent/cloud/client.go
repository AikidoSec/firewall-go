package cloud

import (
	"net/http"
	"time"
)

type ClientConfig struct {
	APIEndpoint      string
	RealtimeEndpoint string
	Token            string
}

type Client struct {
	httpClient       *http.Client
	apiEndpoint      string
	realtimeEndpoint string
	token            string
}

func NewClient(cfg *ClientConfig) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiEndpoint:      cfg.APIEndpoint,
		realtimeEndpoint: cfg.RealtimeEndpoint,
		token:            cfg.Token,
	}
}
