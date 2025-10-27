package cloud

import (
	"net/http"
	"time"
)

type ClientConfig struct {
	APIEndpoint    string
	ConfigEndpoint string
	Token          string
}

type Client struct {
	httpClient     *http.Client
	apiEndpoint    string
	configEndpoint string
	token          string
}

func NewClient(cfg *ClientConfig) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiEndpoint:    cfg.APIEndpoint,
		configEndpoint: cfg.ConfigEndpoint,
		token:          cfg.Token,
	}
}
