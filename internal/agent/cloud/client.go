package cloud

import (
	"net/http"
	"time"
)

type ClientConfig struct {
	APIEndpoint string
	Token       string
}

type Client struct {
	httpClient  *http.Client
	apiEndpoint string
	token       string
}

func NewClient(cfg *ClientConfig) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiEndpoint: cfg.APIEndpoint,
		token:       cfg.Token,
	}
}
