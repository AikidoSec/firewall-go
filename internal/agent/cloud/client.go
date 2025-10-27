package cloud

import (
	"net/http"
	"time"
)

type ClientConfig struct{}

type Client struct {
	httpClient *http.Client
}

func NewClient(cfg *ClientConfig) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}
