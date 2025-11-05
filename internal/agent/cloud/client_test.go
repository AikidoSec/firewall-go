package cloud

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name   string
		config *ClientConfig
		want   *Client
	}{
		{
			name: "creates client with all fields",
			config: &ClientConfig{
				APIEndpoint:      "https://localhost:8080",
				RealtimeEndpoint: "https://localhost:8081",
				Token:            "test-token-123",
			},
			want: &Client{
				apiEndpoint:      "https://localhost:8080",
				realtimeEndpoint: "https://localhost:8081",
				token:            "test-token-123",
			},
		},
		{
			name: "creates client with empty strings",
			config: &ClientConfig{
				APIEndpoint:      "",
				RealtimeEndpoint: "",
				Token:            "",
			},
			want: &Client{
				apiEndpoint:      "",
				realtimeEndpoint: "",
				token:            "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewClient(tt.config)

			require.NotNil(t, got, "NewClient() should not return nil")
			assert.Equal(t, tt.want.apiEndpoint, got.apiEndpoint, "apiEndpoint mismatch")
			assert.Equal(t, tt.want.realtimeEndpoint, got.realtimeEndpoint, "realtimeEndpoint mismatch")
			assert.Equal(t, tt.want.token, got.token, "token mismatch")
			assert.NotNil(t, got.httpClient, "httpClient should not be nil")
		})
	}
}

func TestNewClient_HTTPClient(t *testing.T) {
	config := &ClientConfig{
		APIEndpoint:      "https://localhost:8080",
		RealtimeEndpoint: "https://localhost:8081",
		Token:            "test-token",
	}

	client := NewClient(config)

	assert.NotNil(t, client.httpClient, "httpClient should be initialized")

	expectedTimeout := 30 * time.Second
	assert.Equal(t, expectedTimeout, client.httpClient.Timeout, "httpClient timeout should be 30 seconds")
}
