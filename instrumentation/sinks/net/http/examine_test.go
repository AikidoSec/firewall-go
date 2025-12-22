//go:build !integration

package http

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetPort(t *testing.T) {
	tests := []struct {
		url      string
		expected uint32
	}{
		{"http://example.com", 80},
		{"https://example.com", 443},
		{"http://example.com:8080", 8080},
		{"https://example.com:9443", 9443},
		{"ftp://example.com", 0},
	}

	for _, tt := range tests {
		req, _ := http.NewRequest("GET", tt.url, nil)
		assert.Equal(t, tt.expected, getPort(req), tt.url)
	}
}
