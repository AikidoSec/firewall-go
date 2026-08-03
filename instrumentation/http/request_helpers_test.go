package http

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFullURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		host     string
		hasTLS   bool
		expected string
	}{
		{
			name:     "HTTP request",
			url:      "http://example.com/path",
			host:     "example.com",
			hasTLS:   false,
			expected: "http://example.com/path",
		},
		{
			name:     "HTTPS request",
			url:      "https://example.com/path",
			host:     "example.com",
			hasTLS:   true,
			expected: "https://example.com/path",
		},
		{
			name:     "HTTP with query",
			url:      "http://example.com/path?param=value",
			host:     "example.com",
			hasTLS:   false,
			expected: "http://example.com/path?param=value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedURL, err := url.Parse(tt.url)
			assert.NoError(t, err)

			req := &http.Request{
				Method: "GET",
				URL:    parsedURL,
				Host:   tt.host,
			}

			if tt.hasTLS {
				req.TLS = &tls.ConnectionState{}
			}

			result := FullURL(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHeadersToMap(t *testing.T) {
	t.Run("lowercases header names", func(t *testing.T) {
		headers := http.Header{
			"Content-Type": {"application/json"},
			"User-Agent":   {"test-agent"},
		}
		result := HeadersToMap(headers)
		assert.Equal(t, map[string][]string{
			"content-type": {"application/json"},
			"user-agent":   {"test-agent"},
		}, result)
	})

	t.Run("keeps the raw cookie header", func(t *testing.T) {
		headers := http.Header{
			"Cookie":       {"session=abc"},
			"Content-Type": {"application/json"},
		}
		result := HeadersToMap(headers)
		assert.Equal(t, map[string][]string{
			"cookie":       {"session=abc"},
			"content-type": {"application/json"},
		}, result)
	})
}

func TestCookiesToMap(t *testing.T) {
	t.Run("single value per cookie name", func(t *testing.T) {
		cookies := []*http.Cookie{
			{Name: "session", Value: "abc"},
			{Name: "token", Value: "xyz"},
		}
		result := CookiesToMap(cookies)
		assert.Equal(t, map[string][]string{
			"session": {"abc"},
			"token":   {"xyz"},
		}, result)
	})

	t.Run("multiple values for same cookie name are all kept", func(t *testing.T) {
		cookies := []*http.Cookie{
			{Name: "session", Value: "first"},
			{Name: "session", Value: "second"},
		}
		result := CookiesToMap(cookies)
		assert.Equal(t, map[string][]string{
			"session": {"first", "second"},
		}, result)
	})
}
