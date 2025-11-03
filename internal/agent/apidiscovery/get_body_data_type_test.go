package apidiscovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetBodyDataType(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string][]string
		expected string
	}{
		{"JSON content type", map[string][]string{"content-type": {"application/json"}}, "json"},
		{"API JSON content type", map[string][]string{"content-type": {"application/vnd.api+json"}}, "json"},
		{"CSP report content type", map[string][]string{"content-type": {"application/csp-report"}}, "json"},
		{"X JSON content type", map[string][]string{"content-type": {"application/x-json"}}, "json"},
		{"JSON with charset", map[string][]string{"content-type": {"application/json; charset=utf-8"}}, "json"},
		{"JSON uppercase", map[string][]string{"content-type": {"Application/JSON"}}, "json"},
		{"JSON LD", map[string][]string{"content-type": {"application/ld+json"}}, "json"},
		{"JSON with whitespace", map[string][]string{"content-type": {" application/json "}}, "json"},
		{"Form-urlencoded content type", map[string][]string{"content-type": {"application/x-www-form-urlencoded"}}, "form-urlencoded"},
		{"Multipart form-data content type", map[string][]string{"content-type": {"multipart/form-data"}}, "form-data"},
		{"XML content type", map[string][]string{"content-type": {"text/xml"}}, "xml"},
		{"XML with +xml suffix", map[string][]string{"content-type": {"application/atom+xml"}}, "xml"},
		{"HTML content_type", map[string][]string{"content-type": {"text/html"}}, ""},
		{"Nonexistent content type", map[string][]string{"x-test": {"abc"}}, ""},
		{"Null input", nil, ""},
		{"Empty headers", map[string][]string{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getBodyDataType(tt.headers)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}
