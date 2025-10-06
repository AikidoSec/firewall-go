package apidiscovery

import (
	"strings"
	"testing"
)

func determineType(contentType string) string {
	contentType = strings.ToLower(contentType)
	switch {
	case strings.Contains(contentType, "json"):
		return "json"
	case contentType == "application/x-www-form-urlencoded":
		return "form-urlencoded"
	case contentType == "multipart/form-data":
		return "form-data"
	case strings.HasPrefix(contentType, "text/xml"):
		return "xml"
	default:
		return ""
	}
}

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
		{"Form-urlencoded content type", map[string][]string{"content-type": {"application/x-www-form-urlencoded"}}, "form-urlencoded"},
		{"Multipart form-data content type", map[string][]string{"content-type": {"multipart/form-data"}}, "form-data"},
		{"XML content type", map[string][]string{"content-type": {"text/xml"}}, "xml"},
		{"HTML content_type", map[string][]string{"content-type": {"text/html"}}, ""},
		{"Multiple content types", map[string][]string{"content-type": {"application/json"}}, "json"},
		{"Nonexistent content type", map[string][]string{"x-test": {"abc"}}, ""},
		{"Null input", nil, ""},
		{"Empty headers", map[string][]string{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getBodyDataType(tt.headers)
			if string(result) != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
