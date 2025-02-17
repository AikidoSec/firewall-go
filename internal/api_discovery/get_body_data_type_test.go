package api_discovery

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
		headers  map[string]interface{}
		expected string
	}{
		{"JSON content_type", map[string]interface{}{"content_type": "application/json"}, "json"},
		{"API JSON content_type", map[string]interface{}{"content_type": "application/vnd.api+json"}, "json"},
		{"CSP report content_type", map[string]interface{}{"content_type": "application/csp-report"}, "json"},
		{"X JSON content_type", map[string]interface{}{"content_type": "application/x-json"}, "json"},
		{"Form-urlencoded content_type", map[string]interface{}{"content_type": "application/x-www-form-urlencoded"}, "form-urlencoded"},
		{"Multipart form-data content_type", map[string]interface{}{"content_type": "multipart/form-data"}, "form-data"},
		{"XML content_type", map[string]interface{}{"content_type": "text/xml"}, "xml"},
		{"HTML content_type", map[string]interface{}{"content_type": "text/html"}, ""},
		{"Multiple content_types", map[string]interface{}{"content_type": "application/json"}, "json"},
		{"Nonexistent content_type", map[string]interface{}{"x-test": "abc"}, ""},
		{"Null input", nil, ""},
		{"Empty headers", map[string]interface{}{}, ""},
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
