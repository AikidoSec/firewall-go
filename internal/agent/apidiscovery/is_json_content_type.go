package apidiscovery

import (
	"strings"
)

var jsonContentTypes = []string{
	"application/json",
	"application/vnd.api+json",
	"application/csp-report",
	"application/x-json",
}

func IsJsonContentType(contentType string) bool {
	for _, jsonType := range jsonContentTypes {
		if strings.Contains(contentType, jsonType) {
			return true
		}
	}
	return false
}
