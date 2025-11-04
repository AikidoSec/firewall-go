package apidiscovery

import (
	"strings"
)

// BodyDataType represents the type of the body data.
type BodyDataType string

const (
	BodyTypeJSON           BodyDataType = "json"
	BodyTypeFormURLEncoded BodyDataType = "form-urlencoded"
	BodyTypeFormData       BodyDataType = "form-data"
	BodyTypeXML            BodyDataType = "xml"
	BodyTypeUndefined      BodyDataType = ""
)

func getBodyDataType(headers map[string][]string) BodyDataType {
	if headers == nil {
		return BodyTypeUndefined
	}

	contentTypeArray, exists := headers["content-type"]
	if !exists || len(contentTypeArray) < 1 {
		return BodyTypeUndefined
	}
	contentType := strings.ToLower(strings.TrimSpace(contentTypeArray[0]))

	if isJSONContentType(contentType) {
		return BodyTypeJSON
	}

	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		return BodyTypeFormURLEncoded
	}

	if strings.HasPrefix(contentType, "multipart/form-data") {
		return BodyTypeFormData
	}

	if isXMLContentType(contentType) {
		return BodyTypeXML
	}

	return BodyTypeUndefined
}

var jsonContentTypes = []string{
	"application/json",
	"application/csp-report",
	"application/x-json",
}

func isJSONContentType(contentType string) bool {
	for _, jsonType := range jsonContentTypes {
		if strings.HasPrefix(contentType, jsonType) {
			return true
		}
	}

	return strings.Contains(contentType, "+json")
}

func isXMLContentType(contentType string) bool {
	return strings.HasPrefix(contentType, "application/xml") ||
		strings.HasPrefix(contentType, "text/xml") ||
		strings.Contains(contentType, "+xml")
}
