package api_discovery

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
	contentType := contentTypeArray[0] // Unwrap

	// Check if contentType has multiple values (comma separated or otherwise)
	// and use the first one.
	if strings.Contains(contentType, ",") {
		contentType = strings.Split(contentType, ",")[0]
	}

	if IsJsonContentType(contentType) {
		return BodyTypeJSON
	}

	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		return BodyTypeFormURLEncoded
	}

	if strings.HasPrefix(contentType, "multipart/form-data") {
		return BodyTypeFormData
	}

	if strings.Contains(contentType, "xml") {
		return BodyTypeXML
	}

	return BodyTypeUndefined
}
