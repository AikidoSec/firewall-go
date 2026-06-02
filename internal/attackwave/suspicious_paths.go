package attackwave

import (
	"strings"
)

// foreignExtensions are extensions that a Go app wouldn't natively serve.
// Requests to these extensions are only counted as scan hits when the response
// is 404 — a 200 may indicate the app proxies to another backend.
var foreignExtensions = map[string]bool{
	"php":   true,
	"php3":  true,
	"php4":  true,
	"php5":  true,
	"phtml": true,
	"java":  true,
	"jsp":   true,
	"jspx":  true,
}

// isSuspiciousPath checks if the path contains patterns commonly targeted by scanners.
// statusCode is required to disambiguate foreign-extension paths: they are only
// suspicious when the server returns 404 (a 200 might mean the app proxies to a
// PHP/Java backend).
func isSuspiciousPath(path string, statusCode int) bool {
	normalized := strings.ToLower(path)
	segments := strings.Split(normalized, "/")

	// Get the last segment (filename)
	var filename string
	if len(segments) > 0 {
		filename = segments[len(segments)-1]
	}

	// Check if the filename is in our suspicious list
	if filename != "" && suspiciousFilenames[filename] {
		return true
	}

	// Check file extension
	if filename != "" && strings.Contains(filename, ".") {
		parts := strings.Split(filename, ".")
		if len(parts) > 1 {
			ext := parts[len(parts)-1]
			if suspiciousExtensions[ext] {
				return true
			}
			if foreignExtensions[ext] && statusCode == 404 {
				return true
			}
		}
	}

	// Check all directory segments
	for _, segment := range segments {
		if segment != "" && suspiciousDirectories[segment] {
			return true
		}
	}

	return false
}
