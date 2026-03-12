package attackwave

import (
	"strings"
)

// isSuspiciousPath checks if the path contains patterns commonly targeted by scanners
func isSuspiciousPath(path string) bool {
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
