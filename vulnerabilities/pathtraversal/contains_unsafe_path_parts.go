package pathtraversal

import (
	"strings"
)

var dangerousPathParts = []string{"../", "..\\"}

func containsUnsafePathParts(filePath string) bool {
	for _, dangerousPart := range dangerousPathParts {
		if strings.Contains(filePath, dangerousPart) {
			return true
		}
	}

	// Check for bare ".." path segments that could be used in filepath.Join flows.
	// We need to detect ".." as a standalone path element, not as part of a filename.
	// Split by both forward and back slashes to handle cross-platform paths.
	parts := strings.FieldsFunc(filePath, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	for _, part := range parts {
		if part == ".." {
			return true
		}
	}

	return false
}
