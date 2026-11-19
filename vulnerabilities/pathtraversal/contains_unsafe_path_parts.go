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
