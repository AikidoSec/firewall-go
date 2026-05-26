package pathtraversal

import (
	"strings"
)

// detectPathTraversal detects path traversal attacks.
func detectPathTraversal(filePath, userInput string, checkPathStart bool) bool {
	if len(userInput) <= 1 {
		// We ignore single characters since they don't pose a big threat.
		return false
	}

	if len(userInput) > len(filePath) {
		// We ignore cases where the user input is longer than the file path.
		// Because the user input can't be part of the file path.
		return false
	}

	if !strings.Contains(strings.ToLower(filePath), strings.ToLower(userInput)) {
		// We ignore cases where the user input is not part of the file path.
		// Compared case-insensitively so apps that case-normalize the path
		// before opening it cannot bypass detection on case-insensitive
		// file systems (macOS APFS, Windows NTFS).
		return false
	}

	if containsUnsafePathParts(filePath) && containsUnsafePathParts(userInput) {
		return true
	}

	if checkPathStart {
		// Check for absolute path traversal
		return startsWithUnsafePath(filePath, userInput)
	}

	return false
}
