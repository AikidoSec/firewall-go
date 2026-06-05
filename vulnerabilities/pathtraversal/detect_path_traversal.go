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

	// Compared case-insensitively so apps that case-normalize the path
	// before opening it cannot bypass detection on case-insensitive
	// file systems (macOS APFS, Windows NTFS).
	normalisedFilePath := strings.ToLower(filePath)
	normalisedUserInput := strings.ToLower(userInput)

	if !strings.Contains(normalisedFilePath, normalisedUserInput) {
		// We ignore cases where the user input is not part of the file path.
		return false
	}

	if containsUnsafePathParts(normalisedFilePath) && containsUnsafePathParts(normalisedUserInput) {
		return true
	}

	if checkPathStart {
		// Check for absolute path traversal
		return startsWithUnsafePath(normalisedFilePath, normalisedUserInput)
	}

	return false
}
