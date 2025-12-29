package shellinjection

import (
	"slices"
	"strings"
)

var (
	escapeChars                      = []string{`"`, `'`}
	dangerousCharsInsideDoubleQuotes = []string{"$", "`", "\\", "!"}
)

func isSafelyEncapsulated(command, userInput string) bool {
	segments := getCurrentAndNextSegments(strings.Split(command, userInput))

	for _, segment := range segments {
		currentSegment := segment["currentSegment"]
		nextSegment := segment["nextSegment"]

		// Get the character before and after the user input
		charBeforeUserInput := ""
		if currentSegment != "" {
			charBeforeUserInput = currentSegment[len(currentSegment)-1:]
		}

		charAfterUserInput := ""
		if nextSegment != "" {
			charAfterUserInput = nextSegment[:1]
		}

		// Check if the character before the user input is an escape character
		isEscapeChar := slices.Contains(escapeChars, charBeforeUserInput)

		if !isEscapeChar {
			return false
		}

		// Check if the character before and after the user input are the same
		if charBeforeUserInput != charAfterUserInput {
			return false
		}

		// Check if the user input contains the escape character itself
		if strings.Contains(userInput, charBeforeUserInput) {
			return false
		}

		// Check for dangerous characters inside double quotes
		// https://www.gnu.org/software/bash/manual/html_node/Single-Quotes.html
		// https://www.gnu.org/software/bash/manual/html_node/Double-Quotes.html
		if charBeforeUserInput == `"` {
			for _, dangerousChar := range dangerousCharsInsideDoubleQuotes {
				if strings.Contains(userInput, dangerousChar) {
					return false
				}
			}
		}
	}

	return true
}

func getCurrentAndNextSegments[T any](array []T) []map[string]T {
	var segments []map[string]T
	for i := 0; i < len(array)-1; i++ {
		segment := map[string]T{
			"currentSegment": array[i],
			"nextSegment":    array[i+1],
		}
		segments = append(segments, segment)
	}
	return segments
}
