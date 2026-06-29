package shellinjection

import (
	"strings"
)

var (
	escapeChars                      = []string{`"`, `'`}
	dangerousCharsInsideDoubleQuotes = []string{"$", "`", "\\", "!"}
)

// quoteContext represents the quoting state at a position in the command
type quoteContext int

const (
	noQuote quoteContext = iota
	singleQuote
	doubleQuote
)

// parseQuoteContext analyzes the command string and returns the quote context
// at each position where userInput occurs
func parseQuoteContext(command, userInput string) []quoteContext {
	if !strings.Contains(command, userInput) {
		return nil
	}

	var contexts []quoteContext
	userInputLen := len(userInput)

	// Find all occurrences of userInput
	var occurrences []int
	searchStart := 0
	for {
		idx := strings.Index(command[searchStart:], userInput)
		if idx == -1 {
			break
		}
		occurrences = append(occurrences, searchStart+idx)
		searchStart += idx + userInputLen
	}

	// For each occurrence, determine its quote context
	for _, occStart := range occurrences {
		context := noQuote
		escaped := false

		// Parse from the beginning to the occurrence to determine quote state
		for i := 0; i < occStart; i++ {
			ch := command[i]

			if escaped {
				escaped = false
				continue
			}

			if ch == '\\' {
				// Backslash escapes the next character (except in single quotes)
				if context != singleQuote {
					escaped = true
				}
				continue
			}

			switch ch {
			case '\'':
				if context == noQuote {
					context = singleQuote
				} else if context == singleQuote {
					context = noQuote
				}
				// Inside double quotes, single quote is literal
			case '"':
				if context == noQuote {
					context = doubleQuote
				} else if context == doubleQuote {
					context = noQuote
				}
				// Inside single quotes, double quote is literal
			}
		}

		contexts = append(contexts, context)
	}

	return contexts
}

func isSafelyEncapsulated(command, userInput string) bool {
	if !strings.Contains(command, userInput) {
		return true
	}

	// Parse the actual quote contexts for all occurrences
	contexts := parseQuoteContext(command, userInput)

	if len(contexts) == 0 {
		return true
	}

	// Check each occurrence
	for _, context := range contexts {
		switch context {
		case noQuote:
			// Not quoted at all - not safe
			return false

		case singleQuote:
			// Inside single quotes - check if userInput contains single quote
			// (which would break out of the quoting)
			if strings.Contains(userInput, "'") {
				return false
			}
			// Single quotes are safe - nothing is interpreted

		case doubleQuote:
			// Inside double quotes - check for dangerous characters
			// https://www.gnu.org/software/bash/manual/html_node/Double-Quotes.html
			for _, dangerousChar := range dangerousCharsInsideDoubleQuotes {
				if strings.Contains(userInput, dangerousChar) {
					return false
				}
			}
			// Also check if userInput contains unescaped double quotes
			if strings.Contains(userInput, `"`) {
				return false
			}
		}
	}

	return true
}
