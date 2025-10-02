package sqlinjection

import (
	"regexp"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/zeninternals"
)

func detectSQLInjection(query string, userInput string, dialect int) bool {
	// Lowercase versions of query and user input
	queryLowercase := strings.ToLower(query)
	userInputLowercase := strings.ToLower(userInput)

	if shouldReturnEarly(queryLowercase, userInputLowercase) {
		return false
	}

	// Executing our final check with zen_internals
	return zeninternals.DetectSQLInjection(queryLowercase, userInputLowercase, dialect) == 1

}

var isAlphanumeric = regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString

func shouldReturnEarly(query, userInput string) bool {
	// User input too small or larger than query
	if len(userInput) <= 1 || len(query) < len(userInput) {
		return true
	}

	// User input not in query
	if !strings.Contains(query, userInput) {
		return true
	}

	// User input is alphanumerical (with underscores allowed)
	if isAlphanumeric(userInput) {
		return true
	}

	// Check if user input is a valid comma-separated list of numbers
	cleanedInputForList := strings.ReplaceAll(strings.ReplaceAll(userInput, " ", ""), ",", "")
	match, _ := regexp.MatchString(`^\d+$`, cleanedInputForList)
	return match
}
