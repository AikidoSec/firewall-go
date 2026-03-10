package vulnerabilities

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var (
	uuidRegex        = regexp.MustCompile(`(?i)^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$`)
	objectIDRegex    = regexp.MustCompile(`(?i)^[0-9a-f]{24}$`)
	ulidRegex        = regexp.MustCompile(`(?i)^[0-9A-HJKMNP-TV-Z]{26}$`)
	numberRegex      = regexp.MustCompile(`^\d+$`)
	dateRegex        = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$|^\d{2}-\d{2}-\d{4}$`)
	emailRegex       = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	hashRegex        = regexp.MustCompile(`(?i)^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$`)
	numberArrayRegex = regexp.MustCompile(`^\d+(?:,\d+)*$`)
	ipv4Regex        = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	hashLengths      = map[int]bool{32: true, 40: true, 64: true, 128: true}
)

// extractRouteParams extracts potentially suspicious parts of a URL path.
// This serves as a fallback for when route parameters are not available
// (e.g., pre-Go 1.22 routing, manual path parsing, catch-all handlers).
func extractRouteParams(urlPath string) []string {
	if urlPath == "" || urlPath == "/" {
		return nil
	}

	segments := strings.Split(urlPath, "/")
	var results []string

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		decoded, err := url.PathUnescape(segment)
		if err != nil {
			decoded = segment
		}

		if isAlphanumeric(decoded) {
			continue
		}

		// Check if the segment contains URL-encoded characters (non-standard URL piece)
		if segment != url.PathEscape(decoded) {
			results = append(results, decoded)
		} else if isRouteParameter(segment) {
			// Looks like a dynamic value (number, UUID, hash, secret, etc.)
			results = append(results, decoded)
		}
	}

	decodedPath, err := url.PathUnescape(urlPath)
	if err != nil {
		decodedPath = urlPath
	}

	if len(results) > 0 || strings.Contains(decodedPath, ".") {
		// There are suspicious parts or the decoded path contains dots,
		// which is uncommon and could indicate path traversal or file access.
		// Add the full path (without leading slash) as user input.
		results = append(results, urlPath[1:])
	}

	return results
}

// isAlphanumeric returns true if the string only contains letters and digits.
func isAlphanumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// isRouteParameter returns true if the segment looks like a dynamic route parameter
// (number, UUID, ULID, BSON ObjectID, date, email, IP, hash, or secret).
func isRouteParameter(segment string) bool {
	if segment == "" {
		return false
	}

	if numberRegex.MatchString(segment) {
		return true
	}

	if strings.Contains(segment, ",") && numberArrayRegex.MatchString(segment) {
		return true
	}

	if len(segment) == 36 && uuidRegex.MatchString(segment) {
		return true
	}

	if len(segment) == 26 && ulidRegex.MatchString(segment) {
		return true
	}

	if len(segment) == 24 && objectIDRegex.MatchString(segment) {
		return true
	}

	if dateRegex.MatchString(segment) {
		return true
	}

	if strings.Contains(segment, "@") && emailRegex.MatchString(segment) {
		return true
	}

	if ipv4Regex.MatchString(segment) {
		return true
	}

	if hashLengths[len(segment)] && hashRegex.MatchString(segment) {
		return true
	}

	if looksLikeASecret(segment) {
		return true
	}

	return false
}

const secretMinLength = 10

// looksLikeASecret determines if a string looks like a secret/token value.
func looksLikeASecret(s string) bool {
	if len(s) <= secretMinLength {
		return false
	}

	hasNumber := false
	hasLower := false
	hasUpper := false
	hasSpecial := false

	for _, r := range s {
		switch {
		case unicode.IsDigit(r):
			hasNumber = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case isSpecialChar(r):
			hasSpecial = true
		}
	}

	if !hasNumber {
		return false
	}

	charsets := 0
	if hasLower {
		charsets++
	}
	if hasUpper {
		charsets++
	}
	if hasSpecial {
		charsets++
	}
	if charsets < 2 {
		return false
	}

	if strings.ContainsRune(s, ' ') {
		return false
	}

	if strings.ContainsRune(s, '-') {
		return false
	}

	// Check character uniqueness ratio using sliding window.
	// windowCount is guaranteed >= 1 because len(s) > secretMinLength == windowSize.
	windowSize := secretMinLength
	windowCount := len(s) - windowSize + 1
	totalRatio := 0.0

	for i := 0; i < windowCount; i++ {
		window := s[i : i+windowSize]
		unique := make(map[rune]bool)
		for _, r := range window {
			unique[r] = true
		}
		totalRatio += float64(len(unique)) / float64(windowSize)
	}

	return totalRatio/float64(windowCount) > 0.75
}

func isSpecialChar(r rune) bool {
	return strings.ContainsRune("!#$%^&*|;:<>", r)
}
