package helpers

import (
	"regexp"
)

// Used to map characters to HTML entities.
var htmlEscapes = map[string]string{
	"&": "&amp;",
	"<": "&lt;",
	">": "&gt;",
	`"`: "&quot;",
	"'": "&#39;",
}

// Used to match HTML entities and HTML characters.
var reUnescapedHtml = regexp.MustCompile(`[&<>"']`)

// escapeHTML converts the characters "&", "<", ">", '"', and "'" in a string to their
// corresponding HTML entities.
func EscapeHTML(input string) string {
	if reUnescapedHtml.MatchString(input) {
		return reUnescapedHtml.ReplaceAllStringFunc(input, func(chr string) string {
			return htmlEscapes[chr]
		})
	}
	return input
}
