package helpers

import (
	"regexp"
	"strings"
)

func EscapeStringRegexp(str string) string {
	re := regexp.MustCompile(`[|\\{}()[\]^$+*?.]`)
	str = re.ReplaceAllStringFunc(str, func(match string) string {
		return "\\" + match
	})
	str = strings.ReplaceAll(str, "-", "\\x2d")
	return str
}
