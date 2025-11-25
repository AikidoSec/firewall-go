package attackwave

import "strings"

var suspiciousMethods = map[string]bool{
	"BADMETHOD":     true,
	"BADHTTPMETHOD": true,
	"BADDATA":       true,
	"BADMTHD":       true,
	"BDMTHD":        true,
}

// isSuspiciousMethod checks if the HTTP method is commonly used by scanners
func isSuspiciousMethod(method string) bool {
	return suspiciousMethods[strings.ToUpper(method)]
}
