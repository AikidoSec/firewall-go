package attackwave

import "github.com/AikidoSec/firewall-go/internal/request"

// isWebScanner checks if the request looks like a web scanner or attack tool
func isWebScanner(ctx *request.Context, statusCode int) bool {
	if ctx == nil {
		return false
	}

	if ctx.Method != "" && isSuspiciousMethod(ctx.Method) {
		return true
	}

	if ctx.Path != "" && isSuspiciousPath(ctx.Path, statusCode) {
		return true
	}

	// Check for dangerous payloads in query parameters
	if queryContainsDangerousPayload(ctx) {
		return true
	}

	return false
}
