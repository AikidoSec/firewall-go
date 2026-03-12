package vulnerabilities

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type jwtDecodeResult struct {
	JWT    bool
	Object interface{}
}

func removeBase64Padding(s string) string {
	return strings.TrimRight(s, "=")
}

func tryDecodeAsJWT(jwt string) jwtDecodeResult {
	if !strings.Contains(jwt, ".") {
		return jwtDecodeResult{JWT: false}
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return jwtDecodeResult{JWT: false}
	}

	payload, err := base64.RawURLEncoding.DecodeString(removeBase64Padding(parts[1]))
	if err != nil {
		return jwtDecodeResult{JWT: false}
	}

	var object interface{}
	err = json.Unmarshal(payload, &object)
	if err != nil {
		return jwtDecodeResult{JWT: false}
	}

	return jwtDecodeResult{JWT: true, Object: object}
}
