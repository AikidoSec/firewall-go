package context

import (
	"net"
	"net/http"
)

func GetRemoteAddress(r *http.Request) *string {
	var result string
	rawIP := r.RemoteAddr

	host, _, err := net.SplitHostPort(rawIP)
	if err != nil {
		result = "0.0.0.0"
	} else {
		result = host // Remove port number
	}

	return &result
}
