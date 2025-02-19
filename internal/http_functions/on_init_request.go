package http_functions

import (
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/firewall-go/internal/log"
)

type Response struct {
	StatusCode int
	Message    string
}

func OnInitRequest(ctx context.Context) *Response {
	context.Set(ctx) // Store the new context

	// Blocked IP lists (e.g. known threat actors, geo blocking, ...)
	ip := ctx.GetIP()
	if ipBlocked, ipBlockedDescription := helpers.IsIpBlocked(ip); ipBlocked {
		log.Infof("IP \"%s\" blocked due to: %s!", ip, ipBlockedDescription)
		msg := "Your IP address is not allowed to access this resource."
		msg += "Your message here" + " (Your IP: " + ip + ")"
		return &Response{403, msg}
	}

	return nil
}
