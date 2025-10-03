package http

import (
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/helpers"
)

type Response struct {
	StatusCode int
	Message    string
}

func OnInitRequest(ctx context.Context) *Response {
	if helpers.IsIPBypassed(ctx.GetIP()) {
		return nil // Return early, not setting a context object.
	}
	context.Set(ctx) // Store the new context

	// Blocked IP lists (e.g. known threat actors, geo blocking, ...)
	ip := ctx.GetIP()
	if ipBlocked, _ := helpers.IsIPBlocked(ip); ipBlocked {
		msg := "Your IP address is not allowed to access this resource."
		msg += " (Your IP: " + ip + ")"
		return &Response{403, msg}
	}

	// Check for blocked user agents using a regex (e.g. bot blocking)
	if userAgentBlocked, _ := helpers.IsUserAgentBlocked(ctx.GetUserAgent()); userAgentBlocked {
		msg := "You are not allowed to access this resource because you have been identified as a bot."
		return &Response{403, msg}
	}

	matches := helpers.MatchEndpoints(
		helpers.RouteMetadata{URL: ctx.URL, Method: ctx.GetMethod(), Route: ctx.Route},
		helpers.GetEndpoints(),
	)
	// IP Allowlists per route
	if !ipAllowedToAccessRoute(ip, matches) {
		msg := "Your IP address is not allowed to access this resource."
		msg += " (Your IP: " + ip + ")"
		return &Response{403, msg}
	}

	return nil
}
