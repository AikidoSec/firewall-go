package http

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/config"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/firewall-go/internal/request"
)

type Response struct {
	StatusCode int
	Message    string
}

func OnInitRequest(ctx context.Context) *Response {
	httpCtx := request.GetContext(ctx)
	if httpCtx == nil {
		return nil
	}

	if config.IsIPBypassed(httpCtx.GetIP()) {
		return nil // Return early, not setting a context object.
	}

	// Blocked IP lists (e.g. known threat actors, geo blocking, ...)
	ip := httpCtx.GetIP()
	if ipBlocked, _ := config.IsIPBlocked(ip); ipBlocked {
		msg := "Your IP address is not allowed to access this resource."
		msg += " (Your IP: " + ip + ")"
		return &Response{403, msg}
	}

	// Check for blocked user agents using a regex (e.g. bot blocking)
	if userAgentBlocked, _ := config.IsUserAgentBlocked(httpCtx.GetUserAgent()); userAgentBlocked {
		msg := "You are not allowed to access this resource because you have been identified as a bot."
		return &Response{403, msg}
	}

	matches := helpers.MatchEndpoints(
		helpers.RouteMetadata{URL: httpCtx.URL, Method: httpCtx.GetMethod(), Route: httpCtx.Route},
		config.GetEndpoints(),
	)
	// IP Allowlists per route
	if !ipAllowedToAccessRoute(ip, matches) {
		msg := "Your IP address is not allowed to access this resource."
		msg += " (Your IP: " + ip + ")"
		return &Response{403, msg}
	}

	return nil
}
