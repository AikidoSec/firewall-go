package http

import (
	"context"
	"fmt"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/endpoints"
	"github.com/AikidoSec/firewall-go/internal/request"
)

type Response struct {
	StatusCode int
	Message    string
}

func OnInitRequest(ctx context.Context) *Response {
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return nil
	}

	if config.IsIPBypassed(reqCtx.GetIP()) {
		return nil
	}

	// Blocked IP lists (e.g. known threat actors, geo blocking, ...)
	ip := reqCtx.GetIP()
	if ipBlocked, reason := config.IsIPBlocked(ip); ipBlocked {
		msg := fmt.Sprintf("Your IP address is blocked due to %s. (Your IP: %s)", reason, ip)

		return &Response{403, msg}
	}

	// Check for blocked user agents using a regex (e.g. bot blocking)
	if userAgentBlocked, _ := config.IsUserAgentBlocked(reqCtx.GetUserAgent()); userAgentBlocked {
		msg := "You are not allowed to access this resource because you have been identified as a bot."
		return &Response{403, msg}
	}

	matches := endpoints.FindMatches(
		config.GetEndpoints(),
		endpoints.RouteMetadata{URL: reqCtx.URL, Method: reqCtx.Method, Route: reqCtx.Route},
	)
	// IP Allowlists per route
	if !ipAllowedToAccessRoute(ip, matches) {
		msg := "Your IP address is not allowed to access this resource."
		msg += " (Your IP: " + ip + ")"
		return &Response{403, msg}
	}

	return nil
}
