package http

import (
	"context"
	"fmt"

	"github.com/AikidoSec/firewall-go/internal/agent"
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

	ip := reqCtx.GetIP()

	// Record monitored IP matches for stats
	if monitoredKeys := config.GetMatchingMonitoredIPKeys(ip); len(monitoredKeys) > 0 {
		agent.Stats().OnIPAddressMatches(monitoredKeys)
	}

	// Allowed IP list, global list for allowing traffic by country
	if ipAllowed := config.IsIPAllowed(ip); !ipAllowed {
		msg := fmt.Sprintf("Your IP address is not allowed. (Your IP: %s)", ip)

		return &Response{403, msg}
	}

	// Blocked IP lists (e.g. known threat actors, geo blocking, ...)
	if ipBlocked, reason := config.IsIPBlocked(ip); ipBlocked {
		// Record blocked IP matches for stats
		if blockedKeys := config.GetMatchingBlockedIPKeys(ip); len(blockedKeys) > 0 {
			agent.Stats().OnIPAddressMatches(blockedKeys)
		}

		msg := fmt.Sprintf("Your IP address is blocked due to %s. (Your IP: %s)", reason, ip)

		return &Response{403, msg}
	}

	// Check for blocked user agents using a regex (e.g. bot blocking)
	ua := reqCtx.GetUserAgent()
	userAgentBlocked, _ := config.IsUserAgentBlocked(ua)
	isMonitoredUA := config.IsMonitoredUserAgent(ua)

	if userAgentBlocked || isMonitoredUA {
		if uaKeys := config.GetMatchingUserAgentKeys(ua); len(uaKeys) > 0 {
			agent.Stats().OnUserAgentMatches(uaKeys)
		}
	}

	if userAgentBlocked {
		msg := "You are not allowed to access this resource because you have been identified as a bot."
		return &Response{403, msg}
	}

	matches := endpoints.FindMatches(
		config.GetEndpoints(),
		endpoints.RouteMetadata{Method: reqCtx.Method, Route: reqCtx.Route},
	)
	// IP Allowlists per route
	if !ipAllowedToAccessRoute(ip, matches) {
		msg := "Your IP address is not allowed to access this resource."
		msg += " (Your IP: " + ip + ")"
		return &Response{403, msg}
	}

	return nil
}
