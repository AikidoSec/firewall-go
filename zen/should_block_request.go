package zen

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

func ShouldBlockRequest(ctx context.Context) *BlockResponse {
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil || reqCtx.MarkMiddlewareExecuted() {
		return nil // Do not run middleware twice.
	}

	go agent.OnMiddlewareInstalled() // Report middleware as installed, handy for dashboard.

	// user-blocking :
	userID := reqCtx.GetUserID()
	if config.IsUserBlocked(userID) {
		log.Infof("User \"%s\" is blocked!", userID)
		return &BlockResponse{"blocked", "user", nil}
	}
	// rate-limiting :
	matches := helpers.MatchEndpoints(
		helpers.RouteMetadata{URL: reqCtx.URL, Method: reqCtx.GetMethod(), Route: reqCtx.Route},
		config.GetEndpoints(),
	)

	for _, endpoint := range matches {
		if endpoint.RateLimiting.Enabled {
			rateLimitingStatus := agent.GetRateLimitingStatus(
				endpoint.Method, endpoint.Route, reqCtx.GetUserID(), reqCtx.GetIP(),
			)
			if rateLimitingStatus != nil && rateLimitingStatus.Block {
				log.Infof("Request made from IP \"%s\" is rate-limited by \"%s\"!", reqCtx.GetIP(), rateLimitingStatus.Trigger)
				if rateLimitingStatus.Trigger == "ip" {
					return &BlockResponse{
						"rate-limited", rateLimitingStatus.Trigger, reqCtx.RemoteAddress,
					}
				}
				return &BlockResponse{
					"rate-limited", rateLimitingStatus.Trigger, nil,
				}
			}
		}
	}

	return nil
}

type BlockResponse struct {
	Type    string  // e.g. rate-limited
	Trigger string  // e.g. user, ip, ...
	IP      *string // (Optional) IP Address in case of IP rate-limiting
}
