package zen

import (
	"github.com/AikidoSec/firewall-go/internal/config"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/grpc"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/firewall-go/internal/log"
)

func ShouldBlockRequest() *BlockResponse {
	ctx := context.Get()
	if ctx == nil || ctx.ExecutedMiddleware {
		return nil // Do not run middleware twice.
	}

	go grpc.OnMiddlewareInstalled() // Report middleware as installed, handy for dashboard.
	ctx.ExecutedMiddleware = true
	context.Set(*ctx) // Store the change.

	// user-blocking :
	userID := ctx.GetUserID()
	if config.IsUserBlocked(userID) {
		log.Infof("User \"%s\" is blocked!", userID)
		return &BlockResponse{"blocked", "user", nil}
	}
	// rate-limiting :
	matches := helpers.MatchEndpoints(
		helpers.RouteMetadata{URL: ctx.URL, Method: ctx.GetMethod(), Route: ctx.Route},
		config.GetEndpoints(),
	)

	for _, endpoint := range matches {
		if endpoint.RateLimiting.Enabled {
			rateLimitingStatus := grpc.GetRateLimitingStatus(
				endpoint.Method, endpoint.Route, ctx.GetUserID(), ctx.GetIP(),
			)
			if rateLimitingStatus != nil && rateLimitingStatus.Block {
				log.Infof("Request made from IP \"%s\" is rate-limited by \"%s\"!", ctx.GetIP(), rateLimitingStatus.Trigger)
				if rateLimitingStatus.Trigger == "ip" {
					return &BlockResponse{
						"rate-limited", rateLimitingStatus.Trigger, ctx.RemoteAddress,
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
