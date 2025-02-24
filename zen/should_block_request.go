package zen

import (
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/grpc"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/firewall-go/internal/log"
	"time"
)

func ShouldBlockRequest() *BlockResponse {
	ctx := context.Get()
	if ctx == nil || ctx.ExecutedMiddleware {
		return nil // Do not run middleware twice.
	}
	go grpc.OnMiddlewareInstalled() // Report middleware as installed, handy for dashboard.
	ctx.ExecutedMiddleware = true
	context.Set(*ctx) // Store the change.

	matches := helpers.MatchEndpoints(
		helpers.RouteMetadata{URL: ctx.URL, Method: ctx.GetMethod(), Route: ctx.Route},
		helpers.GetEndpoints(),
	)
	if matches != nil {
		for _, endpoint := range matches {
			if endpoint.RateLimiting.Enabled {
				rateLimitingStatus := grpc.GetRateLimitingStatus(
					endpoint.Method, endpoint.Route, ctx.GetUserId(), ctx.GetIP(), 10*time.Millisecond,
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
	}
	return nil
}

type BlockResponse struct {
	Type    string  // e.g. rate-limited
	Trigger string  // e.g. user, ip, ...
	IP      *string // (Optional) IP Address in case of IP rate-limiting
}
