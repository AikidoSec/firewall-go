package zen

import (
	"context"
	"log/slog"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

func ShouldBlockRequest(ctx context.Context) *BlockResponse {
	if config.IsZenDisabled() {
		return nil
	}

	reqCtx := request.GetContext(ctx)
	if reqCtx == nil || !reqCtx.MarkMiddlewareExecuted() {
		return nil // Do not run middleware twice.
	}

	agent.OnMiddlewareInstalled() // Report middleware as installed, handy for dashboard.
	// user-blocking :
	userID := reqCtx.GetUserID()
	if config.IsUserBlocked(userID) {
		log.Info("User is blocked!", slog.String("user", userID))
		return &BlockResponse{"blocked", "user", nil}
	}

	rateLimitingStatus := agent.GetRateLimitingStatus(
		reqCtx.Method, reqCtx.Route, userID, reqCtx.GetIP(), reqCtx.GetRateLimitGroup(),
	)
	if rateLimitingStatus != nil && rateLimitingStatus.Block {
		go agent.Stats().OnRateLimit()

		log.Info("Request is rate-limited",
			slog.String("ip", reqCtx.GetIP()), slog.String("trigger", rateLimitingStatus.Trigger))

		if rateLimitingStatus.Trigger == "ip" {
			return &BlockResponse{
				"rate-limited", rateLimitingStatus.Trigger, reqCtx.RemoteAddress,
			}
		}
		return &BlockResponse{
			"rate-limited", rateLimitingStatus.Trigger, nil,
		}
	}

	return nil
}

type BlockResponse struct {
	Type    string  // e.g. rate-limited
	Trigger string  // e.g. user, ip, ...
	IP      *string // (Optional) IP Address in case of IP rate-limiting
}
