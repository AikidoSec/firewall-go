package zen

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

// SetRateLimitGroup associates a group with the current request context which is used for rate limiting.
// This function must be called before the Zen middleware is executed.
func SetRateLimitGroup(ctx context.Context, id string) context.Context {
	if len(id) == 0 {
		log.Info("Group ID cannot be empty.")
		return ctx
	}

	reqCtx := request.GetContext(ctx)
	if reqCtx == nil || reqCtx.HasMiddlewareExecuted() {
		log.Info("zen.SetRateLimitGroup(...) must be called before the Zen middleware is executed.")
		return ctx
	}

	reqCtx.SetRateLimitGroup(id)

	return ctx
}
