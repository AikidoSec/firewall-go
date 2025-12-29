package zen

import (
	"context"
	"errors"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

var ErrRateLimitGroupIDEmpty = errors.New("group id cannot be empty")

// SetRateLimitGroup associates a group with the current request context which is used for rate limiting.
// This function must be called before the Zen middleware is executed.
func SetRateLimitGroup(ctx context.Context, id string) (context.Context, error) {
	if id == "" {
		return ctx, ErrRateLimitGroupIDEmpty
	}

	reqCtx := request.GetContext(ctx)
	if reqCtx == nil || reqCtx.HasMiddlewareExecuted() {
		log.Info("zen.SetRateLimitGroup(...) must be called before the Zen middleware is executed.")
		return ctx, nil
	}

	reqCtx.SetRateLimitGroup(id)

	return ctx, nil
}
