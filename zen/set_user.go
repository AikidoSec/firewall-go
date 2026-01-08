package zen

import (
	"context"
	"errors"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

var ErrUserIDOrNameEmpty = errors.New("user id or name cannot be empty")

// SetUser associates a user with the current request context for user-based
// blocking and rate limiting. This function must be called before the Zen
// middleware is executed.
func SetUser(ctx context.Context, id string, name string) (context.Context, error) {
	if config.IsZenDisabled() {
		return ctx, nil
	}

	if id == "" || name == "" {
		return ctx, ErrUserIDOrNameEmpty
	}

	reqCtx := request.GetContext(ctx)
	if reqCtx == nil || reqCtx.HasMiddlewareExecuted() {
		log.Info("zen.SetUser(...) must be called before the Zen middleware is executed.")
		return ctx, nil
	}

	user := agent.OnUser(id, name, reqCtx.GetIP())
	reqCtx.SetUser(&user)

	return ctx, nil
}
