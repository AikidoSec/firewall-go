package zen

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

// SetUser associates a user with the current request context for user-based
// blocking and rate limiting. This function must be called before the Zen
// middleware is executed.
func SetUser(ctx context.Context, id string, name string) context.Context {
	// Validate :
	if len(id) == 0 || len(name) == 0 {
		log.Info("User ID or name cannot be empty.")
		return ctx
	}

	// Get context :
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil || reqCtx.HasMiddlewareExecuted() {
		log.Info("zen.SetUser(...) must be called before the Zen middleware is executed.")
		return ctx
	}

	reqCtx.SetUser(&request.User{ID: id, Name: name})
	go agent.OnUser(id, name, reqCtx.GetIP())

	return ctx
}
