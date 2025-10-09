package zen

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/grpc"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

func SetUser(ctx context.Context, id string, name string) context.Context {
	// Validate :
	if len(id) == 0 || len(name) == 0 {
		log.Info("User ID or name cannot be empty.")
		return ctx
	}

	// Get context :
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil || reqCtx.ExecutedMiddleware {
		log.Info("zen.SetUser(...) must be called before the Zen middleware is executed.")
		return ctx
	}

	reqCtx.User = &request.User{ID: id, Name: name}
	go grpc.OnUserEvent(id, name, reqCtx.GetIP())

	return ctx
}
