package zen

import (
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/grpc"
	"github.com/AikidoSec/firewall-go/internal/log"
)

func SetUser(id string, name string) {
	// Validate :
	if len(id) == 0 || len(name) == 0 {
		log.Info("User ID or name cannot be empty.")
		return
	}

	// Get context :
	ctx := context.Get()
	if ctx == nil {
		return
	}
	if ctx.ExecutedMiddleware {
		log.Info("zen.SetUser(...) must be called before the Zen middleware is executed.")
	}

	// Set :
	ctx.User = &context.User{Id: id, Name: name}
	context.Set(*ctx)
	go grpc.OnUserEvent(id, name, ctx.GetIP())
}
