package http

import (
	"context"
	"log/slog"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/apidiscovery"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

// OnPostRequest gets called after a response is ready to be sent out.
func OnPostRequest(ctx context.Context, statusCode int) {
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return
	}

	apiSpec := apidiscovery.GetAPIInfo(reqCtx)

	method := reqCtx.Method
	route := reqCtx.Route

	if method == "" || route == "" || statusCode == 0 {
		return
	}

	log.Debug("[RSHUTDOWN] Got request metadata", slog.String("method", method), slog.String("route", route), slog.Int("statusCode", statusCode))

	if !shouldDiscoverRoute(statusCode, route, method) {
		return // Route is not to be discovered, e.g. status code might be 500.
	}

	user := reqCtx.GetUserID()
	ip := reqCtx.GetIP()

	agent.OnRequestShutdown(method, route, statusCode, user, ip, apiSpec)
}
