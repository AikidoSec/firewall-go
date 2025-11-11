package http

import (
	"context"
	"log/slog"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/apidiscovery"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

func OnRequestShutdownReporting(method string, route string, statusCode int, user string, ip string, apiSpec *aikido_types.APISpec) {
	if method == "" || route == "" || statusCode == 0 {
		return
	}

	log.Debug("[RSHUTDOWN] Got request metadata", slog.String("method", method), slog.String("route", route), slog.Int("statusCode", statusCode))

	if !shouldDiscoverRoute(statusCode, route, method) {
		return // Route is not to be discovered, e.g. status code might be 500.
	}

	agent.OnRequestShutdown(method, route, statusCode, user, ip, apiSpec)
}

// OnPostRequest gets called after a response is ready to be sent out.
func OnPostRequest(ctx context.Context, statusCode int) {
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return
	}

	apiSpec := apidiscovery.GetAPIInfo(reqCtx)

	go OnRequestShutdownReporting(
		reqCtx.Method, reqCtx.Route, statusCode, reqCtx.GetUserID(), reqCtx.GetIP(), apiSpec,
	)
}
