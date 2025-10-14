package http

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/api_discovery"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

func OnRequestShutdownReporting(method string, route string, statusCode int, user string, ip string, apiSpec *aikido_types.APISpec) {
	if method == "" || route == "" || statusCode == 0 {
		return
	}

	log.Info("[RSHUTDOWN] Got request metadata: ", method, " ", route, " ", statusCode)

	if !helpers.ShouldDiscoverRoute(statusCode, route, method) {
		return // Route is not to be discovered, e.g. status code might be 500.
	}

	log.Info("[RSHUTDOWN] Got API spec: ", apiSpec)
	agent.OnRequestShutdown(method, route, statusCode, user, ip, apiSpec)
}

// OnPostRequest gets called after a response is ready to be sent out.
func OnPostRequest(ctx context.Context, statusCode int) {
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return
	}

	apiSpec := api_discovery.GetAPIInfo(reqCtx)

	go OnRequestShutdownReporting(
		reqCtx.GetMethod(), reqCtx.Route, statusCode, reqCtx.GetUserID(), reqCtx.GetIP(), apiSpec,
	)
}
