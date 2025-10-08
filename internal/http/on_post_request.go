package http

import (
	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/apidiscovery"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/grpc"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/firewall-go/internal/log"
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
	grpc.OnRequestShutdown(method, route, statusCode, user, ip, apiSpec)
}

// OnPostRequest gets called after a response is ready to be sent out.
func OnPostRequest(statusCode int) {
	ctx := context.Get()
	if ctx == nil {
		return
	}

	apiSpec := apidiscovery.GetAPIInfo(*ctx)

	go OnRequestShutdownReporting(
		ctx.GetMethod(), ctx.Route, statusCode, ctx.GetUserID(), ctx.GetIP(), apiSpec,
	)

	context.Clear()
}
