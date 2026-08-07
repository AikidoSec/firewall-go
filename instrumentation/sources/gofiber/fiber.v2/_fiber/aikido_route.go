// This file is added to the github.com/gofiber/fiber/v2 package by the zen-go
// toolexec via the add-file rule in zen.instrument.yml. It is NOT compiled as
// part of any normal Go build; the leading underscore in the parent directory
// keeps the Go toolchain from discovering it.
//
// Fiber resolves the matched route as c.Next() cascades through the handler
// stack, so app.Use middleware runs before c.Route() and c.AllParams() hold the
// endpoint that will serve the request. This walks the same route tree that
// app.next walks, before dispatch, and registers the walk with firewall-go.

package fiber

import (
	"strings"

	"github.com/AikidoSec/firewall-go/instrumentation/sources/gofiber/fiber.v2/routeresolver"
)

func init() {
	routeresolver.Register(aikidoResolveRoute)
}

func aikidoResolveRoute(ctx any) (string, map[string]string, bool) {
	c, ok := ctx.(*Ctx)
	if !ok || c == nil || c.app == nil {
		return "", nil, false
	}

	if c.methodINT < 0 || c.methodINT >= len(c.app.treeStack) {
		return "", nil, false
	}

	tree, ok := c.app.treeStack[c.methodINT][c.treePath]
	if !ok {
		tree = c.app.treeStack[c.methodINT][""]
	}

	// Scratch array: c.values belongs to the router, which fills it at dispatch.
	var values [maxParams]string

	for _, route := range tree {
		if route.use || route.mount {
			continue
		}
		if !route.match(c.detectionPath, c.path, &values) {
			continue
		}

		var params map[string]string
		if len(route.Params) > 0 {
			params = make(map[string]string, len(route.Params))
			for i, name := range route.Params {
				if i >= len(values) {
					break
				}
				// Values alias fasthttp's pooled buffer; clone before retaining.
				params[name] = strings.Clone(values[i])
			}
		}

		return route.Path, params, true
	}

	return "", nil, false
}
