// Package routeresolver holds the route resolver registered by the file that
// zen-go injects into package fiber. It exists as its own package to avoid an
// import cycle: the injected file is compiled as part of package fiber, so it
// cannot import the middleware package, which imports fiber.
package routeresolver

// Resolver reports the route pattern and route params of the endpoint that will
// handle a request. ctx is a *fiber.DefaultCtx, kept as any so this package
// never imports fiber.
type Resolver func(ctx any) (route string, params map[string]string, ok bool)

var resolver Resolver

// Register is called from an init in the file injected into package fiber;
// renaming it requires updating _fiber/aikido_route.go.
func Register(r Resolver) {
	resolver = r
}

// Get returns nil in builds that zen-go did not instrument.
func Get() Resolver {
	return resolver
}
