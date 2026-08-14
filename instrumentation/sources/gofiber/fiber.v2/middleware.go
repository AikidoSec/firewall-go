package fiber

import (
	"errors"
	"strings"

	zenhttp "github.com/AikidoSec/firewall-go/instrumentation/http"
	"github.com/AikidoSec/firewall-go/instrumentation/request"
	"github.com/AikidoSec/firewall-go/instrumentation/sources/gofiber/fiber.v2/routeresolver"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gofiber/fiber/v2"
)

func GetMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !zen.ShouldProtect() {
			zen.WarnIfNotProtected()
			return c.Next()
		}

		// A mounted app's middleware runs alongside its parent's; only the first should report.
		if request.HasContext(c.UserContext()) {
			return c.Next()
		}

		// Aliases fasthttp's pooled buffer too; clone for the same reason as Path/Method.
		ip := strings.Clone(c.IP())

		route, routeParams := resolveRoute(c)

		reqCtx := request.SetContext(c.UserContext(), request.ContextData{
			Source:        "fiber",
			Route:         route,
			RouteParams:   routeParams,
			RemoteAddress: &ip,
			Body:          extractBody(c),
			URL:           c.Protocol() + "://" + c.Hostname() + c.OriginalURL(),
			// Path and Method alias fasthttp's pooled request buffer; clone them so
			// they stay valid after this request's buffer is reused.
			Path:    strings.Clone(c.Path()),
			Method:  strings.Clone(c.Method()),
			Query:   extractQuery(c),
			Headers: extractHeaders(c),
			Cookies: extractCookies(c),
		})
		c.SetUserContext(reqCtx)

		res := zenhttp.OnInitRequest(reqCtx)
		if res != nil {
			return c.Status(res.StatusCode).SendString(res.Message)
		}

		var handlerErr error
		request.Wrap(reqCtx, func() {
			handlerErr = c.Next()
		})

		// fiber's ErrorHandler runs after c.Next() returns, so on error the response status isn't set yet.
		// Mirror fiber's DefaultErrorHandler: default to 500, unless the error carries its own code.
		status := c.Response().StatusCode()
		if handlerErr != nil {
			status = fiber.StatusInternalServerError
			var ferr *fiber.Error
			if errors.As(handlerErr, &ferr) {
				status = ferr.Code
			}
		}
		zenhttp.OnPostRequest(reqCtx, status)

		return handlerErr
	}
}

// resolveRoute returns the route pattern and params of the endpoint that will
// serve this request. c.Route() and c.AllParams() are not usable here: fiber
// resolves the match as c.Next() cascades, so before dispatch they still hold
// this middleware's own route. The resolver is registered by the file zen-go
// injects into fiber; without it an empty route makes SetContext fall back to
// the request path.
func resolveRoute(c *fiber.Ctx) (string, map[string]string) {
	resolve := routeresolver.Get()
	if resolve == nil {
		return "", nil
	}

	route, params, _ := resolve(c)
	return route, params
}

func extractQuery(c *fiber.Ctx) map[string][]string {
	result := make(map[string][]string)
	for k, v := range c.Context().QueryArgs().All() {
		key := string(k)
		result[key] = append(result[key], string(v))
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func extractHeaders(c *fiber.Ctx) map[string][]string {
	headers := make(map[string][]string)
	for k, v := range c.Context().Request.Header.All() {
		key := strings.ToLower(string(k))
		headers[key] = append(headers[key], string(v))
	}
	return headers
}

func extractCookies(c *fiber.Ctx) map[string][]string {
	cookies := make(map[string][]string)
	for k, v := range c.Context().Request.Header.Cookies() {
		cookies[string(k)] = append(cookies[string(k)], string(v))
	}
	return cookies
}
