package fiber

import (
	"encoding/json"
	"net/url"
	"strings"

	zenhttp "github.com/AikidoSec/firewall-go/instrumentation/http"
	"github.com/AikidoSec/firewall-go/instrumentation/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gofiber/fiber/v3"
)

func GetMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		if !zen.ShouldProtect() {
			zen.WarnIfNotProtected()
			return c.Next()
		}

		ip := c.IP()

		routeParamNames := c.Route().Params
		var routeParams map[string]string
		if len(routeParamNames) > 0 {
			// Fiber's param values alias fasthttp's pooled request buffer, which gets
			// reused for later requests, so they must be copied before being retained.
			routeParams = make(map[string]string, len(routeParamNames))
			for _, name := range routeParamNames {
				routeParams[name] = strings.Clone(c.Params(name))
			}
		}

		reqCtx := request.SetContext(c.Context(), request.ContextData{
			Source:        "fiber",
			Route:         c.Route().Path,
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
		c.SetContext(reqCtx)

		res := zenhttp.OnInitRequest(reqCtx)
		if res != nil {
			return c.Status(res.StatusCode).SendString(res.Message)
		}

		var handlerErr error
		request.Wrap(reqCtx, func() {
			handlerErr = c.Next()
		})

		zenhttp.OnPostRequest(reqCtx, c.Response().StatusCode())

		return handlerErr
	}
}

func extractBody(c fiber.Ctx) any {
	raw := c.Body()
	if len(raw) == 0 {
		return nil
	}

	var jsonResult any
	if err := json.Unmarshal(raw, &jsonResult); err != nil {
		jsonResult = nil
	}

	var formResult url.Values
	contentType := string(c.RequestCtx().Request.Header.ContentType())
	if strings.Contains(contentType, "multipart/form-data") {
		if form, err := c.MultipartForm(); err == nil && form != nil && len(form.Value) > 0 {
			formResult = url.Values(form.Value)
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if vals, err := url.ParseQuery(string(raw)); err == nil && len(vals) > 0 {
			formResult = vals
		}
	}

	if jsonResult != nil && len(formResult) > 0 {
		return []any{jsonResult, formResult}
	}
	if jsonResult != nil {
		return jsonResult
	}
	if len(formResult) > 0 {
		return formResult
	}
	return nil
}

func extractQuery(c fiber.Ctx) map[string][]string {
	result := make(map[string][]string)
	for k, v := range c.RequestCtx().QueryArgs().All() {
		key := string(k)
		result[key] = append(result[key], string(v))
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func extractHeaders(c fiber.Ctx) map[string][]string {
	headers := make(map[string][]string)
	for k, v := range c.RequestCtx().Request.Header.All() {
		key := strings.ToLower(string(k))
		headers[key] = append(headers[key], string(v))
	}
	return headers
}

func extractCookies(c fiber.Ctx) map[string][]string {
	cookies := make(map[string][]string)
	for k, v := range c.RequestCtx().Request.Header.Cookies() {
		cookies[string(k)] = append(cookies[string(k)], string(v))
	}
	return cookies
}
