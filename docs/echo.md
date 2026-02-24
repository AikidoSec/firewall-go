# Echo Web Framework

## Installation

If you haven't already, follow the [installation instructions](../README.md#installation) in the main README.

## Setting a user

If you want to use user-blocking, know which user performed an attack and rate-limit on a user basis, you have to set a user using the following function :

```go
// Setting a user:
zen.SetUser(c.Request().Context(), id, name)

// So an example for Bob with id 1:
zen.SetUser(c.Request().Context(), "1", "Bob")
```

It's advised to do this in your authentication middleware, and before you add the Aikido Middleware (used for rate-limiting and user blocking, [See here](#middleware))

## Middleware

To use rate-limiting or user-blocking we require you to add some middleware yourself.
Here is an example of how to do that, you can tailor the responses to something that is more appropriate for your app.

```go
// ...
e.Use(AikidoMiddleware())
// ...
func AikidoMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			blockResult := zen.ShouldBlockRequest(c.Request().Context())

			if blockResult != nil {
				if blockResult.Type == "rate-limited" {
					message := "You are rate limited by Zen."
					if blockResult.Trigger == "ip" {
						message += " (Your IP: " + *blockResult.IP + ")"
					}
					return c.String(http.StatusTooManyRequests, message)
				} else if blockResult.Type == "blocked" {
					return c.String(http.StatusForbidden, "You are blocked by Zen.")
				}
			}

			return next(c)
		}
	}
}
```

## Proxy settings

The middleware uses Echo's built-in `c.RealIP()` to determine the client's IP address. By default this uses a legacy fallback that checks `X-Forwarded-For` then `X-Real-IP` without validating the source, which can allow IP spoofing.

You should explicitly configure Echo's `IPExtractor` to match your infrastructure:

```go
e := echo.New()

// Behind a reverse proxy - trust X-Forwarded-For from private network ranges
e.IPExtractor = echo.ExtractIPFromXFFHeader(
    echo.TrustLoopback(true),
    echo.TrustPrivateNet(true),
)

// Behind a reverse proxy that sets X-Real-IP
e.IPExtractor = echo.ExtractIPFromRealIPHeader(
    echo.TrustLoopback(true),
    echo.TrustPrivateNet(true),
)

// No proxy - app is directly exposed to the internet
e.IPExtractor = echo.ExtractIPDirect()
```
