# Fiber Web Framework

Zen supports Fiber v2.

## Installation

If you haven't already, follow the [installation instructions](../README.md#installation) in the main README.

## Setting a user
If you want to use user-blocking, know which user performed an attack and rate-limit on a user basis, you have to set a user using the following function:
```go
// Setting a user:
zen.SetUser(c.UserContext(), id, name)

// So an example for Bob with id 1:
zen.SetUser(c.UserContext(), "1", "Bob")
```
It's advised to do this in your authentication middleware, and before you add the Aikido Middleware (used for rate-limiting and user blocking, [See here](#middleware))

## Middleware
To use rate-limiting or user-blocking we require you to add some middleware yourself.
Here is an example of how to do that, you can tailor the responses to something that is more appropriate for your app.
```go
// ...
app.Use(AikidoMiddleware())
// ...
func AikidoMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		blockResult := zen.ShouldBlockRequest(c.UserContext())

		if blockResult != nil {
			if blockResult.Type == "rate-limited" {
				message := "You are rate limited by Zen."
				if blockResult.Trigger == "ip" {
					message += " (Your IP: " + *blockResult.IP + ")"
				}
				c.Set("Retry-After", strconv.Itoa(blockResult.RetryAfterSeconds))
				return c.Status(fiber.StatusTooManyRequests).SendString(message)
			} else if blockResult.Type == "blocked" {
				return c.Status(fiber.StatusForbidden).SendString("You are blocked by Zen.")
			}
		}

		return c.Next()
	}
}
```
The important part here is the call to `zen.ShouldBlockRequest()` which returns whether to block the request and the reason why.

When `blockResult.Type` is `"rate-limited"`, `blockResult.RetryAfterSeconds` tells you how long to wait until the rate limit window frees up again. Sending it back as the standard `Retry-After` header (as shown above) lets well-behaved clients back off instead of retrying immediately.

## Proxy settings

The middleware uses Fiber's built-in `c.IP()` to determine the client's IP address.

**By default, Fiber does not read any proxy headers** — `c.IP()` returns the direct TCP remote address, so it's safe out of the box even without configuration. If your app sits behind a reverse proxy or load balancer, you need to opt in to reading the client IP from a header:

```go
app := fiber.New(fiber.Config{
	// Trust the given proxy IPs or CIDR ranges
	EnableTrustedProxyCheck: true,
	TrustedProxies:          []string{"10.0.0.0/8", "172.16.0.0/12"},

	// Header to read the client IP from once the proxy is trusted
	ProxyHeader: fiber.HeaderXForwardedFor,
})
```

Setting `ProxyHeader` without also enabling `EnableTrustedProxyCheck` and configuring `TrustedProxies` lets any client spoof their IP by setting that header directly, so always configure them together.
