# Gin Web Framework

## Installation

If you haven't already, follow the [installation instructions](../README.md#installation) in the main README.

## Setting a user
If you want to use user-blocking, know which user performed an attack and rate-limit on a user basis, you have to set  a user using the following function : 
```go
// Setting a user : 
zen.SetUser(ctx, id, name)

// So an example for Bob with id 1 :
zen.SetUser(ctx, "1", "Bob")
```
It's advised to do this in your authentication middleware, and before you add the Aikido Middleware (used for rate-limiting and user blocking, [See here](#middleware))

## Middleware
To use rate-limiting or user-blocking we require you to add some middleware yourself.
Here is an example of how to do that, you can tailor the responses to something that is more appropriate for your app.
```go
// ...
r.Use(AikidoMiddleware())
// ... 
func AikidoMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		blockResult := zen.ShouldBlockRequest(c)

		if blockResult != nil {
			if blockResult.Type == "rate-limited" {
				message := "You are rate limited by Zen."
				if blockResult.Trigger == "ip" {
					message += " (Your IP: " + *blockResult.IP + ")"
				}
				c.String(http.StatusTooManyRequests, message)
				c.Abort() // Stop further processing
				return
			} else if blockResult.Type == "blocked" {
				c.String(http.StatusForbidden, "You are blocked by Zen.")
				c.Abort() // Stop further processing
				return
			}
		}

		c.Next()
	}
}
```
The important part here is the call to `zen.ShouldBlockRequest()` which returns whether to block the request and the reason why.

## Proxy settings

The middleware uses Gin's built-in `c.ClientIP()` to determine the client's IP address, which reads from `X-Forwarded-For` and `X-Real-IP` headers.

**By default, Gin trusts all proxies**, which means a client can spoof their IP by setting these headers directly. You should explicitly configure which proxies to trust:

```go
// Trust specific proxy IPs or CIDR ranges
router.SetTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12"})

// Disable proxy trust entirely if your app is directly exposed
router.SetTrustedProxies(nil)
```

If you're running behind a known platform, Gin has built-in constants for common CDN/platform headers:

```go
// Cloudflare (uses CF-Connecting-IP)
router.TrustedPlatform = gin.PlatformCloudflare

// Google App Engine (uses X-Appengine-Remote-Addr)
router.TrustedPlatform = gin.PlatformGoogleAppEngine

// Fly.io (uses Fly-Client-IP)
router.TrustedPlatform = gin.PlatformFlyIO
```
