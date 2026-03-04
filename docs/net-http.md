# net/http (Standard Library) and Chi

## Installation

If you haven't already, follow the [installation instructions](../README.md#installation) in the main README.

No additional dependencies are required for `net/http`, support is included in the core `firewall-go` module.

Chi uses the standard `http.Handler` interface, so the setup below applies to both `net/http` and Chi.

## Setting a user
If you want to use user-blocking, know which user performed an attack and rate-limit on a user basis, you have to set a user using the following function:
```go
// Setting a user:
zen.SetUser(r.Context(), id, name)

// So an example for Bob with id 1:
zen.SetUser(r.Context(), "1", "Bob")
```
It's advised to do this in your authentication middleware, and before you add the Aikido Middleware (used for rate-limiting and user blocking, [See here](#middleware))

## Middleware
To use rate-limiting or user-blocking we require you to add some middleware yourself.
Here is an example of how to do that, you can tailor the responses to something that is more appropriate for your app.
```go
// ...
handler := AikidoMiddleware(mux)
// ...
func AikidoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blockResult := zen.ShouldBlockRequest(r.Context())
		if blockResult != nil {
			switch blockResult.Type {
			case "rate-limited":
				message := "You are rate limited by Zen."
				if blockResult.Trigger == "ip" {
					message += " (Your IP: " + *blockResult.IP + ")"
				}
				http.Error(w, message, http.StatusTooManyRequests)
				return
			case "blocked":
				http.Error(w, "You are blocked by Zen.", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
```
The important part here is the call to `zen.ShouldBlockRequest()` which returns whether to block the request and the reason why.

## Proxy settings

The middleware automatically uses the `X-Forwarded-For` header to determine the client's IP address when your app runs behind a reverse proxy or load balancer.

If your server is publicly exposed without a proxy in front of it, set `AIKIDO_TRUST_PROXY=false` to prevent clients from spoofing their IP address (which could bypass rate limiting):

```bash
AIKIDO_TRUST_PROXY=false ./your-app
```

If your infrastructure uses a different header to carry the real client IP, set `AIKIDO_CLIENT_IP_HEADER` to its name:

```bash
# For DigitalOcean App Platform
AIKIDO_CLIENT_IP_HEADER=do-connecting-ip ./your-app
```

| Environment variable | Default | Description |
|---|---|---|
| `AIKIDO_TRUST_PROXY` | `true` | Trust proxy headers to determine the client IP |
| `AIKIDO_CLIENT_IP_HEADER` | `X-Forwarded-For` | Header name to read the client IP from |
