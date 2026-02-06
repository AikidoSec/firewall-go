# Echo Web Framework

## Installation

If you haven't already, follow the [installation instructions](../README.md#installation) in the main README.

## Setting a user
If you want to use user-blocking, know which user performed an attack and rate-limit on a user basis, you have to set  a user using the following function :
```go
// Setting a user : 
zen.SetUser(c.Request().Context(), id, name)

// So an example for Bob with id 1 :
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
