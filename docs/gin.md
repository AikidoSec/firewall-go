# Gin Web Framework

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
