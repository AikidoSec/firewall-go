package main

import (
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gin-gonic/gin"
	"net/http"
)

var db *DatabaseHelper

func main() {
	zen.Init()
	db = NewDatabaseHelper()
	// Set up Gin router
	r := gin.Default()
	r.Use(RateLimitMiddleware())

	defineStaticRoutes(r)
	defineApiRoutes(r, db)

	// Start the server
	r.Run(":8080")
}

func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		blockResult := zen.ShouldBlockRequest()

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

		c.Next() // Proceed to the next middleware/handler if not blocked
	}
}
