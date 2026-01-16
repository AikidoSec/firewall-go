package main

import (
	"log"
	"net/http"
	"os"

	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gin-gonic/gin"
)

var db *DatabaseHelper

func main() {
	err := zen.Protect()
	if err != nil {
		log.Fatal(err)
	}

	db = NewDatabaseHelper()
	// Set up Gin router
	r := gin.Default()

	// Must be enabled to ensure Gin properly respects request contexts
	r.ContextWithFallback = true

	r.Use(func(c *gin.Context) {
		if c.GetHeader("user") != "" {
			_, err = zen.SetUser(c, c.GetHeader("user"), "John Doe")
			if err != nil {
				log.Println(err)
				_ = c.AbortWithError(http.StatusInternalServerError, err)
				return
			}
		}
	})
	r.Use(RateLimitMiddleware())

	defineStaticRoutes(r)
	defineAPIRoutes(r, db)

	// Start the server
	err = r.Run(":" + os.Getenv("PORT"))
	if err != nil {
		log.Fatal(err)
	}
}

func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		blockResult := zen.ShouldBlockRequest(c)

		if blockResult != nil {
			switch blockResult.Type {
			case "rate-limited":
				message := "You are rate limited by Zen."
				if blockResult.Trigger == "ip" {
					message += " (Your IP: " + *blockResult.IP + ")"
				}
				c.String(http.StatusTooManyRequests, message)
				c.Abort() // Stop further processing
				return
			case "blocked":
				c.String(http.StatusForbidden, "You are blocked by Zen.")
				c.Abort() // Stop further processing
				return
			}
		}

		c.Next()
	}
}
