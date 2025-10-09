package main

import (
	"fmt"
	"net/http"

	"github.com/AikidoSec/firewall-go/zen"
	"github.com/labstack/echo/v4"
)

var db *DatabaseHelper

func main() {
	zen.Init()
	db = NewDatabaseHelper()
	// Set up Echo router
	e := echo.New()
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userHeader := c.Request().Header.Get("user")
			fmt.Println("userHeader:", userHeader)
			if userHeader != "" {
				zen.SetUser(c.Request().Context(), userHeader, "Bob example")
			}
			return next(c)
		}
	})
	e.Use(AikidoMiddleware())
	defineStaticRoutes(e)
	defineAPIRoutes(e, db)

	// Start the server
	e.Start(":8082")
}

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
