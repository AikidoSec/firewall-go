package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AikidoSec/firewall-go/zen"
	"github.com/labstack/echo/v5"
)

var db *DatabaseHelper

func main() {
	err := zen.Protect()
	if err != nil {
		log.Fatal(err)
	}

	db = NewDatabaseHelper()
	// Set up Echo router
	e := echo.New()
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			userHeader := c.Request().Header.Get("user")
			fmt.Println("userHeader:", userHeader)
			if userHeader != "" {
				_, err = zen.SetUser(c.Request().Context(), userHeader, "Bob example")
				if err != nil {
					log.Println(err)
					return err
				}
			}
			return next(c)
		}
	})
	e.Use(AikidoMiddleware())
	defineStaticRoutes(e)
	defineAPIRoutes(e, db)

	// Start the server
	err = e.Start(":" + os.Getenv("PORT"))
	if err != nil {
		log.Fatal(err)
	}
}

func AikidoMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			blockResult := zen.ShouldBlockRequest(c.Request().Context())

			if blockResult != nil {
				switch blockResult.Type {
				case "rate-limited":
					message := "You are rate limited by Zen."
					if blockResult.Trigger == "ip" {
						message += " (Your IP: " + *blockResult.IP + ")"
					}
					return c.String(http.StatusTooManyRequests, message)
				case "blocked":
					return c.String(http.StatusForbidden, "You are blocked by Zen.")
				}
			}

			return next(c)
		}
	}
}
