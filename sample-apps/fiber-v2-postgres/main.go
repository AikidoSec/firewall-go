package main

import (
	"log"
	"os"

	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gofiber/fiber/v2"
)

var db *DatabaseHelper

func main() {
	err := zen.Protect()
	if err != nil {
		log.Fatal(err)
	}

	db = NewDatabaseHelper()

	app := fiber.New()

	app.Use(SetUserMiddleware())
	app.Use(RateLimitMiddleware())

	defineStaticRoutes(app)
	defineAPIRoutes(app, db)

	port := os.Getenv("PORT")
	if err = app.Listen(":" + port); err != nil {
		log.Fatal(err)
	}
}

func SetUserMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if userID := c.Get("user"); userID != "" {
			_, err := zen.SetUser(c.UserContext(), userID, "John Doe")
			if err != nil {
				log.Println(err)
				return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
			}
		}
		return c.Next()
	}
}

func RateLimitMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		blockResult := zen.ShouldBlockRequest(c.UserContext())
		if blockResult != nil {
			switch blockResult.Type {
			case "rate-limited":
				message := "You are rate limited by Zen."
				if blockResult.Trigger == "ip" {
					message += " (Your IP: " + *blockResult.IP + ")"
				}
				return c.Status(fiber.StatusTooManyRequests).SendString(message)
			case "blocked":
				return c.Status(fiber.StatusForbidden).SendString("You are blocked by Zen.")
			}
		}
		return c.Next()
	}
}
