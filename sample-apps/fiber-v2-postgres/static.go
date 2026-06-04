package main

import (
	"github.com/gofiber/fiber/v2"
)

func defineStaticRoutes(app *fiber.App) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("fiber-v2-postgres sample app")
	})
}
