package main

import (
	"github.com/gofiber/fiber/v3"
)

func defineStaticRoutes(app *fiber.App) {
	app.Get("/", func(c fiber.Ctx) error {
		return c.SendString("fiber-v3-postgres sample app")
	})
}
