package main

import (
	"fmt"
	"net/url"

	"github.com/gofiber/fiber/v2"
)

type CreateRequest struct {
	Name string `json:"name"`
}

type RequestRequest struct {
	URL string `json:"url"`
}

func defineAPIRoutes(app *fiber.App, db *DatabaseHelper) {
	app.Get("/api/pets", func(c *fiber.Ctx) error {
		pets, err := db.GetAllPets(c.UserContext())
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(pets)
	})

	app.Post("/api/create", func(c *fiber.Ctx) error {
		var req CreateRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		rowsCreated, err := db.CreatePetByName(c.UserContext(), req.Name)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendString(fmt.Sprintf("%d", rowsCreated))
	})

	app.Post("/api/execute", func(c *fiber.Ctx) error {
		userCommand := c.FormValue("user_command")
		if userCommand == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_command is required"})
		}
		result, err := executeShellCommand(userCommand)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendString(result)
	})

	app.Get("/api/execute/:command", func(c *fiber.Ctx) error {
		userCommand := c.Params("command")
		result, err := executeShellCommand(userCommand)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendString(result)
	})

	app.Post("/api/request", func(c *fiber.Ctx) error {
		var req RequestRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		response := makeHTTPRequest(req.URL)
		return c.SendString(response)
	})

	app.Get("/api/read", func(c *fiber.Ctx) error {
		filePath := c.Query("path")
		content, err := readFile(filePath)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendString(content)
	})

	app.Get("/api/read_double", func(c *fiber.Ctx) error {
		filePath, _ := url.QueryUnescape(c.Query("path"))
		content, err := readFile(filePath)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendString(content)
	})
}
