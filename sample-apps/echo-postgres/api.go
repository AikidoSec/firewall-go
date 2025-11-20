package main

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

type CreateRequest struct {
	Name string `json:"name"`
}

type CommandRequest struct {
	UserCommand string `json:"userCommand"`
}

type RequestRequest struct {
	URL string `json:"url"`
}

func defineAPIRoutes(e *echo.Echo, db *DatabaseHelper) {
	e.GET("/api/pets/", func(c echo.Context) error {
		pets, err := db.GetAllPets(c.Request().Context()) // Assuming GetAllPets returns an error
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, pets)
	})

	e.POST("/api/create", func(c echo.Context) error {
		req := new(CreateRequest)
		if err := c.Bind(req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		rowsCreated, err := db.CreatePetByName(c.Request().Context(), req.Name)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.String(http.StatusOK, fmt.Sprint("%i", rowsCreated))
	})

	e.POST("/api/execute", func(c echo.Context) error {
		userCommand := c.FormValue("user_command")

		if userCommand == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "user_command is required"})
		}

		result, err := executeShellCommand(userCommand)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		return c.String(http.StatusOK, result)
	})

	e.GET("/api/execute/:command", func(c echo.Context) error {
		userCommand := c.Param("command")
		result, err := executeShellCommand(userCommand)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.String(http.StatusOK, result)
	})

	e.POST("/api/request", func(c echo.Context) error {
		req := new(RequestRequest)
		if err := c.Bind(req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		response, err := makeHTTPRequest(req.URL)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return c.String(http.StatusOK, response)
	})

	e.GET("/api/read", func(c echo.Context) error {
		filePath := c.QueryParam("path")
		fmt.Println("Opening file: ", filePath)
		content, err := readFile(filePath)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		fmt.Println("File content: ", content)
		return c.String(http.StatusOK, content)
	})
}
