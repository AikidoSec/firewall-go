package main

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
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

func defineApiRoutes(e *echo.Echo, db *DatabaseHelper) {
	e.GET("/api/pets/", func(c echo.Context) error {
		pets, err := db.GetAllPets() // Assuming GetAllPets returns an error
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
		rowsCreated, _ := db.CreatePetByName(req.Name)
		return c.String(http.StatusOK, string(rowsCreated))
	})

	e.POST("/api/execute", func(c echo.Context) error {
		req := new(CommandRequest)
		if err := c.Bind(req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		result, err := executeShellCommand(req.UserCommand)
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
		response, err := makeHttpRequest(req.URL)
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
