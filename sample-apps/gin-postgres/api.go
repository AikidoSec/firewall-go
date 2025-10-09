package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
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

func defineAPIRoutes(r *gin.Engine, db *DatabaseHelper) {
	r.GET("/api/pets", func(c *gin.Context) {
		pets, err := db.GetAllPets(c) // Assuming GetAllPets returns an error
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, pets)
	})

	r.POST("/api/create", func(c *gin.Context) {
		var req CreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		rowsCreated, _ := db.CreatePetByName(c, req.Name)
		c.String(http.StatusOK, "%d", rowsCreated)
	})

	r.POST("/api/execute", func(c *gin.Context) {
		userCommand := c.PostForm("user_command")

		if userCommand == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user_command is required"})
			return
		}

		result := executeShellCommand(userCommand)
		c.String(http.StatusOK, result)
	})

	r.GET("/api/execute/:command", func(c *gin.Context) {
		userCommand := c.Param("command")
		result := executeShellCommand(userCommand)
		c.String(http.StatusOK, result)
	})

	r.POST("/api/request", func(c *gin.Context) {
		var req RequestRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		response := makeHttpRequest(req.URL)
		c.String(http.StatusOK, response)
	})

	r.GET("/api/read", func(c *gin.Context) {
		filePath := c.Query("path")
		content := readFile(filePath)
		c.String(http.StatusOK, content)
	})
}
