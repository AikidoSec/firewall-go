package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type CreateRequest struct {
	Name string `json:"name"`
}

func defineApiRoutes(r *gin.Engine, db *DatabaseHelper) {
	r.GET("/api/pets", func(c *gin.Context) {
		pets, err := db.GetAllPets() // Assuming GetAllPets returns an error
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
		rowsCreated, err := db.CreatePetByName(req.Name)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.String(http.StatusOK, "%d", rowsCreated)
	})
}
