package main

import (
	"github.com/gin-gonic/gin"
)

var db *DatabaseHelper

func main() {
	db = NewDatabaseHelper()
	// Set up Gin router
	r := gin.Default()

	defineStaticRoutes(r)
	defineApiRoutes(r, db)

	// Start the server
	r.Run(":8080")
}
