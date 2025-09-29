package main

import (
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/labstack/echo/v4"
)

var db *DatabaseHelper

func main() {
	zen.Init()
	db = NewDatabaseHelper()
	// Set up Echo router
	e := echo.New()

	defineStaticRoutes(e)
	defineApiRoutes(e, db)

	// Start the server
	e.Start(":8082")
}
