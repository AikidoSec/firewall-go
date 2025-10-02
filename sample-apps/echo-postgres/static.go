package main

import (
	"github.com/labstack/echo/v4"
)

func defineStaticRoutes(e *echo.Echo) {
	// Define routes
	e.File("/", "html/index.html")
	e.File("/pages/execute", "html/execute_command.html")
	e.File("/pages/create", "html/create.html")
	e.File("/pages/request", "html/request.html")
	e.File("/pages/read", "html/read_file.html")
}
