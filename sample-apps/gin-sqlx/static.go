package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func defineStaticRoutes(r *gin.Engine) {
	r.LoadHTMLGlob("html/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})

	r.GET("/pages/execute", func(c *gin.Context) {
		c.HTML(http.StatusOK, "execute_command.html", gin.H{})
	})

	r.GET("/pages/create", func(c *gin.Context) {
		c.HTML(http.StatusOK, "create.html", gin.H{})
	})

	r.GET("/pages/request", func(c *gin.Context) {
		c.HTML(http.StatusOK, "request.html", gin.H{})
	})

	r.GET("/pages/read", func(c *gin.Context) {
		c.HTML(http.StatusOK, "read_file.html", gin.H{})
	})
}

