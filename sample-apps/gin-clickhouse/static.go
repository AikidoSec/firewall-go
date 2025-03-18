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

	r.GET("/pages/create", func(c *gin.Context) {
		c.HTML(http.StatusOK, "create.html", gin.H{})
	})
}
