package main

import (
	"log"
	"net/http"
	"os"

	"github.com/AikidoSec/firewall-go/zen"
	"github.com/go-chi/chi/v5"
)

var db *DatabaseHelper

func main() {
	err := zen.Protect()
	if err != nil {
		log.Fatal(err)
	}

	db = NewDatabaseHelper()
	// Set up Chi router
	r := chi.NewRouter()

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("user") != "" {
				_, err := zen.SetUser(r.Context(), r.Header.Get("user"), "John Doe")
				if err != nil {
					log.Println(err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	r.Use(RateLimitMiddleware())

	defineStaticRoutes(r)
	defineAPIRoutes(r, db)

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	err = http.ListenAndServe(":"+port, r)
	if err != nil {
		log.Fatal(err)
	}
}

func RateLimitMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			blockResult := zen.ShouldBlockRequest(r.Context())

			if blockResult != nil {
				if blockResult.Type == "rate-limited" {
					message := "You are rate limited by Zen."
					if blockResult.Trigger == "ip" {
						message += " (Your IP: " + *blockResult.IP + ")"
					}
					http.Error(w, message, http.StatusTooManyRequests)
					return
				} else if blockResult.Type == "blocked" {
					http.Error(w, "You are blocked by Zen.", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
