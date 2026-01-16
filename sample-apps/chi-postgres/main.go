package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

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
				_, err = zen.SetUser(r.Context(), r.Header.Get("user"), "John Doe")
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

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Starting HTTP server on :%s\n", port)
	if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func RateLimitMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			blockResult := zen.ShouldBlockRequest(r.Context())

			if blockResult != nil {
				switch blockResult.Type {
				case "rate-limited":
					message := "You are rate limited by Zen."
					if blockResult.Trigger == "ip" {
						message += " (Your IP: " + *blockResult.IP + ")"
					}
					http.Error(w, message, http.StatusTooManyRequests)
					return
				case "blocked":
					http.Error(w, "You are blocked by Zen.", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
