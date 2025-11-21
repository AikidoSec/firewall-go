package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/AikidoSec/firewall-go/zen"
)

var db *DatabaseHelper

func main() {
	err := zen.Protect()
	if err != nil {
		log.Fatal(err)
	}

	db = NewDatabaseHelper()

	// Set up native router
	mux := http.NewServeMux()

	// Wrap the router with middleware
	handler := SetUserMiddleware(mux)
	handler = RateLimitMiddleware(handler)

	// Define routes
	defineStaticRoutes(mux)
	defineAPIRoutes(mux, db)

	// Start the server
	port := os.Getenv("PORT")

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Starting HTTP server on :%s\n", port)
	if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func SetUserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("user") != "" {
			zen.SetUser(r.Context(), r.Header.Get("user"), "John Doe")
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware is now a standard http.Handler wrapper
func RateLimitMiddleware(next http.Handler) http.Handler {
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
