package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
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

func defineAPIRoutes(r *chi.Mux, db *DatabaseHelper) {
	r.Get("/api/pets", func(w http.ResponseWriter, r *http.Request) {
		pets, err := db.GetAllPets(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pets)
	})

	r.Post("/api/create", func(w http.ResponseWriter, r *http.Request) {
		var req CreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rowsCreated, err := db.CreatePetByName(r.Context(), req.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf("%d", rowsCreated)))
	})

	r.Post("/api/execute", func(w http.ResponseWriter, r *http.Request) {
		userCommand := r.FormValue("user_command")

		if userCommand == "" {
			http.Error(w, "user_command is required", http.StatusBadRequest)
			return
		}

		result := executeShellCommand(userCommand)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(result))
	})

	r.Get("/api/execute/{command}", func(w http.ResponseWriter, r *http.Request) {
		userCommand := chi.URLParam(r, "command")
		result := executeShellCommand(userCommand)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(result))
	})

	r.Post("/api/request", func(w http.ResponseWriter, r *http.Request) {
		var req RequestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		response := makeHTTPRequest(req.URL)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	})

	r.Get("/api/read", func(w http.ResponseWriter, r *http.Request) {
		filePath := r.URL.Query().Get("path")
		content := readFile(filePath)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	})
}
