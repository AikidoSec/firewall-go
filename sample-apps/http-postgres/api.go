package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type CreateRequest struct {
	Name string `json:"name"`
}

type RequestRequest struct {
	URL string `json:"url"`
}

func getAllPetsHandler(w http.ResponseWriter, r *http.Request, db *DatabaseHelper) {
	pets, err := db.GetAllPets(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(pets); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func createPetHandler(w http.ResponseWriter, r *http.Request, db *DatabaseHelper) {
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
	if _, err := w.Write([]byte(fmt.Sprintf("%d", rowsCreated))); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func executeCommandHandler(w http.ResponseWriter, r *http.Request) {
	userCommand := r.FormValue("user_command")
	if userCommand == "" {
		http.Error(w, "user_command is required", http.StatusBadRequest)
		return
	}
	result := executeShellCommand(userCommand)
	if _, err := w.Write([]byte(result)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func executeCommandParamHandler(w http.ResponseWriter, r *http.Request, command string) {
	result := executeShellCommand(command)
	if _, err := w.Write([]byte(result)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func makeRequestHandler(w http.ResponseWriter, r *http.Request) {
	var req RequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	response := makeHTTPRequest(req.URL)
	if _, err := w.Write([]byte(response)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func readFileHandler(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	content := readFile(filePath)
	if _, err := w.Write([]byte(content)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func defineAPIRoutes(mux *http.ServeMux, db *DatabaseHelper) {
	mux.HandleFunc("/api/pets/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			getAllPetsHandler(w, r, db)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/create", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			createPetHandler(w, r, db)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/execute", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			executeCommandHandler(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/execute/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			command := r.URL.Path[len("/api/execute/"):]
			executeCommandParamHandler(w, r, command)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/request", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			makeRequestHandler(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/read", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			readFileHandler(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
