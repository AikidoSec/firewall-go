package main

import (
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func defineStaticRoutes(r *chi.Mux) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("html/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	})

	r.Get("/pages/execute", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("html/execute_command.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	})

	r.Get("/pages/create", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("html/create.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	})

	r.Get("/pages/request", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("html/request.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	})

	r.Get("/pages/read", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("html/read_file.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	})
}

