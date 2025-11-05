package main

import (
	"html/template"
	"net/http"
)

func defineStaticRoutes(mux *http.ServeMux) {
	tmpl := template.Must(template.ParseGlob("html/*.html"))

	renderHTML := func(w http.ResponseWriter, tmplName string) {
		err := tmpl.ExecuteTemplate(w, tmplName, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, "index.html")
	})
	mux.HandleFunc("/pages/execute", func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, "execute_command.html")
	})
	mux.HandleFunc("/pages/create", func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, "create.html")
	})
	mux.HandleFunc("/pages/request", func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, "request.html")
	})
	mux.HandleFunc("/pages/read", func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, "read_file.html")
	})
}
