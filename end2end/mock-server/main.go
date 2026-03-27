package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	mu     sync.Mutex
	events []json.RawMessage
)

var configUpdatedAt = time.Now().UnixMilli()

func cloudConfigResponse() map[string]any {
	return map[string]any{
		"success":                  true,
		"serviceId":                1,
		"configUpdatedAt":          configUpdatedAt,
		"heartbeatIntervalInMS":    30000,
		"endpoints":                []any{},
		"blockedUserIds":           []any{},
		"allowedIPAddresses":       []any{},
		"receivedAnyStats":         false,
		"blockNewOutgoingRequests": false,
		"domains":                  []any{},
	}
}

func listsConfigResponse() map[string]any {
	return map[string]any{
		"success":              true,
		"serviceId":            1,
		"blockedIPAddresses":   []any{},
		"monitoredIPAddresses": []any{},
		"blockedUserAgents":    "",
		"monitoredUserAgents":  "",
		"allowedIPAddresses":   []any{},
		"userAgentDetails":     []any{},
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("error writing JSON response: %v", err)
	}
}

func handleEvent(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	mu.Lock()
	events = append(events, raw)
	mu.Unlock()

	writeJSON(w, cloudConfigResponse())
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, cloudConfigResponse())
}

func handleLists(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, listsConfigResponse())
}

func handleConfigUpdatedAt(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"serviceId":       1,
		"configUpdatedAt": configUpdatedAt,
	})
}

func handleGetEvents(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	snapshot := make([]json.RawMessage, len(events))
	copy(snapshot, events)
	mu.Unlock()

	writeJSON(w, snapshot)
}

func handleDeleteEvents(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	events = events[:0]
	mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func main() {
	port := os.Getenv("MOCK_SERVER_PORT")
	if port == "" {
		port = "9090"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/runtime/events", handleEvent)
	mux.HandleFunc("GET /api/runtime/config", handleConfig)
	mux.HandleFunc("GET /api/runtime/firewall/lists", handleLists)
	mux.HandleFunc("GET /config", handleConfigUpdatedAt)
	mux.HandleFunc("GET /mock/events", handleGetEvents)
	mux.HandleFunc("DELETE /mock/events", handleDeleteEvents)

	server := &http.Server{
		Addr:        ":" + port,
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
	}
	log.Printf("Mock server listening on :%s", port) // #nosec G706 - port is a trusted env var, not user-controlled input
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
