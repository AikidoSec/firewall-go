package cloud

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_sendCloudRequest(t *testing.T) {
	t.Run("successful request", func(t *testing.T) {
		tests := []struct {
			name    string
			payload any
			method  string
		}{
			{
				name:    "with JSON payload",
				payload: map[string]string{"key": "value"},
				method:  "POST",
			},
			{
				name:    "with nil payload",
				payload: nil,
				method:  "GET",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				expectedResponse := map[string]string{"status": "success"}
				responseBody, _ := json.Marshal(expectedResponse)

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, tt.method, r.Method)
					assert.Equal(t, "test-token", r.Header.Get("Authorization"))
					assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

					if tt.payload != nil {
						body, err := io.ReadAll(r.Body)
						require.NoError(t, err)
						assert.NotEmpty(t, body)
					}

					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(responseBody)
				}))
				defer server.Close()

				client := &Client{
					httpClient: &http.Client{Timeout: 30 * time.Second},
					token:      "test-token",
				}

				result, err := client.sendCloudRequest(server.URL, "/api/test", tt.method, tt.payload)

				require.NoError(t, err)
				assert.JSONEq(t, string(responseBody), string(result))
			})
		}
	})

	t.Run("request validation", func(t *testing.T) {
		tests := []struct {
			name          string
			token         string
			endpoint      string
			route         string
			payload       any
			expectedError string
			errorCheck    func(error) bool
		}{
			{
				name:          "no token set",
				token:         "",
				endpoint:      "http://localhost",
				route:         "/api/test",
				payload:       nil,
				expectedError: "no token set",
				errorCheck:    func(err error) bool { return errors.Is(err, ErrNoTokenSet) },
			},
			{
				name:          "invalid payload",
				token:         "test-token",
				endpoint:      "http://localhost",
				route:         "/api/test",
				payload:       make(chan int), // channels cannot be marshaled to JSON
				expectedError: "failed to marshal payload",
				errorCheck:    nil,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				client := &Client{
					httpClient: &http.Client{Timeout: 30 * time.Second},
					token:      tt.token,
				}

				result, err := client.sendCloudRequest(tt.endpoint, tt.route, "POST", tt.payload)

				assert.Nil(t, result)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				if tt.errorCheck != nil {
					assert.True(t, tt.errorCheck(err))
				}
			})
		}
	})

	t.Run("HTTP status codes", func(t *testing.T) {
		tests := []struct {
			name       string
			statusCode int
			statusText string
		}{
			{
				name:       "400 Bad Request",
				statusCode: http.StatusBadRequest,
				statusText: "400 Bad Request",
			},
			{
				name:       "401 Unauthorized",
				statusCode: http.StatusUnauthorized,
				statusText: "401 Unauthorized",
			},
			{
				name:       "404 Not Found",
				statusCode: http.StatusNotFound,
				statusText: "404 Not Found",
			},
			{
				name:       "500 Internal Server Error",
				statusCode: http.StatusInternalServerError,
				statusText: "500 Internal Server Error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.statusCode)
				}))
				defer server.Close()

				client := &Client{
					httpClient: &http.Client{Timeout: 30 * time.Second},
					token:      "test-token",
				}

				result, err := client.sendCloudRequest(server.URL, "/api/test", "POST", nil)

				assert.Nil(t, result)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "received non-OK response")
				assert.Contains(t, err.Error(), tt.statusText)
			})
		}
	})

	t.Run("network errors", func(t *testing.T) {
		t.Run("connection refused", func(t *testing.T) {
			// Create a server that closes immediately to simulate connection error
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			serverURL := server.URL
			server.Close()

			client := &Client{
				httpClient: &http.Client{Timeout: 30 * time.Second},
				token:      "test-token",
			}

			result, err := client.sendCloudRequest(serverURL, "/api/test", "POST", nil)

			assert.Nil(t, result)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to make request")
		})
	})

	t.Run("request headers", func(t *testing.T) {
		tests := []struct {
			name          string
			token         string
			expectedToken string
		}{
			{
				name:          "simple token",
				token:         "test-token",
				expectedToken: "test-token",
			},
			{
				name:          "Bearer token",
				token:         "Bearer my-secret-token",
				expectedToken: "Bearer my-secret-token",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var capturedToken string

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					capturedToken = r.Header.Get("Authorization")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{}`))
				}))
				defer server.Close()

				client := &Client{
					httpClient: &http.Client{Timeout: 30 * time.Second},
					token:      tt.token,
				}

				_, err := client.sendCloudRequest(server.URL, "/api/test", "POST", nil)

				require.NoError(t, err)
				assert.Equal(t, tt.expectedToken, capturedToken)
			})
		}
	})

	t.Run("route concatenation", func(t *testing.T) {
		var capturedPath string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer server.Close()

		client := &Client{
			httpClient: &http.Client{Timeout: 30 * time.Second},
			token:      "test-token",
		}

		_, err := client.sendCloudRequest(server.URL, "/api/runtime/events", "POST", nil)

		require.NoError(t, err)
		assert.Equal(t, "/api/runtime/events", capturedPath)
	})
}
