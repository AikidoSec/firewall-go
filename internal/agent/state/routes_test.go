package state

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreRoute(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		route        string
		apiSpec      *aikido_types.APISpec
		expectedHits int64
		calls        int
		setupRoutes  map[string]map[string]*aikido_types.Route
	}{
		{
			name:         "stores new route",
			method:       "GET",
			route:        "/api/users",
			apiSpec:      nil,
			expectedHits: 1,
			calls:        1,
		},
		{
			name:         "handles different methods for same route",
			method:       "POST",
			route:        "/api/users",
			apiSpec:      nil,
			expectedHits: 1,
			calls:        1,
			setupRoutes: map[string]map[string]*aikido_types.Route{
				"/api/users": {
					"GET": &aikido_types.Route{Path: "/api/users", Method: "GET", Hits: 10},
				},
			},
		},
		{
			name:         "multiple calls to same route and method",
			method:       "GET",
			route:        "/api/users",
			apiSpec:      nil,
			expectedHits: 5,
			calls:        5,
		},
		{
			name:   "stores route with API spec",
			method: "POST",
			route:  "/api/users",
			apiSpec: &aikido_types.APISpec{
				Body: &aikido_types.APIBodyInfo{
					Type: "application/json",
					Schema: &aikido_types.DataSchema{
						Type: []string{"object"},
					},
				},
			},
			expectedHits: 1,
			calls:        1,
		},
		{
			name:   "merges API specs on multiple calls",
			method: "POST",
			route:  "/api/users",
			apiSpec: &aikido_types.APISpec{
				Query: &aikido_types.DataSchema{
					Type: []string{"object"},
				},
			},
			expectedHits: 3, // 1 from setup + 2 new calls
			calls:        2,
			setupRoutes: map[string]map[string]*aikido_types.Route{
				"/api/users": {
					"POST": &aikido_types.Route{
						Path:   "/api/users",
						Method: "POST",
						Hits:   1,
						APISpec: &aikido_types.APISpec{
							Body: &aikido_types.APIBodyInfo{
								Type: "application/json",
							},
						},
					},
				},
			},
		},
		{
			name:         "handles empty route string",
			method:       "GET",
			route:        "",
			apiSpec:      nil,
			expectedHits: 1,
			calls:        1,
		},
		{
			name:         "handles empty method string",
			method:       "",
			route:        "/api/users",
			apiSpec:      nil,
			expectedHits: 1,
			calls:        1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCollector()

			if tt.setupRoutes != nil {
				c.routes = tt.setupRoutes
			}

			for i := 0; i < tt.calls; i++ {
				c.StoreRoute(tt.method, tt.route, tt.apiSpec)
			}

			result := c.GetRoutesAndClear()

			// Find the route in results
			found := false
			for _, r := range result {
				if r.Path == tt.route && r.Method == tt.method {
					assert.Equal(t, tt.expectedHits, r.Hits, "hits should match expected value")
					found = true
					break
				}
			}
			require.True(t, found, "route %s %s should be stored", tt.method, tt.route)
		})
	}
}

func TestGetRoutesAndClear(t *testing.T) {
	tests := []struct {
		name          string
		setupRoutes   map[string]map[string]*aikido_types.Route
		expectedCount int
		shouldContain []struct {
			method string
			route  string
			hits   int64
		}
	}{
		{
			name:          "returns empty slice when no routes",
			setupRoutes:   map[string]map[string]*aikido_types.Route{},
			expectedCount: 0,
		},
		{
			name: "returns single route",
			setupRoutes: map[string]map[string]*aikido_types.Route{
				"/api/users": {
					"GET": &aikido_types.Route{Path: "/api/users", Method: "GET", Hits: 5},
				},
			},
			expectedCount: 1,
			shouldContain: []struct {
				method string
				route  string
				hits   int64
			}{
				{method: "GET", route: "/api/users", hits: 5},
			},
		},
		{
			name: "returns multiple routes",
			setupRoutes: map[string]map[string]*aikido_types.Route{
				"/api/users": {
					"GET":  &aikido_types.Route{Path: "/api/users", Method: "GET", Hits: 5},
					"POST": &aikido_types.Route{Path: "/api/users", Method: "POST", Hits: 3},
				},
				"/api/posts": {
					"GET": &aikido_types.Route{Path: "/api/posts", Method: "GET", Hits: 10},
				},
			},
			expectedCount: 3,
			shouldContain: []struct {
				method string
				route  string
				hits   int64
			}{
				{method: "GET", route: "/api/users", hits: 5},
				{method: "POST", route: "/api/users", hits: 3},
				{method: "GET", route: "/api/posts", hits: 10},
			},
		},
		{
			name: "skips routes with zero hits",
			setupRoutes: map[string]map[string]*aikido_types.Route{
				"/api/users": {
					"GET":  &aikido_types.Route{Path: "/api/users", Method: "GET", Hits: 5},
					"POST": &aikido_types.Route{Path: "/api/users", Method: "POST", Hits: 0},
				},
			},
			expectedCount: 1,
			shouldContain: []struct {
				method string
				route  string
				hits   int64
			}{
				{method: "GET", route: "/api/users", hits: 5},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCollector()
			c.routes = tt.setupRoutes

			result := c.GetRoutesAndClear()

			assert.Len(t, result, tt.expectedCount, "should return expected number of routes")

			for _, expected := range tt.shouldContain {
				found := false
				for _, r := range result {
					if r.Path == expected.route && r.Method == expected.method {
						assert.Equal(t, expected.hits, r.Hits, "hits should match for %s %s", expected.method, expected.route)
						found = true
						break
					}
				}
				require.True(t, found, "should contain route %s %s", expected.method, expected.route)
			}

			// Verify routes were cleared
			secondResult := c.GetRoutesAndClear()
			assert.Empty(t, secondResult, "second call should return empty slice after clearing")
		})
	}
}

func TestGetMergedAPISpec(t *testing.T) {
	tests := []struct {
		name           string
		currentAPISpec *aikido_types.APISpec
		newAPISpec     *aikido_types.APISpec
		expectNil      bool
		checkBodyType  string
		checkHasBody   bool
		checkHasQuery  bool
		checkHasAuth   bool
	}{
		{
			name:           "returns new spec when current is nil",
			currentAPISpec: nil,
			newAPISpec: &aikido_types.APISpec{
				Body: &aikido_types.APIBodyInfo{
					Type:   "application/json",
					Schema: &aikido_types.DataSchema{Type: []string{"object"}},
				},
			},
			expectNil:     false,
			checkBodyType: "application/json",
			checkHasBody:  true,
		},
		{
			name: "returns current spec when new is nil",
			currentAPISpec: &aikido_types.APISpec{
				Body: &aikido_types.APIBodyInfo{
					Type:   "application/json",
					Schema: &aikido_types.DataSchema{Type: []string{"object"}},
				},
			},
			newAPISpec:    nil,
			expectNil:     false,
			checkBodyType: "application/json",
			checkHasBody:  true,
		},
		{
			name:           "returns nil when both are nil",
			currentAPISpec: nil,
			newAPISpec:     nil,
			expectNil:      true,
		},
		{
			name: "prefers new body type over current",
			currentAPISpec: &aikido_types.APISpec{
				Body: &aikido_types.APIBodyInfo{
					Type:   "application/json",
					Schema: &aikido_types.DataSchema{Type: []string{"object"}},
				},
			},
			newAPISpec: &aikido_types.APISpec{
				Body: &aikido_types.APIBodyInfo{
					Type:   "application/xml",
					Schema: &aikido_types.DataSchema{Type: []string{"object"}},
				},
			},
			expectNil:     false,
			checkBodyType: "application/xml",
		},
		{
			name: "uses current body type when new is empty",
			currentAPISpec: &aikido_types.APISpec{
				Body: &aikido_types.APIBodyInfo{
					Type:   "application/json",
					Schema: &aikido_types.DataSchema{Type: []string{"object"}},
				},
			},
			newAPISpec: &aikido_types.APISpec{
				Body: &aikido_types.APIBodyInfo{
					Type:   "",
					Schema: &aikido_types.DataSchema{Type: []string{"object"}},
				},
			},
			expectNil:     false,
			checkBodyType: "application/json",
		},
		{
			name: "merges query schemas",
			currentAPISpec: &aikido_types.APISpec{
				Query: &aikido_types.DataSchema{Type: []string{"object"}},
			},
			newAPISpec: &aikido_types.APISpec{
				Query: &aikido_types.DataSchema{Type: []string{"object"}},
			},
			expectNil:     false,
			checkHasQuery: true,
		},
		{
			name: "merges auth types",
			currentAPISpec: &aikido_types.APISpec{
				Auth: []*aikido_types.APIAuthType{
					{Type: "bearer"},
				},
			},
			newAPISpec: &aikido_types.APISpec{
				Auth: []*aikido_types.APIAuthType{
					{Type: "apiKey"},
				},
			},
			expectNil:    false,
			checkHasAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getMergedAPISpec(tt.currentAPISpec, tt.newAPISpec)

			if tt.expectNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)

			if tt.checkBodyType != "" {
				require.NotNil(t, result.Body)
				assert.Equal(t, tt.checkBodyType, result.Body.Type)
			}

			if tt.checkHasBody {
				assert.NotNil(t, result.Body)
			}

			if tt.checkHasQuery {
				assert.NotNil(t, result.Query)
			}

			if tt.checkHasAuth {
				assert.NotNil(t, result.Auth)
			}
		})
	}
}

func TestGetAPISpecData_NilSpec(t *testing.T) {
	schema, bodyType, query, auth := getAPISpecData(nil)

	require.Nil(t, schema)
	require.Empty(t, bodyType)
	require.Nil(t, query)
	require.Nil(t, auth)
}
