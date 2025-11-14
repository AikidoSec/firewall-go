package agent

import (
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

// List of routes and their methods and count of calls collect from the requests
// [method][route] = hits
var routes = make(map[string]map[string]*aikido_types.Route)

// Routes mutex used to sync access to routes data across the go routines
var routesMutex sync.Mutex

func storeRoute(method string, route string, apiSpec *aikido_types.APISpec) {
	routesMutex.Lock()
	defer routesMutex.Unlock()

	if _, ok := routes[route]; !ok {
		routes[route] = make(map[string]*aikido_types.Route)
	}
	routeData, ok := routes[route][method]
	if !ok {
		routeData = &aikido_types.Route{Path: route, Method: method}
		routes[route][method] = routeData
	}

	routeData.Hits++
	routeData.APISpec = getMergedAPISpec(routeData.APISpec, apiSpec)
}

func GetRoutesAndClear() []aikido_types.Route {
	routesMutex.Lock()
	defer routesMutex.Unlock()

	var result []aikido_types.Route
	for _, methodsMap := range routes {
		for _, routeData := range methodsMap {
			if routeData.Hits == 0 {
				continue
			}
			result = append(result, *routeData)
			routeData.Hits = 0
		}
	}

	// Clear routes data
	routes = make(map[string]map[string]*aikido_types.Route)
	return result
}
