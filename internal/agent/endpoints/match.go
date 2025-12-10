package endpoints

import (
	"regexp"
	"sort"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

// RouteMetadata represents a limited context with method, and route.
type RouteMetadata struct {
	Method string
	Route  string
}

// FindMatches finds matching endpoints from a provided list based on the context.
// This is the core matching logic that can be reused with any endpoint list.
func FindMatches(endpoints []aikido_types.Endpoint, context RouteMetadata) []aikido_types.Endpoint {
	var matches []aikido_types.Endpoint

	if context.Method == "" {
		return matches
	}

	// Filter possible endpoints based on method
	var possible []aikido_types.Endpoint
	for _, endpoint := range endpoints {
		if endpoint.Method == "*" || endpoint.Method == context.Method {
			possible = append(possible, endpoint)
		}
	}

	// Sort so that exact method matches come first before wildcard matches
	sort.Slice(possible, func(i, j int) bool {
		if possible[i].Method == possible[j].Method {
			return false
		}
		return possible[i].Method != "*" // exact matches come first
	})

	// Check for exact matches
	for _, endpoint := range possible {
		if endpoint.Route == context.Route {
			matches = append(matches, endpoint)
		}
	}

	var wildcards []aikido_types.Endpoint

	// Filter wildcards and sort by the number of '*' in the route
	for _, endpoint := range possible {
		if strings.Contains(endpoint.Route, "*") {
			wildcards = append(wildcards, endpoint)
		}
	}

	sort.Slice(wildcards, func(i, j int) bool {
		return strings.Count(wildcards[i].Route, "*") > strings.Count(wildcards[j].Route, "*")
	})

	// Check wildcards
	for _, wildcard := range wildcards {
		regex := regexp.MustCompile("^" + strings.ReplaceAll(wildcard.Route, "*", "(.*)") + "/?$")
		if regex.MatchString(context.Route) {
			matches = append(matches, wildcard)
		}
	}

	return matches
}
