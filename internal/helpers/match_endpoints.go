package helpers

import (
	. "github.com/AikidoSec/zen-internals-agent/aikido_types"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// RouteMetadata represents a limited context with URL, method, and route.
type RouteMetadata struct {
	URL    string
	Method string
	Route  string
}

// MatchEndpoints finds matching endpoints based on the provided context.
func MatchEndpoints(context RouteMetadata, endpoints []Endpoint) []Endpoint {
	var matches []Endpoint

	if context.Method == "" {
		return matches
	}

	// Filter possible endpoints based on method
	var possible []Endpoint
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

	if context.URL != "" {
		// Match the pathname
		path := tryParseURLPath(context.URL)
		var wildcards []Endpoint

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
			if regex.MatchString(path) {
				matches = append(matches, wildcard)
			}
		}
	}

	return matches
}

// tryParseURLPath extracts the path from a given URL.
func tryParseURLPath(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		// If there's an error in parsing, return an empty string or handle it as needed
		return ""
	}

	// Return the path component of the URL
	return parsedURL.Path
}
