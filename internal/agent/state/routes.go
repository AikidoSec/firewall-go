package state

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/apidiscovery"
)

func (c *Collector) StoreRoute(method string, route string, apiSpec *aikido_types.APISpec) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.routes[route]; !ok {
		c.routes[route] = make(map[string]*aikido_types.Route)
	}
	routeData, ok := c.routes[route][method]
	if !ok {
		routeData = &aikido_types.Route{Path: route, Method: method}
		c.routes[route][method] = routeData
	}

	routeData.Hits++
	routeData.APISpec = getMergedAPISpec(routeData.APISpec, apiSpec)
}

func (c *Collector) GetRoutesAndClear() []aikido_types.Route {
	c.mu.Lock()
	defer c.mu.Unlock()

	var result []aikido_types.Route
	for _, methodsMap := range c.routes {
		for _, routeData := range methodsMap {
			if routeData.Hits == 0 {
				continue
			}
			result = append(result, *routeData)
			routeData.Hits = 0
		}
	}

	// Clear routes data
	c.routes = make(map[string]map[string]*aikido_types.Route)
	return result
}

func getAPISpecData(apiSpec *aikido_types.APISpec) (*aikido_types.DataSchema, string, *aikido_types.DataSchema, []*aikido_types.APIAuthType) {
	if apiSpec == nil {
		return nil, "", nil, nil
	}

	var bodyDataSchema *aikido_types.DataSchema = nil
	bodyType := ""
	if apiSpec.Body != nil {
		bodyDataSchema = apiSpec.Body.Schema
		bodyType = apiSpec.Body.Type
	}

	return bodyDataSchema, bodyType, apiSpec.Query, apiSpec.Auth
}

func getMergedAPISpec(currentAPISpec *aikido_types.APISpec, newAPISpec *aikido_types.APISpec) *aikido_types.APISpec {
	if newAPISpec == nil {
		return currentAPISpec
	}
	if currentAPISpec == nil {
		return newAPISpec
	}

	currentBodySchema, currentBodyType, currentQuerySchema, currentAuth := getAPISpecData(currentAPISpec)
	newBodySchema, newBodyType, newQuerySchema, newAuth := getAPISpecData(newAPISpec)

	mergedBodySchema := apidiscovery.MergeDataSchemas(currentBodySchema, newBodySchema)
	mergedQuerySchema := apidiscovery.MergeDataSchemas(currentQuerySchema, newQuerySchema)
	mergedAuth := apidiscovery.MergeAPIAuthTypes(currentAuth, newAuth)
	if mergedBodySchema == nil && mergedQuerySchema == nil && mergedAuth == nil {
		return nil
	}

	mergedBodyType := newBodyType
	if mergedBodyType == "" {
		mergedBodyType = currentBodyType
	}

	return &aikido_types.APISpec{
		Body: &aikido_types.APIBodyInfo{
			Type:   mergedBodyType,
			Schema: mergedBodySchema,
		},
		Query: mergedQuerySchema,
		Auth:  mergedAuth,
	}
}
