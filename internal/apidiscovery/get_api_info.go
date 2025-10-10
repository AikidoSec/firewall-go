package apidiscovery

import (
	"reflect"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

func GetAPIInfo(ctx *request.Context) *aikido_types.APISpec {
	if !config.CollectAPISchema {
		log.Debug("Collection of API Discovery was disabled.")
		return nil
	}
	var bodyInfo *aikido_types.APIBodyInfo
	var queryInfo *aikido_types.DataSchema

	body := ctx.Body
	query := ctx.Query
	// Check body data
	if body != nil && isObject(body) {
		bodyType := getBodyDataType(ctx.Headers)
		if bodyType == BodyTypeUndefined {
			log.Debug("Body type is undefined -> no API schema!")
			return nil
		}
		bodySchema := GetDataSchema(body, 0)

		bodyInfo = &aikido_types.APIBodyInfo{
			Type:   string(bodyType),
			Schema: bodySchema,
		}
	}

	// Check query data
	if query != nil && isObject(query) && len(query) > 0 {
		queryInfo = GetDataSchema(query, 0)
	}

	// Get Auth Info
	authInfo := GetApiAuthType(ctx.Headers, ctx.Cookies)

	if bodyInfo == nil && queryInfo == nil && authInfo == nil {
		log.Debug("All sub-schemas are empty -> no API schema!")
		return nil
	}

	return &aikido_types.APISpec{
		Body:  bodyInfo,
		Query: queryInfo,
		Auth:  authInfo,
	}
}

func isObject(data any) bool {
	// Helper function to determine if the data is an object (map in Go)
	return reflect.TypeOf(data).Kind() == reflect.Map
}
