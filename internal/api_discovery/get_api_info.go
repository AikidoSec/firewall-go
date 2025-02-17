package api_discovery

import (
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/globals"
	"github.com/AikidoSec/firewall-go/internal/log"
	. "github.com/AikidoSec/firewall-go/internal/types"
	"github.com/AikidoSec/zen-internals-agent/ipc/protos"
	"reflect"
)

func GetApiInfo(ctx context.Context) *protos.APISpec {
	if !globals.EnvironmentConfig.CollectApiSchema {
		return nil
	}
	var bodyInfo *protos.APIBodyInfo
	var queryInfo *protos.DataSchema

	body := ctx.Body
	query := ctx.Query
	// Check body data
	if body != nil && isObject(body) {
		bodyType := getBodyDataType(ctx.Headers)
		if bodyType == Undefined {
			log.Debug("Body type is undefined -> no API schema!")
			return nil
		}
		bodySchema := GetDataSchema(body, 0)

		bodyInfo = &protos.APIBodyInfo{
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

	return &protos.APISpec{
		Body:  bodyInfo,
		Query: queryInfo,
		Auth:  authInfo,
	}
}

func isObject(data interface{}) bool {
	// Helper function to determine if the data is an object (map in Go)
	return reflect.TypeOf(data).Kind() == reflect.Map
}
