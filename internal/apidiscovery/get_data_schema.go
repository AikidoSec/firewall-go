package apidiscovery

import (
	"reflect"

	"github.com/AikidoSec/firewall-go/agent/aikido_types"
)

const (
	maxDepth      = 20
	maxProperties = 100
)

// GetDataSchema returns the schema of the given data as a DataSchema
func GetDataSchema(data any, depth int) *aikido_types.DataSchema {
	// If the data is not an object (or an array), return the type
	if data == nil {
		return &aikido_types.DataSchema{Type: []string{"null"}}
	}

	dataType := reflect.TypeOf(data)

	switch dataType.Kind() {
	case reflect.Slice, reflect.Array:
		// If the data is an array/slice, return an array schema
		v := reflect.ValueOf(data)
		if v.Len() > 0 {
			return &aikido_types.DataSchema{
				Type:  []string{"array"},
				Items: GetDataSchema(v.Index(0).Interface(), depth+1),
			}
		} else {
			return &aikido_types.DataSchema{Type: []string{"array"}}
		}
	case reflect.Map:
		// Create an object schema with properties
		schema := aikido_types.DataSchema{
			Type:       []string{"object"},
			Properties: make(map[string]*aikido_types.DataSchema),
		}

		// Traverse properties if within depth
		if depth < maxDepth {
			keys := reflect.ValueOf(data).MapKeys()
			for i, key := range keys {
				if i >= maxProperties {
					break
				}
				value := reflect.ValueOf(data).MapIndex(key).Interface()
				schema.Properties[key.String()] = GetDataSchema(value, depth+1)
			}
		}

		return &schema

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return &aikido_types.DataSchema{Type: []string{"number"}}

	case reflect.Float32, reflect.Float64:
		return &aikido_types.DataSchema{Type: []string{"number"}}

	case reflect.Bool:
		return &aikido_types.DataSchema{Type: []string{"boolean"}}

	default:
		// If the data is not an object or array, return its type
		return &aikido_types.DataSchema{Type: []string{dataType.Kind().String()}}
	}
}
