package apidiscovery

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

// Helper function for comparing two DataSchema structs
func compareSchemas(t *testing.T, got, expected *aikido_types.DataSchema) {
	gotJson, _ := json.Marshal(got)
	expectedJson, _ := json.Marshal(expected)

	if string(gotJson) != string(expectedJson) {
		t.Errorf("Got %s, expected %s", string(gotJson), string(expectedJson))
	}
}

func TestGetDataSchema(t *testing.T) {
	t.Run("it works", func(t *testing.T) {
		compareSchemas(t, GetDataSchema("test", 0), &aikido_types.DataSchema{
			Type: []string{"string"},
		})

		compareSchemas(t, GetDataSchema([]string{"test"}, 0), &aikido_types.DataSchema{
			Type: []string{"array"},
			Items: &aikido_types.DataSchema{
				Type: []string{"string"},
			},
		})

		compareSchemas(t, GetDataSchema(map[string]interface{}{"test": "abc"}, 0), &aikido_types.DataSchema{
			Type: []string{"object"},
			Properties: map[string]*aikido_types.DataSchema{
				"test": {Type: []string{"string"}},
			},
		})

		compareSchemas(t, GetDataSchema(map[string]interface{}{"test": 123, "arr": []int{1, 2, 3}}, 0), &aikido_types.DataSchema{
			Type: []string{"object"},
			Properties: map[string]*aikido_types.DataSchema{
				"test": {Type: []string{"number"}},
				"arr": {
					Type: []string{"array"},
					Items: &aikido_types.DataSchema{
						Type: []string{"number"},
					},
				},
			},
		})

		compareSchemas(t, GetDataSchema(map[string]interface{}{
			"test": 123,
			"arr":  []interface{}{map[string]interface{}{"sub": true}},
			"x":    nil,
		}, 0), &aikido_types.DataSchema{
			Type: []string{"object"},
			Properties: map[string]*aikido_types.DataSchema{
				"test": {Type: []string{"number"}},
				"arr": {
					Type: []string{"array"},
					Items: &aikido_types.DataSchema{
						Type: []string{"object"},
						Properties: map[string]*aikido_types.DataSchema{
							"sub": {Type: []string{"boolean"}},
						},
					},
				},
				"x": {Type: []string{"null"}},
			},
		})

		compareSchemas(t, GetDataSchema(map[string]interface{}{
			"test": map[string]interface{}{
				"x": map[string]interface{}{
					"y": map[string]interface{}{
						"z": 123,
					},
				},
			},
			"arr": []interface{}{},
		}, 0), &aikido_types.DataSchema{
			Type: []string{"object"},
			Properties: map[string]*aikido_types.DataSchema{
				"test": {
					Type: []string{"object"},
					Properties: map[string]*aikido_types.DataSchema{
						"x": {
							Type: []string{"object"},
							Properties: map[string]*aikido_types.DataSchema{
								"y": {
									Type: []string{"object"},
									Properties: map[string]*aikido_types.DataSchema{
										"z": {Type: []string{"number"}},
									},
								},
							},
						},
					},
				},
				"arr": {
					Type:  []string{"array"},
					Items: nil,
				},
			},
		})
	})

	t.Run("test max depth", func(t *testing.T) {
		var generateTestObjectWithDepth func(depth int) interface{}

		generateTestObjectWithDepth = func(depth int) interface{} {
			if depth == 0 {
				return "testValue"
			}
			return map[string]interface{}{
				"prop": generateTestObjectWithDepth(depth - 1),
			}
		}

		obj := generateTestObjectWithDepth(10)
		schema := GetDataSchema(obj, 0)
		schemaJson, _ := json.Marshal(schema)
		if !json.Valid([]byte(schemaJson)) || !strings.Contains(string(schemaJson), `"type":["string"]`) {
			t.Errorf("Expected schema to contain 'type: string'! Got %s", string(schemaJson))
		}

		obj2 := generateTestObjectWithDepth(21)
		schema2 := GetDataSchema(obj2, 0)
		schema2Json, _ := json.Marshal(schema2)
		schema2JsonStr := string(schema2Json)
		if strings.Contains(schema2JsonStr, `"type":["string"]`) {
			t.Errorf("Expected schema to not contain 'type: string' for depth beyond limit! Got %s", schema2JsonStr)
		}
	})

	t.Run("test max properties", func(t *testing.T) {
		generateObjectWithProperties := func(count int) map[string]interface{} {
			obj := make(map[string]interface{})
			for i := 0; i < count; i++ {
				obj[fmt.Sprintf("prop%d", i)] = i
			}
			return obj
		}

		obj := generateObjectWithProperties(80)
		schema := GetDataSchema(obj, 0)
		if len(schema.Properties) != 80 {
			t.Errorf("Expected 80 properties, got %d", len(schema.Properties))
		}

		obj2 := generateObjectWithProperties(120)
		schema2 := GetDataSchema(obj2, 0)
		if len(schema2.Properties) != 100 {
			t.Errorf("Expected 100 properties, got %d", len(schema2.Properties))
		}
	})
}
