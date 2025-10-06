package api_discovery

import (
	"testing"

	"github.com/AikidoSec/firewall-go/agent/ipc/protos"

	"github.com/stretchr/testify/assert"
)

func TestMergeDataSchemas(t *testing.T) {
	assert := assert.New(t)

	// Example 1
	schema1 := GetDataSchema(map[string]interface{}{"test": "abc"}, 0)
	schema2 := GetDataSchema(map[string]interface{}{"test2": "abc"}, 0)
	expected1 := &protos.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*protos.DataSchema{
			"test": {
				Type:     []string{"string"},
				Optional: true,
			},
			"test2": {
				Type:     []string{"string"},
				Optional: true,
			},
		},
	}
	assert.Equal(expected1, MergeDataSchemas(schema1, schema2))

	// Example 2
	schema3 := GetDataSchema(map[string]interface{}{"test": "abc", "x": map[string]interface{}{"a": 1}}, 0)
	schema4 := GetDataSchema(map[string]interface{}{"test": "abc", "x": map[string]interface{}{"b": 2}}, 0)
	expected2 := &protos.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*protos.DataSchema{
			"test": {
				Type: []string{"string"},
			},
			"x": {
				Type: []string{"object"},
				Properties: map[string]*protos.DataSchema{
					"a": {
						Type:     []string{"number"},
						Optional: true,
					},
					"b": {
						Type:     []string{"number"},
						Optional: true,
					},
				},
			},
		},
	}
	assert.Equal(expected2, MergeDataSchemas(schema3, schema4))

	// Example 3
	schema5 := GetDataSchema(map[string]interface{}{"test": "abc", "x": map[string]interface{}{"a": 1}, "arr": []int{1, 2}}, 0)
	schema6 := GetDataSchema(map[string]interface{}{"test": "abc", "x": map[string]interface{}{"a": 1, "b": 2}, "arr": []int{1, 2, 3}}, 0)
	expected3 := &protos.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*protos.DataSchema{
			"test": {
				Type: []string{"string"},
			},
			"x": {
				Type: []string{"object"},
				Properties: map[string]*protos.DataSchema{
					"a": {
						Type: []string{"number"},
					},
					"b": {
						Type:     []string{"number"},
						Optional: true,
					},
				},
			},
			"arr": {
				Type: []string{"array"},
				Items: &protos.DataSchema{
					Type: []string{"number"},
				},
			},
		},
	}
	assert.Equal(expected3, MergeDataSchemas(schema5, schema6))
}

func TestPreferNonNullType(t *testing.T) {
	assert := assert.New(t)

	schema1 := GetDataSchema(map[string]interface{}{"test": "abc"}, 0)
	schema2 := GetDataSchema(nil, 0)
	expected1 := &protos.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*protos.DataSchema{
			"test": {
				Type: []string{"string"},
			},
		},
	}
	assert.Equal(expected1, MergeDataSchemas(schema1, schema2))
	assert.Equal(expected1, MergeDataSchemas(schema2, schema1))
}

func TestEmptyArray(t *testing.T) {
	assert := assert.New(t)

	schema1 := GetDataSchema([]interface{}{}, 0)
	expected := &protos.DataSchema{
		Type:  []string{"array"},
		Items: nil,
	}
	assert.Equal(expected, MergeDataSchemas(schema1, schema1))
}

func TestMergeTypes(t *testing.T) {
	assert := assert.New(t)

	// Example 1
	schema1 := GetDataSchema("str", 0)
	schema2 := GetDataSchema(15, 0)
	expected := &protos.DataSchema{
		Type: []string{"string", "number"},
	}
	assert.Equal(expected, MergeDataSchemas(schema1, schema2))

	// Example 2: Cannot merge object with primitive type
	schema3 := GetDataSchema(map[string]interface{}{"test": "abc"}, 0)
	schema4 := GetDataSchema(15, 0)
	expected2 := &protos.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*protos.DataSchema{
			"test": {
				Type: []string{"string"},
			},
		},
	}
	assert.Equal(expected2, MergeDataSchemas(schema3, schema4))

	// Example 3: Merge string and boolean types
	schema5 := GetDataSchema(map[string]interface{}{"test": "abc"}, 0)
	schema6 := GetDataSchema(map[string]interface{}{"test": true}, 0)
	expected3 := &protos.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*protos.DataSchema{
			"test": {
				Type: []string{"string", "boolean"},
			},
		},
	}
	assert.Equal(expected3, MergeDataSchemas(schema5, schema6))

	// Additional nested merges
	assert.Equal(expected3, MergeDataSchemas(schema5, MergeDataSchemas(schema5, schema6)))

	expected4 := &protos.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*protos.DataSchema{
			"test": {
				Type: []string{"boolean", "string"},
			},
		},
	}
	assert.Equal(expected4, MergeDataSchemas(MergeDataSchemas(GetDataSchema(map[string]interface{}{"test": true}, 0), GetDataSchema(map[string]interface{}{"test": "test"}, 0)), GetDataSchema(map[string]interface{}{"test": "abc"}, 0)))

	expected5 := &protos.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*protos.DataSchema{
			"test": {
				Type: []string{"string", "number", "boolean"},
			},
		},
	}
	assert.Equal(expected5, MergeDataSchemas(schema5, MergeDataSchemas(GetDataSchema(map[string]interface{}{"test": 123}, 0), GetDataSchema(map[string]interface{}{"test": true}, 0))))
}
