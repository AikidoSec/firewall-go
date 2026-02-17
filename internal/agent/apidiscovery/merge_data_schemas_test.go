package apidiscovery

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"

	"github.com/stretchr/testify/assert"
)

func TestIsSameType(t *testing.T) {
	t.Run("matching strings", func(t *testing.T) {
		assert.True(t, isSameType("string", "string"))
	})

	t.Run("non-matching strings", func(t *testing.T) {
		assert.False(t, isSameType("string", "number"))
	})

	t.Run("different reflect types", func(t *testing.T) {
		assert.False(t, isSameType("string", []string{"string"}))
	})

	t.Run("unsupported type returns false", func(t *testing.T) {
		assert.False(t, isSameType(123, 123))
	})
}

func TestMergeTypeArrays(t *testing.T) {
	t.Run("merges single string types", func(t *testing.T) {
		result := mergeTypeArrays("string", "number")
		assert.Equal(t, []string{"string", "number"}, result)
	})

	t.Run("merges string with slice", func(t *testing.T) {
		result := mergeTypeArrays("string", []string{"number", "boolean"})
		assert.Equal(t, []string{"string", "number", "boolean"}, result)
	})
}

func TestMergeDataSchemasNilInputs(t *testing.T) {
	schema := &aikido_types.DataSchema{Type: []string{"string"}}

	t.Run("returns second when first is nil", func(t *testing.T) {
		result := MergeDataSchemas(nil, schema)
		assert.Equal(t, schema, result)
	})

	t.Run("returns first when second is nil", func(t *testing.T) {
		result := MergeDataSchemas(schema, nil)
		assert.Equal(t, schema, result)
	})

	t.Run("returns nil when both are nil", func(t *testing.T) {
		result := MergeDataSchemas(nil, nil)
		assert.Nil(t, result)
	})
}

func TestMergeDataSchemas(t *testing.T) {
	// Example 1
	schema1 := GetDataSchema(map[string]any{"test": "abc"}, 0)
	schema2 := GetDataSchema(map[string]any{"test2": "abc"}, 0)
	expected1 := &aikido_types.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*aikido_types.DataSchema{
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
	assert.Equal(t, expected1, MergeDataSchemas(schema1, schema2))

	// Example 2
	schema3 := GetDataSchema(map[string]any{"test": "abc", "x": map[string]any{"a": 1}}, 0)
	schema4 := GetDataSchema(map[string]any{"test": "abc", "x": map[string]any{"b": 2}}, 0)
	expected2 := &aikido_types.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*aikido_types.DataSchema{
			"test": {
				Type: []string{"string"},
			},
			"x": {
				Type: []string{"object"},
				Properties: map[string]*aikido_types.DataSchema{
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
	assert.Equal(t, expected2, MergeDataSchemas(schema3, schema4))

	// Example 3
	schema5 := GetDataSchema(map[string]any{"test": "abc", "x": map[string]any{"a": 1}, "arr": []int{1, 2}}, 0)
	schema6 := GetDataSchema(map[string]any{"test": "abc", "x": map[string]any{"a": 1, "b": 2}, "arr": []int{1, 2, 3}}, 0)
	expected3 := &aikido_types.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*aikido_types.DataSchema{
			"test": {
				Type: []string{"string"},
			},
			"x": {
				Type: []string{"object"},
				Properties: map[string]*aikido_types.DataSchema{
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
				Items: &aikido_types.DataSchema{
					Type: []string{"number"},
				},
			},
		},
	}
	assert.Equal(t, expected3, MergeDataSchemas(schema5, schema6))
}

func TestPreferNonNullType(t *testing.T) {
	schema1 := GetDataSchema(map[string]any{"test": "abc"}, 0)
	schema2 := GetDataSchema(nil, 0)
	expected1 := &aikido_types.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*aikido_types.DataSchema{
			"test": {
				Type: []string{"string"},
			},
		},
	}
	assert.Equal(t, expected1, MergeDataSchemas(schema1, schema2))
	assert.Equal(t, expected1, MergeDataSchemas(schema2, schema1))
}

func TestEmptyArray(t *testing.T) {
	schema1 := GetDataSchema([]any{}, 0)
	expected := &aikido_types.DataSchema{
		Type:  []string{"array"},
		Items: nil,
	}
	assert.Equal(t, expected, MergeDataSchemas(schema1, schema1))
}

func TestMergeTypes(t *testing.T) {
	// Example 1
	schema1 := GetDataSchema("str", 0)
	schema2 := GetDataSchema(15, 0)
	expected := &aikido_types.DataSchema{
		Type: []string{"string", "number"},
	}
	assert.Equal(t, expected, MergeDataSchemas(schema1, schema2))

	// Example 2: Cannot merge object with primitive type
	schema3 := GetDataSchema(map[string]any{"test": "abc"}, 0)
	schema4 := GetDataSchema(15, 0)
	expected2 := &aikido_types.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*aikido_types.DataSchema{
			"test": {
				Type: []string{"string"},
			},
		},
	}
	assert.Equal(t, expected2, MergeDataSchemas(schema3, schema4))

	// Example 3: Merge string and boolean types
	schema5 := GetDataSchema(map[string]any{"test": "abc"}, 0)
	schema6 := GetDataSchema(map[string]any{"test": true}, 0)
	expected3 := &aikido_types.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*aikido_types.DataSchema{
			"test": {
				Type: []string{"string", "boolean"},
			},
		},
	}
	assert.Equal(t, expected3, MergeDataSchemas(schema5, schema6))

	// Additional nested merges
	assert.Equal(t, expected3, MergeDataSchemas(schema5, MergeDataSchemas(schema5, schema6)))

	expected4 := &aikido_types.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*aikido_types.DataSchema{
			"test": {
				Type: []string{"boolean", "string"},
			},
		},
	}
	assert.Equal(t, expected4, MergeDataSchemas(MergeDataSchemas(GetDataSchema(map[string]any{"test": true}, 0), GetDataSchema(map[string]any{"test": "test"}, 0)), GetDataSchema(map[string]any{"test": "abc"}, 0)))

	expected5 := &aikido_types.DataSchema{
		Type: []string{"object"},
		Properties: map[string]*aikido_types.DataSchema{
			"test": {
				Type: []string{"string", "number", "boolean"},
			},
		},
	}
	assert.Equal(t, expected5, MergeDataSchemas(schema5, MergeDataSchemas(GetDataSchema(map[string]any{"test": 123}, 0), GetDataSchema(map[string]any{"test": true}, 0))))
}
