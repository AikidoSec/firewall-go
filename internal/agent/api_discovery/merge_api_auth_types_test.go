package api_discovery

import (
	"reflect"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

// TestMergeApiAuthTypes tests the mergeApiAuthTypes function.
func TestMergeApiAuthTypes(t *testing.T) {
	// Test case 1: Merge two valid arrays
	result := MergeAPIAuthTypes(
		[]*aikido_types.APIAuthType{
			{Type: "http", Scheme: ("bearer")},
			{Type: "apiKey", In: ("header"), Name: ("x-api-key")},
		},
		[]*aikido_types.APIAuthType{
			{Type: "http", Scheme: ("bearer")},
			{Type: "http", Scheme: ("basic")},
			{Type: "apiKey", In: ("header"), Name: ("x-api-key-v2")},
		},
	)

	expected := []*aikido_types.APIAuthType{
		{Type: "http", Scheme: ("bearer")},
		{Type: "apiKey", In: ("header"), Name: ("x-api-key")},
		{Type: "http", Scheme: ("basic")},
		{Type: "apiKey", In: ("header"), Name: ("x-api-key-v2")},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, but got %v", expected, result)
	}

	// Test case 2: Both arguments are nil, should return nil
	result = MergeAPIAuthTypes(nil, nil)
	if result != nil {
		t.Errorf("Expected nil, but got %v", result)
	}

	// Test case 3: Existing array is provided, newAuth is nil
	result = MergeAPIAuthTypes(
		[]*aikido_types.APIAuthType{
			{Type: "http", Scheme: ("bearer")},
		},
		nil,
	)

	expected = []*aikido_types.APIAuthType{
		{Type: "http", Scheme: ("bearer")},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, but got %v", expected, result)
	}

	// Test case 4: Existing array is nil, newAuth is provided
	result = MergeAPIAuthTypes(
		nil,
		[]*aikido_types.APIAuthType{
			{Type: "http", Scheme: ("digest")},
		},
	)

	expected = []*aikido_types.APIAuthType{
		{Type: "http", Scheme: ("digest")},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}
