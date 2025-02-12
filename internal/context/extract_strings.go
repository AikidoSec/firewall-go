package context

import "reflect"

func ExtractStrings(input interface{}) map[string]struct{} {
	result := make(map[string]struct{})
	val := reflect.ValueOf(input)

	// Check if the input is a pointer and get the value it points to
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	// If the input is a struct, iterate through its fields
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if field.Kind() == reflect.String {
				result[field.String()] = struct{}{}
			}
		}
	} else if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
		// If the input is a slice or array, iterate through its elements
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i)
			if elem.Kind() == reflect.String {
				result[elem.String()] = struct{}{}
			}
		}
	} else if val.Kind() == reflect.String {
		// If the input is a string, add it directly
		result[val.String()] = struct{}{}
	}

	return result
}
