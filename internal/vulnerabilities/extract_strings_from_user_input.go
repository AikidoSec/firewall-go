package vulnerabilities

import (
	"fmt"
	"reflect"
	"strings"
)

type pathPart struct {
	Type  string
	Key   string
	Index int
}

func buildPathToPayload(pathToPayload []pathPart) string {
	if len(pathToPayload) == 0 {
		return "."
	}

	path := ""
	for _, part := range pathToPayload {
		switch part.Type {
		case "jwt":
			path += "<jwt>"
		case "object":
			path += "." + part.Key
		case "array":
			path += fmt.Sprintf(".[%d]", part.Index)
		}
	}
	return path
}

// extractStringsFromUserInput recursively extracts strings from user input
func extractStringsFromUserInput(obj interface{}, pathToPayload []pathPart) map[string]string {
	results := make(map[string]string)

	val := reflect.ValueOf(obj)
	switch val.Kind() {
	case reflect.Map:
		for _, key := range val.MapKeys() {
			keyStr := fmt.Sprintf("%v", key.Interface())
			results[keyStr] = buildPathToPayload(pathToPayload)
			nestedResults := extractStringsFromUserInput(val.MapIndex(key).Interface(), append(pathToPayload, pathPart{Type: "object", Key: keyStr}))
			for k, v := range nestedResults {
				results[k] = v
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < val.Len(); i++ {
			nestedResults := extractStringsFromUserInput(val.Index(i).Interface(), append(pathToPayload, pathPart{Type: "array", Index: i}))
			for k, v := range nestedResults {
				results[k] = v
			}
		}

		// Add array as string to results
		// This prevents bypassing the firewall by HTTP Parameter Pollution
		// Example: ?param=value1&param=value2 could be treated as an array
		// If its used inside a string, it will be converted to a comma separated string
		if val.Len() > 0 {
			var values []string
			for i := 0; i < val.Len(); i++ {
				values = append(values, reflect.ValueOf(val.Index(i).Interface()).String())
			}
			results[strings.Join(values, ",")] = buildPathToPayload(pathToPayload)
		}

	case reflect.String:
		str := val.String()
		results[str] = buildPathToPayload(pathToPayload)
		jwt := tryDecodeAsJWT(str)
		if jwt.JWT {
			for k, v := range extractStringsFromUserInput(jwt.Object, append(pathToPayload, pathPart{Type: "jwt"})) {
				if k == "iss" || strings.HasSuffix(v, "<jwt>.iss") {
					continue
				}
				results[k] = v
			}
		}

	}

	return results
}
