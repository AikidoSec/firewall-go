package vulnerabilities

import (
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const maxURLDecodeDepth = 5

type pathPart struct {
	Type  string
	Key   string
	Index int
}

func buildPathToPayload(pathToPayload []pathPart) string {
	if len(pathToPayload) == 0 {
		return "."
	}
	var b strings.Builder
	for _, part := range pathToPayload {
		switch part.Type {
		case "jwt":
			b.WriteString("<jwt>")
		case "object":
			b.WriteByte('.')
			b.WriteString(part.Key)
		case "array":
			b.WriteString(".[")
			b.WriteString(strconv.Itoa(part.Index))
			b.WriteByte(']')
		}
	}
	return b.String()
}

// addURLDecodedVariants adds further URL-decoded forms of str, so apps that
// apps that decode again before a sink have their payload inspected
func addURLDecodedVariants(results map[string]string, str string, pathToPayload []pathPart) {
	current := str
	for i := 0; i < maxURLDecodeDepth; i++ {
		if !strings.Contains(current, "%") {
			break
		}
		decoded, err := url.PathUnescape(current)
		if err != nil || decoded == current {
			break
		}
		results[decoded] = buildPathToPayload(pathToPayload)
		current = decoded
	}
}

// extractStringsFromUserInput recursively extracts strings from user input
func extractStringsFromUserInput(obj interface{}, pathToPayload []pathPart) map[string]string {
	results := make(map[string]string)
	// Pre-allocate path with extra capacity so recursive appends reuse the
	// backing array (stack-like) instead of allocating on every level.
	path := make([]pathPart, len(pathToPayload), len(pathToPayload)+8)
	copy(path, pathToPayload)
	extractStringsInto(obj, path, results)
	return results
}

func extractStringsInto(obj interface{}, path []pathPart, results map[string]string) {
	switch v := obj.(type) {
	case map[string]interface{}:
		currentPath := buildPathToPayload(path)
		for key, val := range v {
			results[key] = currentPath
			extractStringsInto(val, append(path, pathPart{Type: "object", Key: key}), results)
		}
	case map[string][]string:
		currentPath := buildPathToPayload(path)
		for key, vals := range v {
			results[key] = currentPath
			extractStringsInto(vals, append(path, pathPart{Type: "object", Key: key}), results)
		}
	case url.Values:
		currentPath := buildPathToPayload(path)
		for key, vals := range v {
			results[key] = currentPath
			extractStringsInto(vals, append(path, pathPart{Type: "object", Key: key}), results)
		}
	case map[string]string:
		currentPath := buildPathToPayload(path)
		for key, val := range v {
			results[key] = currentPath
			extractStringsInto(val, append(path, pathPart{Type: "object", Key: key}), results)
		}
	case []interface{}:
		var values []string
		for i, item := range v {
			extractStringsInto(item, append(path, pathPart{Type: "array", Index: i}), results)
			values = append(values, fmt.Sprintf("%v", item))
		}
		// Add array as string to results
		// This prevents bypassing the firewall by HTTP Parameter Pollution
		// Example: ?param=value1&param=value2 could be treated as an array
		// If its used inside a string, it will be converted to a comma separated string
		if len(values) > 0 {
			results[strings.Join(values, ",")] = buildPathToPayload(path)
		}
	case []string:
		for i, item := range v {
			extractStringsInto(item, append(path, pathPart{Type: "array", Index: i}), results)
		}
		if len(v) > 0 {
			results[strings.Join(v, ",")] = buildPathToPayload(path)
		}
	case string:
		results[v] = buildPathToPayload(path)
		addURLDecodedVariants(results, v, path)
		jwt := tryDecodeAsJWT(v)
		if jwt.JWT {
			jwtPath := append(slices.Clone(path), pathPart{Type: "jwt"})
			// JWT needs a temporary map for iss filtering before merging.
			jwtResults := make(map[string]string)
			extractStringsInto(jwt.Object, jwtPath, jwtResults)
			for k, vv := range jwtResults {
				if k == "iss" || strings.HasSuffix(vv, "<jwt>.iss") {
					continue
				}
				results[k] = vv
			}
		}
	default:
		extractStringsReflect(obj, path, results)
	}
}

// extractStringsReflect is the fallback for types not covered by the typed
// cases above (named map/slice types, maps with other key/value types, arrays,
// named string types), e.g. a custom Body passed via the public SetContext API.
func extractStringsReflect(obj interface{}, path []pathPart, results map[string]string) {
	val := reflect.ValueOf(obj)
	switch val.Kind() {
	case reflect.Map:
		currentPath := buildPathToPayload(path)
		for _, key := range val.MapKeys() {
			keyStr := fmt.Sprintf("%v", key.Interface())
			results[keyStr] = currentPath
			extractStringsInto(val.MapIndex(key).Interface(), append(path, pathPart{Type: "object", Key: keyStr}), results)
		}
	case reflect.Slice, reflect.Array:
		var values []string
		for i := 0; i < val.Len(); i++ {
			item := val.Index(i).Interface()
			extractStringsInto(item, append(path, pathPart{Type: "array", Index: i}), results)
			values = append(values, fmt.Sprintf("%v", item))
		}
		if len(values) > 0 {
			results[strings.Join(values, ",")] = buildPathToPayload(path)
		}
	case reflect.String:
		extractStringsInto(val.String(), path, results)
	}
}
