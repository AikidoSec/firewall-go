package vulnerabilities

import (
	"reflect"
	"testing"
)

func TestBuildPathToPayload(t *testing.T) {
	tests := []struct {
		name     string
		parts    []pathPart
		expected string
	}{
		{
			name:     "empty path returns dot",
			parts:    []pathPart{},
			expected: ".",
		},
		{
			name:     "single object part",
			parts:    []pathPart{{Type: "object", Key: "username"}},
			expected: ".username",
		},
		{
			name:     "single array part index zero",
			parts:    []pathPart{{Type: "array", Index: 0}},
			expected: ".[0]",
		},
		{
			name:     "single array part large index",
			parts:    []pathPart{{Type: "array", Index: 99}},
			expected: ".[99]",
		},
		{
			name:     "single jwt part",
			parts:    []pathPart{{Type: "jwt"}},
			expected: "<jwt>",
		},
		{
			name: "nested object path",
			parts: []pathPart{
				{Type: "object", Key: "a"},
				{Type: "object", Key: "b"},
				{Type: "object", Key: "c"},
			},
			expected: ".a.b.c",
		},
		{
			name: "object then array",
			parts: []pathPart{
				{Type: "object", Key: "arr"},
				{Type: "array", Index: 2},
			},
			expected: ".arr.[2]",
		},
		{
			name: "jwt then object",
			parts: []pathPart{
				{Type: "jwt"},
				{Type: "object", Key: "sub"},
			},
			expected: "<jwt>.sub",
		},
		{
			name: "complex mixed path",
			parts: []pathPart{
				{Type: "object", Key: "token"},
				{Type: "jwt"},
				{Type: "object", Key: "username"},
				{Type: "object", Key: "$ne"},
			},
			expected: ".token<jwt>.username.$ne",
		},
		{
			name:     "unknown type is skipped",
			parts:    []pathPart{{Type: "unknown", Key: "x"}},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := buildPathToPayload(tt.parts)
			if actual != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, actual)
			}
		})
	}
}

func TestExtractStringsFromUserInput(t *testing.T) {
	t.Run("empty object returns empty array", func(t *testing.T) {
		obj := map[string]interface{}{}
		pathToPayload := []pathPart{}
		expected := map[string]string{}
		actual := extractStringsFromUserInput(obj, pathToPayload)
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("it ignores iss value of jwt", func(t *testing.T) {
		obj := map[string]interface{}{
			"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.QLC0vl-A11a1WcUPD6vQR2PlUvRMsqpegddfQzPajQM",
		}

		expected := map[string]string{
			"token": ".",
			"iat":   ".token<jwt>",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.QLC0vl-A11a1WcUPD6vQR2PlUvRMsqpegddfQzPajQM": ".token",
			"sub":        ".token<jwt>",
			"1234567890": ".token<jwt>.sub",
			"name":       ".token<jwt>",
			"John Doe":   ".token<jwt>.name",
		}

		actual := extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("it can extract query objects", func(t *testing.T) {
		obj := map[string]interface{}{
			"age": map[string]interface{}{
				"$gt": "21",
			},
		}

		expected := map[string]string{
			"age": ".",
			"$gt": ".age",
			"21":  ".age.$gt",
		}
		actual := extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}

		obj = map[string]interface{}{
			"title": map[string]interface{}{
				"$ne": "null",
			},
		}

		expected = map[string]string{
			"title": ".",
			"$ne":   ".title",
			"null":  ".title.$ne",
		}
		actual = extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}

		obj = map[string]interface{}{
			"age":        "whaat1",
			"user_input": []string{"whaat", "dangerous"},
		}

		expected = map[string]string{
			"user_input":      ".",
			"age":             ".",
			"whaat1":          ".age",
			"whaat":           ".user_input.[0]",
			"dangerous":       ".user_input.[1]",
			"whaat,dangerous": ".user_input",
		}
		actual = extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("it can extract cookie objects", func(t *testing.T) {
		obj := map[string]interface{}{
			"session":  "ABC",
			"session2": "DEF",
		}

		expected := map[string]string{
			"session2": ".",
			"session":  ".",
			"ABC":      ".session",
			"DEF":      ".session2",
		}
		actual := extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}

		obj = map[string]interface{}{
			"session":  "ABC",
			"session2": 1234,
		}

		expected = map[string]string{
			"session2": ".",
			"session":  ".",
			"ABC":      ".session",
		}
		actual = extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("it can extract header objects", func(t *testing.T) {
		obj := map[string]interface{}{
			"Content-Type": "application/json",
		}

		expected := map[string]string{
			"Content-Type":     ".",
			"application/json": ".Content-Type",
		}
		actual := extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}

		obj = map[string]interface{}{
			"Content-Type": 54321,
		}
		expected = map[string]string{
			"Content-Type": ".",
		}
		actual = extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}

		obj = map[string]interface{}{
			"Content-Type": "application/json",
			"ExtraHeader":  "value",
		}
		expected = map[string]string{
			"Content-Type":     ".",
			"application/json": ".Content-Type",
			"ExtraHeader":      ".",
			"value":            ".ExtraHeader",
		}
		actual = extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("it can extract body objects", func(t *testing.T) {
		obj := map[string]interface{}{
			"nested": map[string]interface{}{
				"nested": map[string]interface{}{
					"$ne": nil,
				},
			},
		}

		expected := map[string]string{
			"nested": ".nested",
			"$ne":    ".nested.nested",
		}
		actual := extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}

		obj = map[string]interface{}{
			"age": map[string]interface{}{
				"$gt": "21",
				"$lt": "100",
			},
		}

		expected = map[string]string{
			"age": ".",
			"$lt": ".age",
			"$gt": ".age",
			"21":  ".age.$gt",
			"100": ".age.$lt",
		}
		actual = extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("it decodes JWTs", func(t *testing.T) {
		obj := map[string]interface{}{
			"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOnsiJG5lIjpudWxsfSwiaWF0IjoxNTE2MjM5MDIyfQ._jhGJw9WzB6gHKPSozTFHDo9NOHs3CNOlvJ8rWy6VrQ",
		}

		expected := map[string]string{
			"token":      ".",
			"iat":        ".token<jwt>",
			"username":   ".token<jwt>",
			"sub":        ".token<jwt>",
			"1234567890": ".token<jwt>.sub",
			"$ne":        ".token<jwt>.username",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOnsiJG5lIjpudWxsfSwiaWF0IjoxNTE2MjM5MDIyfQ._jhGJw9WzB6gHKPSozTFHDo9NOHs3CNOlvJ8rWy6VrQ": ".token",
		}

		actual := extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("it also adds the JWT itself as string", func(t *testing.T) {
		obj := map[string]interface{}{
			"header": "/;ping%20localhost;.e30=.",
		}

		expected := map[string]string{
			"header":                    ".",
			"/;ping%20localhost;.e30=.": ".header",
			"/;ping localhost;.e30=.":   ".header",
		}

		actual := extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("it adds URL-decoded variants", func(t *testing.T) {
		obj := map[string]interface{}{
			"path": "%252e%252e%252fetc%252fpasswd",
		}

		expected := map[string]string{
			"path":                          ".",
			"%252e%252e%252fetc%252fpasswd": ".path",
			"%2e%2e%2fetc%2fpasswd":         ".path",
			"../etc/passwd":                 ".path",
		}

		actual := extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})

	t.Run("it concatenates array values", func(t *testing.T) {
		obj := map[string]interface{}{
			"arr": []interface{}{"1", "2", "3"},
		}

		expected := map[string]string{
			"arr":   ".",
			"1,2,3": ".arr",
			"1":     ".arr.[0]",
			"2":     ".arr.[1]",
			"3":     ".arr.[2]",
		}
		actual := extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}

		obj = map[string]interface{}{
			"arr": []interface{}{"1", 2, true, nil, nil, map[string]interface{}{"test": "test"}},
		}

		expected = map[string]string{
			"arr":  ".",
			"1":    ".arr.[0]",
			"test": ".arr.[5].test",
			"1,<int Value>,<bool Value>,<invalid Value>,<invalid Value>,<map[string]interface {} Value>": ".arr",
		}
		actual = extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}

		obj = map[string]interface{}{
			"arr": []interface{}{"1", 2, true, nil, nil, map[string]interface{}{"test": []string{"test123", "test345"}}},
		}

		expected = map[string]string{
			"arr":             ".",
			"1":               ".arr.[0]",
			"test":            ".arr.[5]",
			"test123":         ".arr.[5].test.[0]",
			"test345":         ".arr.[5].test.[1]",
			"test123,test345": ".arr.[5].test",
			"1,<int Value>,<bool Value>,<invalid Value>,<invalid Value>,<map[string]interface {} Value>": ".arr",
		}
		actual = extractStringsFromUserInput(obj, []pathPart{})
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("Expected %v, got %v", expected, actual)
		}
	})
}
