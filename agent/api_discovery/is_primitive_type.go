package api_discovery

func onlyContainsPrimitiveTypes(types any) bool {
	switch t := types.(type) {
	case string:
		return isPrimitiveType(t)
	case []string:
		for _, item := range t {
			if !isPrimitiveType(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isPrimitiveType(typeStr string) bool {
	return typeStr != "object" && typeStr != "array"
}
