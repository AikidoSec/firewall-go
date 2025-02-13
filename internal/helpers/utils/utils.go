package utils

func ArrayContains(array []string, search string) bool {
	for _, member := range array {
		if member == search {
			return true
		}
	}
	return false
}
