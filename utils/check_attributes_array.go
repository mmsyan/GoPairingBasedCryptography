package utils

func CheckAttributesArray(attributes []int, universe int) bool {
	if attributes == nil || len(attributes) == 0 {
		return false
	}
	for _, a := range attributes {
		if a < 1 || a > universe {
			return false
		}
	}
	return true
}
