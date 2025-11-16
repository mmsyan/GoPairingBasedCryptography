package utils

func CheckAttributesArray(attributes []int64, universe int64) bool {
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
