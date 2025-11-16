package utils

// 如果attribute1和attribute2当中相同的元素超过指定的requiredCount个，返回长度为requiredCount的相同元素，否则返回nil
func FindCommonAttributes(attributes1 []int64, attributes2 []int64, requiredCount int) []int64 {
	// 使用 map 记录 attributes1 中元素的出现情况，value 可以是 bool 或 struct{}，这里为了简洁使用 bool
	attributeMap := make(map[int64]bool)
	for _, attr := range attributes1 {
		attributeMap[attr] = true
	}

	// 存储共同的元素
	var commonAttributes []int64
	// 使用一个 set 避免重复添加
	commonSet := make(map[int64]bool)

	// 遍历 attributes2，检查是否存在于 attributeMap 中
	for _, attr := range attributes2 {
		if attributeMap[attr] && !commonSet[attr] {
			commonAttributes = append(commonAttributes, attr)
			commonSet[attr] = true
		}
	}

	// 检查共同元素的数量是否满足 requiredCount
	if len(commonAttributes) >= requiredCount {
		// 返回前 requiredCount 个元素
		return commonAttributes[:requiredCount]
	}

	// 如果不满足，返回 nil
	return nil
}
