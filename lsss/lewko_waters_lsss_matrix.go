package lsss

type LewkoWatersLsssMatrix struct {
	l            int
	n            int
	lsssMatrix   [][]int
	attributeRho []string
}

func copyVector(v []int) []int {
	result := make([]int, len(v))
	copy(result, v)
	return result
}

func NewLSSSMatrixFromTree(root *BinaryAccessTree) *LewkoWatersLsssMatrix {
	counter := 1
	var matrix [][]int
	var rho []string
	root.Vector = []int{1}

	var recursionFunc func(node *BinaryAccessTree)
	recursionFunc = func(node *BinaryAccessTree) {
		if node.Value == "or" {
			node.Left.Vector = copyVector(node.Vector)
			node.Right.Vector = copyVector(node.Vector)
		} else if node.Value == "and" {
			node.Left.VectorPad(counter)
			node.Left.Vector = append(node.Left.Vector, -1)
			node.Right.Vector = copyVector(node.Vector)
			node.Right.VectorPad(counter)
			node.Right.Vector = append(node.Right.Vector, 1)
			counter++
		} else {
			matrix = append(matrix, copyVector(node.Vector))
			rho = append(rho, node.Value)
			return
		}
		recursionFunc(node.Left)
		recursionFunc(node.Right)
	}
	recursionFunc(root)

	// 填充所有行到相同长度
	for i := range matrix {
		for j := len(matrix[i]); j < counter; j++ {
			matrix[i] = append(matrix[i], 0)
		}
	}

	return &LewkoWatersLsssMatrix{
		l:            len(matrix),
		n:            len(matrix[0]),
		lsssMatrix:   matrix,
		attributeRho: rho,
	}
}

func isTargetVector(v []int) bool {
	if v[0] != 1 {
		return false
	}
	for i := 1; i < len(v); i++ {
		if v[i] != 0 {
			return false
		}
	}
	return true
}
