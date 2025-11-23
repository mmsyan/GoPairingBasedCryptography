package lsss

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

type LewkoWatersLsssMatrix struct {
	l            int
	n            int
	lsssMatrix   [][]int
	attributeRho []fr.Element
}

func copyVector(v []int) []int {
	result := make([]int, len(v))
	copy(result, v)
	return result
}

func NewLSSSMatrixFromTree(root *BinaryAccessTree) *LewkoWatersLsssMatrix {
	counter := 1
	var matrix [][]int
	var rho []fr.Element
	root.Vector = []int{1}

	var recursionFunc func(node *BinaryAccessTree)
	recursionFunc = func(node *BinaryAccessTree) {
		if node.Type == NodeTypeOr {
			node.Left.Vector = copyVector(node.Vector)
			node.Right.Vector = copyVector(node.Vector)
		} else if node.Type == NodeTypeAnd {
			node.Left.VectorPadZero(counter)
			node.Left.Vector = append(node.Left.Vector, -1)
			node.Right.Vector = copyVector(node.Vector)
			node.Right.VectorPadZero(counter)
			node.Right.Vector = append(node.Right.Vector, 1)
			counter++
		} else if node.Type == NodeTypeLeave {
			matrix = append(matrix, copyVector(node.Vector))
			rho = append(rho, node.Value)
			return
		} else {
			panic("node type error")
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

func (m *LewkoWatersLsssMatrix) GetL() int {
	return m.l
}

func (m *LewkoWatersLsssMatrix) RhoX(row int) fr.Element {
	return m.attributeRho[row]
}

func (m *LewkoWatersLsssMatrix) ComputeVector(x int, v []fr.Element) fr.Element {
	if x < 0 || x >= m.l {
		panic("index out of Lewko Waters Lsss Matrix range")
	}
	result := new(fr.Element).SetZero()
	for i := 0; i < m.l; i++ {
		temp := new(fr.Element).Mul(&v[i], new(fr.Element).SetInt64(int64(m.lsssMatrix[x][i])))
		result.Add(result, temp)
	}
	return *result
}

func (m *LewkoWatersLsssMatrix) Mi(i int) []fr.Element {
	if i < 0 || i >= m.l {
		panic("index out of Lewko Waters Lsss Matrix range")
	}
	result := make([]fr.Element, m.n)
	for j := 0; j < m.n; j++ {
		result[j] = *new(fr.Element).SetInt64(int64(m.lsssMatrix[i][j]))
	}
	return result
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
