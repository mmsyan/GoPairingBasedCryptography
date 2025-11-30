package lsss

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type LewkoWatersLsssMatrix struct {
	rowNumber         int
	columnNumber      int
	accessMatrix      [][]int
	rhoRowToAttribute []fr.Element
}

func NewLSSSMatrixFromTree(root *BinaryAccessTree) *LewkoWatersLsssMatrix {
	counter := 1
	var matrix [][]int
	var rho []fr.Element
	root.Vector = []int{1}

	var copyVector func(v []int) []int
	copyVector = func(v []int) []int {
		result := make([]int, len(v))
		copy(result, v)
		return result
	}

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
			rho = append(rho, node.Attribute)
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
		rowNumber:         len(matrix),
		columnNumber:      len(matrix[0]),
		accessMatrix:      matrix,
		rhoRowToAttribute: rho,
	}
}

func (m *LewkoWatersLsssMatrix) RowNumber() int {
	return m.rowNumber
}

func (m *LewkoWatersLsssMatrix) ColumnNumber() int {
	return m.columnNumber
}

func (m *LewkoWatersLsssMatrix) Rho(rowIndex int) fr.Element {
	return m.rhoRowToAttribute[rowIndex]
}

func (m *LewkoWatersLsssMatrix) ComputeVector(rowIndex int, vector []fr.Element) fr.Element {
	if rowIndex < 0 || rowIndex >= m.rowNumber {
		panic("index out of Lewko Waters Lsss Matrix range")
	}
	result := new(fr.Element).SetZero()
	for i := 0; i < m.columnNumber; i++ {
		temp := new(fr.Element).Mul(&vector[i], new(fr.Element).SetInt64(int64(m.accessMatrix[rowIndex][i])))
		result.Add(result, temp)
	}
	return *result
}

func (m *LewkoWatersLsssMatrix) GetSatisfiedLinearCombination(attributes []fr.Element) ([]int, []fr.Element) {
	var satisfiedRows []int

	// 遍历m.rhoRowToAttribute；如果attributes切片当中有某个元素等于m.rhoRowToAttribute[i]，则i加入satisfiedRows
	// 先构建 map
	attrMap := make(map[fr.Element]bool, len(attributes))
	for i := range attributes {
		attrMap[attributes[i]] = true
	}

	// 单次遍历查找
	for i := 0; i < len(m.rhoRowToAttribute); i++ {
		if attrMap[m.rhoRowToAttribute[i]] {
			satisfiedRows = append(satisfiedRows, i)
		}
	}

	// 如果没有满足的行，返回nil
	if len(satisfiedRows) == 0 {
		return nil, nil
	}

	// satisfiedRows是所有可能的行集合；我们在这里需要找到线性组合满足(1,0,0,..,0)
	// 注意线性组合的参数只有可能是1或者0，这里可以穷举

	// 使用位掩码穷举所有可能的子集（除了空集）
	numRows := len(satisfiedRows)
	maxCombinations := (1 << numRows) - 1 // 2^columnNumber - 1, 排除空集

	for mask := 1; mask <= maxCombinations; mask++ {
		// 计算当前子集的线性组合
		combination := make([]int, m.columnNumber)

		for i := 0; i < numRows; i++ {
			if (mask & (1 << i)) != 0 {
				rowIdx := satisfiedRows[i]
				// 将该行加到组合中
				for j := 0; j < m.columnNumber; j++ {
					combination[j] += m.accessMatrix[rowIdx][j]
				}
			}
		}

		// 检查是否满足目标向量 (1,0,0,...,0)
		if isTargetVector(combination) {
			// 构造结果
			var resultRows []int
			var resultCoeffs []fr.Element

			for i := 0; i < numRows; i++ {
				if (mask & (1 << i)) != 0 {
					resultRows = append(resultRows, satisfiedRows[i])
					// 系数为1
					var one fr.Element
					one.SetOne()
					resultCoeffs = append(resultCoeffs, one)
				}
			}

			return resultRows, resultCoeffs
		}
	}

	// 没有找到满足的线性组合
	return nil, nil
}

// isTargetVector 检查向量是否为目标向量 (1,0,0,...,0)。
//
// 参数：
//   - v: 待检查的向量
//
// 返回值：
//   - bool: 如果是目标向量返回 true，否则返回 false
func isTargetVector(v []int) bool {
	if len(v) == 0 || v[0] != 1 {
		return false
	}
	for i := 1; i < len(v); i++ {
		if v[i] != 0 {
			return false
		}
	}
	return true
}
