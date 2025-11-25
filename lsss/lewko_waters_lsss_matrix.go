package lsss

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

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

func (m *LewkoWatersLsssMatrix) GetN() int {
	return m.n
}

func (m *LewkoWatersLsssMatrix) RhoX(row int) fr.Element {
	return m.attributeRho[row]
}

func (m *LewkoWatersLsssMatrix) ComputeVector(x int, v []fr.Element) fr.Element {
	if x < 0 || x >= m.l {
		panic("index out of Lewko Waters Lsss Matrix range")
	}
	result := new(fr.Element).SetZero()
	for i := 0; i < m.n; i++ {
		temp := new(fr.Element).Mul(&v[i], new(fr.Element).SetInt64(int64(m.lsssMatrix[x][i])))
		result.Add(result, temp)
	}
	return *result
}

func (m *LewkoWatersLsssMatrix) GetSatisfiedLinearCombination(attributes []fr.Element) ([]int, []fr.Element) {
	var satisfiedRows []int

	// 遍历m.attributeRho；如果attributes切片当中有某个元素等于m.attributeRho[i]，则i加入satisfiedRows
	for i := 0; i < len(m.attributeRho); i++ {
		for j := 0; j < len(attributes); j++ {
			if m.attributeRho[i].Equal(&attributes[j]) {
				satisfiedRows = append(satisfiedRows, i)
				break
			}
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
	maxCombinations := (1 << numRows) - 1 // 2^n - 1, 排除空集

	for mask := 1; mask <= maxCombinations; mask++ {
		// 计算当前子集的线性组合
		combination := make([]int, m.n)

		for i := 0; i < numRows; i++ {
			if (mask & (1 << i)) != 0 {
				rowIdx := satisfiedRows[i]
				// 将该行加到组合中
				for j := 0; j < m.n; j++ {
					combination[j] += m.lsssMatrix[rowIdx][j]
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
