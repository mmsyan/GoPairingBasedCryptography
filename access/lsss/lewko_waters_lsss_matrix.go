package lsss

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// LewkoWatersLsssMatrix 表示Lewko-Waters线性秘密共享方案(LSSS)矩阵
//
// 该结构体实现了基于访问树的属性基加密(ABE)中的LSSS矩阵。
// 矩阵的每一行对应一个属性，通过线性组合可以重构秘密。
type LewkoWatersLsssMatrix struct {
	rowNumber         int
	columnNumber      int
	accessMatrix      [][]fr.Element
	rhoRowToAttribute []fr.Element
}

// NewLSSSMatrixFromBinaryTree 从二叉访问树构造LSSS矩阵
//
// 该函数通过递归遍历访问树，将其转换为LSSS矩阵表示：
//   - OR门：左右子节点继承父节点的向量
//   - AND门：左子节点追加-1，右子节点追加1，并增加列维度
//   - 叶子节点：成为矩阵的一行
//
// 参数：
//   - root: 访问树的根节点
//
// 返回值：
//   - *LewkoWatersLsssMatrix: 构造好的LSSS矩阵
func NewLSSSMatrixFromBinaryTree(root *BinaryAccessTree) *LewkoWatersLsssMatrix {
	counter := 1
	var matrix [][]fr.Element
	var rho []fr.Element
	oneElement := fr.NewElement(1)
	zeroElement := fr.NewElement(0)
	minusOneElement := *new(fr.Element).Sub(&zeroElement, &oneElement)
	root.Vector = []fr.Element{oneElement}

	var copyVector func(v []fr.Element) []fr.Element
	copyVector = func(v []fr.Element) []fr.Element {
		result := make([]fr.Element, len(v))
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
			node.Left.Vector = append(node.Left.Vector, minusOneElement)
			node.Right.Vector = copyVector(node.Vector)
			node.Right.VectorPadZero(counter)
			node.Right.Vector = append(node.Right.Vector, oneElement)
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
			matrix[i] = append(matrix[i], zeroElement)
		}
	}

	return &LewkoWatersLsssMatrix{
		rowNumber:         len(matrix),
		columnNumber:      len(matrix[0]),
		accessMatrix:      matrix,
		rhoRowToAttribute: rho,
	}
}

// RowNumber 返回矩阵的行数
func (m *LewkoWatersLsssMatrix) RowNumber() int {
	return m.rowNumber
}

// ColumnNumber 返回矩阵的列数
func (m *LewkoWatersLsssMatrix) ColumnNumber() int {
	return m.columnNumber
}

// Rho 返回指定行索引对应的属性
//
// 参数：
//   - rowIndex: 行索引
//
// 返回值：
//   - fr.Element: 该行对应的属性值
func (m *LewkoWatersLsssMatrix) Rho(rowIndex int) fr.Element {
	return m.rhoRowToAttribute[rowIndex]
}

// Attributes 返回所有行对应的属性列表
//
// 返回值：
//   - []fr.Element: 属性列表，索引i对应第i行的属性
func (m *LewkoWatersLsssMatrix) Attributes() []fr.Element {
	return m.rhoRowToAttribute
}

// ComputeVector 计算指定行向量与给定向量的内积
//
// 该函数计算 M[rowIndex] · vector，其中M[rowIndex]是矩阵的第rowIndex行。
//
// 参数：
//   - rowIndex: 行索引
//   - vector: 输入向量，长度必须等于矩阵列数
//
// 返回值：
//   - fr.Element: 内积结果
//
// Panics：
//   - 当rowIndex越界时触发panic
func (m *LewkoWatersLsssMatrix) ComputeVector(rowIndex int, vector []fr.Element) fr.Element {
	if rowIndex < 0 || rowIndex >= m.rowNumber {
		panic("index out of Lewko Waters Lsss Matrix range")
	}
	result := new(fr.Element).SetZero()
	for i := 0; i < m.columnNumber; i++ {
		temp := new(fr.Element).Mul(&vector[i], &m.accessMatrix[rowIndex][i])
		result.Add(result, temp)
	}
	return *result
}

// FindLinearCombinationWeight 寻找满足条件的线性组合权重
//
// 该函数是LSSS方案的核心算法，用于判断给定的属性集合是否满足访问策略。
// 它通过高斯消元法求解线性方程组，找到权重 w₁, w₂, ..., wₘ 使得：
//
//	Σ(wᵢ × Mᵢ) = (1, 0, 0, ..., 0)
//
// 其中Mᵢ是满足属性条件的矩阵行。
//
// 时间复杂度：O(n·m²)，其中n是列数，m是满足条件的行数
//
// 参数：
//   - attributes: 用户拥有的属性集合
//
// 返回值：
//   - []int: 满足条件的行索引列表（相对于原矩阵的索引）
//   - []fr.Element: 对应的权重系数列表
//   - 如果无法满足访问策略（无解），返回 (nil, nil)
//
// 示例：
//
//	假设矩阵有5行，用户属性匹配第0,2,3行，且找到的权重为[2, -3, 1]
//	则返回 ([0, 2, 3], [2, -3, 1])
//	表示：2×M₀ + (-3)×M₂ + 1×M₃ = (1, 0, 0, ..., 0)
func (m *LewkoWatersLsssMatrix) FindLinearCombinationWeight(attributes []fr.Element) ([]int, []fr.Element) {
	var satisfiedRows []int

	// 构建属性映射
	attrMap := make(map[fr.Element]bool, len(attributes))
	for i := range attributes {
		attrMap[attributes[i]] = true
	}

	// 找到所有满足的行
	for i := 0; i < len(m.rhoRowToAttribute); i++ {
		if attrMap[m.rhoRowToAttribute[i]] {
			satisfiedRows = append(satisfiedRows, i)
		}
	}

	// 如果没有满足的行，返回nil
	if len(satisfiedRows) == 0 {
		return nil, nil
	}

	// 提取满足条件的行，构造子矩阵
	subMatrix := make([][]fr.Element, len(satisfiedRows))
	for i, rowIdx := range satisfiedRows {
		subMatrix[i] = make([]fr.Element, m.columnNumber)
		for j := 0; j < m.columnNumber; j++ {
			subMatrix[i][j] = m.accessMatrix[rowIdx][j]
		}
	}

	// 使用高斯消元求解
	weights := findWeightsGaussian(subMatrix, m.columnNumber)

	if weights == nil {
		return nil, nil
	}

	// 构造结果：过滤掉权重为0的行
	var resultRows []int
	var resultCoeffs []fr.Element

	for i, w := range weights {
		if !w.IsZero() {
			resultRows = append(resultRows, satisfiedRows[i])
			resultCoeffs = append(resultCoeffs, w)
		}
	}

	// 如果所有权重都为0，说明无解
	if len(resultRows) == 0 {
		return nil, nil
	}

	return resultRows, resultCoeffs
}

// Print 打印LSSS矩阵的详细信息
//
// 输出格式包括：
//   - 矩阵维度信息
//   - 每一行的索引、对应属性、以及向量值
func (m *LewkoWatersLsssMatrix) Print() {
	fmt.Println()
	fmt.Println("------------------------------------------------")
	fmt.Printf("matrix rowNumber: %d, columnNumber: %d \n", m.rowNumber, m.columnNumber)
	fmt.Println("ρ(i)  Matrix")
	for i := range m.accessMatrix {
		fmt.Printf("index %d || attribute: %s ||  ", i, m.rhoRowToAttribute[i].String())
		for j := range m.accessMatrix[i] {
			fmt.Printf(" %s ", (m.accessMatrix[i][j]).String())
		}
		fmt.Println()
	}
	fmt.Println("------------------------------------------------")
	fmt.Println()
}

// findWeightsGaussian 使用高斯消元法在有限域上求解线性方程组
//
// 该函数求解方程组：Σ(wᵢ × vᵢ) = (1, 0, 0, ..., 0)
// 其中vᵢ是输入的行向量，wᵢ是待求的权重。
//
// 算法步骤：
//  1. 构造增广矩阵 [A^T | b]，其中A^T是向量转置矩阵，b=(1,0,...,0)
//  2. 高斯消元：通过行变换将矩阵化为阶梯形
//  3. 回代求解：从下往上计算每个权重
//  4. 验证解的正确性
//
// 注意事项：
//   - 在有限域上进行运算，所有除法通过乘以逆元实现
//   - 对于欠定系统（向量数>维度），返回一个特解
//   - 对于超定系统（向量数<维度），可能无解
//
// 参数：
//   - vectors: m个行向量，每个长度为n
//   - n: 向量维度（列数）
//
// 返回值：
//   - []fr.Element: 长度为m的权重数组
//   - 如果无解返回nil
func findWeightsGaussian(vectors [][]fr.Element, n int) []fr.Element {

	if len(vectors) == 0 {
		return nil
	}

	m := len(vectors) // 向量个数（行数）

	// 构造增广矩阵 [A^T | b]
	// A^T 是 n×m 矩阵，其中 A^T[i][j] = vectors[j][i]
	augmented := make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		augmented[i] = make([]fr.Element, m+1)
		for j := 0; j < m; j++ {
			augmented[i][j] = vectors[j][i]
		}
		// 目标向量 b = (1, 0, 0, ..., 0)
		if i == 0 {
			augmented[i][m].SetOne()
		} else {
			augmented[i][m].SetZero()
		}
	}

	// 高斯消元法 - 前向消元
	for pivot := 0; pivot < min(n, m); pivot++ {
		// 部分主元选取：找到该列第一个非零元素
		maxRow := -1
		for row := pivot; row < n; row++ {
			if !augmented[row][pivot].IsZero() {
				maxRow = row
				break
			}
		}

		if maxRow == -1 {
			continue // 该列全为0，跳过
		}

		// 交换行
		if maxRow != pivot {
			augmented[pivot], augmented[maxRow] = augmented[maxRow], augmented[pivot]
		}

		// 计算主元的逆元
		var pivotInv fr.Element
		pivotInv.Inverse(&augmented[pivot][pivot])

		// 消元：将pivot列下方的元素变为0
		for row := pivot + 1; row < n; row++ {
			if augmented[row][pivot].IsZero() {
				continue
			}

			// factor = augmented[row][pivot] / augmented[pivot][pivot]
			var factor fr.Element
			factor.Mul(&augmented[row][pivot], &pivotInv)

			// 更新该行的所有元素
			for col := pivot; col <= m; col++ {
				// augmented[row][col] -= factor * augmented[pivot][col]
				var temp fr.Element
				temp.Mul(&factor, &augmented[pivot][col])
				augmented[row][col].Sub(&augmented[row][col], &temp)
			}
		}
	}

	// 检查是否有矛盾方程（左侧全0但右侧非0）
	for i := 0; i < n; i++ {
		allZero := true
		for j := 0; j < m; j++ {
			if !augmented[i][j].IsZero() {
				allZero = false
				break
			}
		}
		if allZero && !augmented[i][m].IsZero() {
			return nil // 无解
		}
	}

	// 回代求解
	w := make([]fr.Element, m)
	for i := 0; i < m; i++ {
		w[i].SetZero()
	}

	// 从下往上回代
	for i := min(n, m) - 1; i >= 0; i-- {
		if augmented[i][i].IsZero() {
			// 寻找该行是否有其他非零元素
			hasNonZero := false
			for j := i; j < m; j++ {
				if !augmented[i][j].IsZero() {
					hasNonZero = true
					break
				}
			}
			if !hasNonZero {
				continue
			}
			// 如果有非零元素但对角线为0，说明需要特殊处理
			// 这种情况在欠定系统中可能出现，我们寻找一个特解
			for j := i; j < m; j++ {
				if !augmented[i][j].IsZero() {
					// 设置这个变量为 (右侧值 / 系数)
					var inv fr.Element
					inv.Inverse(&augmented[i][j])

					sum := augmented[i][m]
					for k := j + 1; k < m; k++ {
						var temp fr.Element
						temp.Mul(&augmented[i][k], &w[k])
						sum.Sub(&sum, &temp)
					}

					w[j].Mul(&sum, &inv)
					break
				}
			}
			continue
		}

		// sum = augmented[i][m]
		sum := augmented[i][m]

		// sum -= Σ(augmented[i][j] * w[j]) for j > i
		for j := i + 1; j < m; j++ {
			var temp fr.Element
			temp.Mul(&augmented[i][j], &w[j])
			sum.Sub(&sum, &temp)
		}

		// w[i] = sum / augmented[i][i]
		var diagInv fr.Element
		diagInv.Inverse(&augmented[i][i])
		w[i].Mul(&sum, &diagInv)
	}

	// 验证解的正确性
	result := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		result[i].SetZero()
		for j := 0; j < m; j++ {
			var temp fr.Element
			temp.Mul(&w[j], &vectors[j][i])
			result[i].Add(&result[i], &temp)
		}
	}

	// 检查是否等于 (1, 0, 0, ..., 0)
	if !result[0].IsOne() {
		return nil
	}
	for i := 1; i < n; i++ {
		if !result[i].IsZero() {
			return nil
		}
	}

	return w
}
