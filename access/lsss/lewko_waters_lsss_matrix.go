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
	rowNumber    int            // 矩阵行数
	columnNumber int            // 矩阵列数
	accessMatrix [][]fr.Element // 访问矩阵，每行是一个向量
	rho          []fr.Element   // 行索引到属性的映射，rho[i]表示第i行对应的属性
}

// NewLSSSMatrixFromBinaryTree 从二叉访问树构造LSSS矩阵
//
// 该函数通过递归遍历访问树，将其转换为LSSS矩阵表示：
//   - OR门：左右子节点继承父节点的向量
//   - AND门：左子节点追加-1，右子节点追加1，并增加列维度
//   - 叶子节点：成为矩阵的一行
//
// 参考：https://eprint.iacr.org/2010/351.pdf
// <Decentralizing Attribute-Based Encryption> Appendix G
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
			// we pad v with 0’s at the end (if necessary) to make it of length c.
			node.VectorPadZero(counter)

			// Then we label one of its children with the vector v|1 (where|denotes concatenation)
			// and the other with the vector (0, . . . , 0)|− 1, where (0, . . . , 0) denotes the zero vector of length c.
			// Note that these two vectors sum to v|0.

			// node left: 0_counter | -1
			node.Left.VectorPadZero(counter)
			node.Left.Vector = append(node.Left.Vector, minusOneElement)

			// node right: v | 1
			node.Right.Vector = copyVector(node.Vector)
			node.Right.Vector = append(node.Right.Vector, oneElement)

			// // We now increment the value of c by 1. counter++
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
		rowNumber:    len(matrix),
		columnNumber: len(matrix[0]),
		accessMatrix: matrix,
		rho:          rho,
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
	return m.rho[rowIndex]
}

// Attributes 返回所有行对应的属性列表
//
// 返回值：
//   - []fr.Element: 属性列表，索引i对应第i行的属性
func (m *LewkoWatersLsssMatrix) Attributes() []fr.Element {
	return m.rho
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
	for i := 0; i < len(m.rho); i++ {
		if attrMap[m.rho[i]] {
			satisfiedRows = append(satisfiedRows, i)
		}
	}

	fmt.Println("satisfiedRows: ", satisfiedRows)

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
		fmt.Printf("index %d || attribute: %s ||  ", i, m.rho[i].String())
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
	augmented := make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		augmented[i] = make([]fr.Element, m+1)
		for j := 0; j < m; j++ {
			augmented[i][j] = vectors[j][i]
		}
		if i == 0 {
			augmented[i][m].SetOne()
		} else {
			augmented[i][m].SetZero()
		}
	}

	// 记录每一行的主元列位置
	pivotCol := make([]int, n)
	for i := range pivotCol {
		pivotCol[i] = -1
	}

	// 高斯消元法 - 前向消元
	currentRow := 0
	for col := 0; col < m && currentRow < n; col++ {
		// 找到该列第一个非零元素
		maxRow := -1
		for row := currentRow; row < n; row++ {
			if !augmented[row][col].IsZero() {
				maxRow = row
				break
			}
		}

		if maxRow == -1 {
			continue // 该列全为0，跳过
		}

		// 记录主元位置
		pivotCol[currentRow] = col

		// 交换行
		if maxRow != currentRow {
			augmented[currentRow], augmented[maxRow] = augmented[maxRow], augmented[currentRow]
		}

		// 计算主元的逆元
		var pivotInv fr.Element
		pivotInv.Inverse(&augmented[currentRow][col])

		// 消元：将该列下方的元素变为0
		for row := currentRow + 1; row < n; row++ {
			if augmented[row][col].IsZero() {
				continue
			}

			var factor fr.Element
			factor.Mul(&augmented[row][col], &pivotInv)

			for c := col; c <= m; c++ {
				var temp fr.Element
				temp.Mul(&factor, &augmented[currentRow][c])
				augmented[row][c].Sub(&augmented[row][c], &temp)
			}
		}

		currentRow++
	}

	// 检查是否有矛盾方程
	for i := currentRow; i < n; i++ {
		if !augmented[i][m].IsZero() {
			return nil // 无解
		}
	}

	// 回代求解
	w := make([]fr.Element, m)
	for i := 0; i < m; i++ {
		w[i].SetZero() // 自由变量默认设为0
	}

	// 从下往上回代，只处理有主元的行
	for i := currentRow - 1; i >= 0; i-- {
		col := pivotCol[i]
		if col == -1 {
			continue
		}

		// sum = augmented[i][m] - Σ(augmented[i][j] * w[j]) for j > col
		sum := augmented[i][m]
		for j := col + 1; j < m; j++ {
			var temp fr.Element
			temp.Mul(&augmented[i][j], &w[j])
			sum.Sub(&sum, &temp)
		}

		// w[col] = sum / augmented[i][col]
		var diagInv fr.Element
		diagInv.Inverse(&augmented[i][col])
		w[col].Mul(&sum, &diagInv)
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
