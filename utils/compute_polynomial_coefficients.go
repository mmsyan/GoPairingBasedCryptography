package utils

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// ComputePolyCoefficients 计算多项式 ∏(x + rᵢ) 的展开系数
//
// 功能说明：
//
//	给定元素集合 [r₁, r₂, ..., rₙ]，计算多项式乘积：
//	(x + r₁)(x + r₂)...(x + rₙ)
//	并返回展开后的系数数组 [c₀, c₁, c₂, ..., cₙ]，表示多项式：
//	c₀ + c₁·x + c₂·x² + ... + cₙ·xⁿ
//
// 参数：
//
//	elements - 多项式中的常数项数组 [r₁, r₂, ..., rₙ]
//
// 返回值：
//
//	系数数组，其中：
//	- coefficients[0] = r₁·r₂·...·rₙ (常数项，所有元素的乘积)
//	- coefficients[i] = xⁱ 的系数
//	- coefficients[n] = 1 (最高次项系数始终为1)
//
// 算法示例：
//
//	输入: [r₁, r₂]
//	步骤1: (x + r₁) → [r₁, 1]
//	步骤2: (x + r₁)(x + r₂) → [r₁·r₂, r₁+r₂, 1]
//	输出: [r₁·r₂, r₁+r₂, 1] 表示 r₁·r₂ + (r₁+r₂)x + x²
//
// 时间复杂度: O(n²)，其中 n = len(elements)
// 空间复杂度: O(n)
func ComputePolyCoefficients(elements []fr.Element) []fr.Element {
	coefficients := []fr.Element{*new(fr.Element).SetOne()}
	if len(elements) == 0 {
		return coefficients
	}

	for _, r := range elements {
		newCoefficients := make([]fr.Element, len(coefficients)+1)
		for i := 0; i < len(coefficients); i++ {
			var tmp fr.Element

			// tmp = r * ci
			tmp.Mul(&r, &coefficients[i])

			// ci' += r * ci
			newCoefficients[i].Add(&newCoefficients[i], &tmp)
			// c{i+1}' += ci
			newCoefficients[i+1].Add(&newCoefficients[i+1], &coefficients[i])
		}
		coefficients = newCoefficients
	}

	return coefficients
}
