package utils

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ComputePolynomialValue 使用秦九韶算法计算多项式的值。一切运算都是模q运算
// q: 有限域的阶 (ecc.BN254.ScalarField())
// coefficient: 多项式的系数，其中 coefficient[i] 是 x^i 的系数。
// 例如：P(x) = a_3*x^3 + a_2*x^2 + a_1*x + a_0，则 coefficient = {a_0, a_1, a_2, a_3}。
// x: 要求值的点。
// 返回值: P(x) mod q 的计算结果 (*big.Int)

func ComputePolynomialValue(coefficient []fr.Element, x fr.Element) fr.Element {

	if len(coefficient) == 0 {
		return *new(fr.Element).SetZero()
	}
	result := new(fr.Element)

	// 1. 初始化 result = a_n (最高次系数) mod q。[0, q-1]，但为了安全，仍然执行 Mod
	result.Set(&coefficient[len(coefficient)-1])

	// 从倒数第二个系数开始 (a_{n-1}) 迭代到 a_0
	// i 的范围是 [len(coefficient)-2, 0]
	for i := len(coefficient) - 2; i >= 0; i-- {
		// 1. result = (result * x) mod q
		// 使用 Mul 方法将当前 result 乘以 x
		result.Mul(result, &x)

		// 2. result = (result + coefficient[i]) mod q
		// 使用 Add 方法将 coefficient[i] 加到 result 上
		result.Add(result, &coefficient[i])
	}

	// 返回计算结果的指针
	return *result
}
