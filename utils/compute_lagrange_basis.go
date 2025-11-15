package utils

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ComputeLagrangeBasis 计算拉格朗日基函数在 x 处的值：Delta_{i, S}(x) mod q
func ComputeLagrangeBasis(i int, s []int, x int) fr.Element {
	iElement := new(fr.Element).SetInt64(int64(i))
	xElement := new(fr.Element).SetInt64(int64(x))
	delta := new(fr.Element).SetOne()

	for _, j := range s {
		if i != j {
			jElement := new(fr.Element).SetInt64(int64(j))

			// 1. 计算 分子: (x - j) mod q。numerator = (x - j) mod q
			numerator := new(fr.Element).Sub(xElement, jElement)

			// 2. 计算 分母: (i - j) mod q。denominator = (i - j) mod q
			denominator := new(fr.Element).Sub(iElement, jElement)

			// 3. 计算 模逆: (i - j)^-1 mod q。invDenominator = (i - j)^-1 mod q
			invDenominator := new(fr.Element).Inverse(denominator)

			// 4. 计算分数: (x - j) * (i - j)^-1 mod q。fraction = numerator * invDenominator mod q
			fraction := new(fr.Element).Mul(numerator, invDenominator)

			// 5. 更新 delta: delta = delta * fraction mod q
			delta.Mul(delta, fraction)
		}
	}

	return *delta
}
