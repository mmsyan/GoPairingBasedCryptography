package utils

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// GenerateRandomPolynomial 生成一个次数最高为 (degree - 1) 的多项式的系数列表。
//
// 注意：多项式的系数是按低次到高次的顺序排列：{a_0, a_1, ..., a_{degree-1}}
// degree:   多项式系数列表的长度（即最高次数 + 1）。
// constantTerm: 多项式的常数项系数 a_0。
// 返回值:   一个 []*big.Int 数组，表示多项式的系数。
func GenerateRandomPolynomial(degree int, constantTerm fr.Element) []fr.Element {
	if degree <= 0 {
		return []fr.Element{}
	}
	coefficients := make([]fr.Element, degree)
	coefficients[0] = constantTerm
	for i := 1; i < degree; i++ {
		randomCoef, err := new(fr.Element).SetRandom()
		if err != nil {
			panic(err)
		}
		coefficients[i] = *randomCoef
	}
	return coefficients
}
