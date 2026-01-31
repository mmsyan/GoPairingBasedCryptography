package ibbe07

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ComputePolyCoefficients
// 计算(x+r1)(x+r2)...(x+rn)
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
