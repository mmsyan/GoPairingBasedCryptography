package afp25_bibe

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func h(t *BatchLabel) bn254.G1Affine {
	h := sha256.New()
	h.Write(t.T)
	bytes := h.Sum(nil)
	var result bn254.G1Affine
	result.SetBytes(bytes)
	return result
}

func computePolynomialCoeffs(identities []*Identity) []fr.Element {
	// 从常数多项式 1 开始
	coeffs := []fr.Element{*new(fr.Element).SetOne()}

	// 如果没有根，直接返回 [1]
	if len(identities) == 0 {
		return coeffs
	}

	// 逐个乘以 (X - root)
	for _, identity := range identities {
		newCoeffs := make([]fr.Element, len(coeffs)+1)

		// 乘以 (X - root) = X * coeffs - root * coeffs
		for i := 0; i < len(coeffs); i++ {
			// -root * coeffs[i] 加到 newCoeffs[i]
			var temp fr.Element
			temp.Mul(&identity.Id, &coeffs[i])
			temp.Neg(&temp)
			newCoeffs[i].Add(&newCoeffs[i], &temp)

			// coeffs[i] 加到 newCoeffs[i+1] (X项)
			newCoeffs[i+1].Add(&newCoeffs[i+1], &coeffs[i])
		}

		coeffs = newCoeffs
	}

	return coeffs
}
