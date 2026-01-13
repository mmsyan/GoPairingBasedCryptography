package afp25_bibe

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	hash2 "github.com/mmsyan/GoPairingBasedCryptography/hash"
	"math/big"
)

func h(t *BatchLabel) bn254.G1Affine {
	return hash2.BytesToG1(t.T)
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

func computeG1PolynomialTau(g1TauPowers []bn254.G1Affine, coef []fr.Element) bn254.G1Affine {
	var result bn254.G1Affine
	_, _, g1, _ := bn254.Generators()
	result.ScalarMultiplication(&g1, coef[0].BigInt(new(big.Int)))
	for i := 1; i < len(coef); i++ {
		var term bn254.G1Affine
		term.ScalarMultiplication(&g1TauPowers[i-1], coef[i].BigInt(new(big.Int)))
		result.Add(&result, &term)
	}
	return result
}
