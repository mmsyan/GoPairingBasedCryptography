package afp25_bibe

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

// NewIdentity - 从大整数创建身份
func NewIdentity(id *big.Int) *Identity {
	var idElem fr.Element
	idElem.SetBigInt(id)
	return &Identity{Id: idElem}
}

// NewBatchLabel - 创建批标签
func NewBatchLabel(data []byte) *BatchLabel {
	return &BatchLabel{T: data}
}

// NewMessage - 从 GT 元素创建消息
func NewMessage(m bn254.GT) *Message {
	return &Message{M: m}
}

// RandomMessage - 生成随机消息 (用于测试)
func RandomMessage() (*Message, error) {
	// 生成一个随机的 GT 元素
	// GT 元素通常通过配对生成
	_, _, g1Gen, g2Gen := bn254.Generators()

	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}

	var g1Rand bn254.G1Affine
	g1Rand.ScalarMultiplication(&g1Gen, r.BigInt(new(big.Int)))

	gt, err := bn254.Pair([]bn254.G1Affine{g1Rand}, []bn254.G2Affine{g2Gen})
	if err != nil {
		return nil, err
	}

	return &Message{M: gt}, nil
}

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
