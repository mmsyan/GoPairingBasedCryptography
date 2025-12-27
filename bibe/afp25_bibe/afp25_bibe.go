package afp25_bibe

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

type BatchIBEParams struct {
	B int
}

type MasterSecretKey struct {
	Msk fr.Element
}

type MasterPublicKey struct {
	G1ExpTauPower []bn254.G1Affine
	G2ExpTau      bn254.G2Affine
	G2ExpMsk      bn254.G2Affine
}

type Identity struct {
	Id fr.Element
}

type BatchLabel struct {
	T []byte
}

type BatchDigest struct {
	D bn254.G1Affine
}

type Message struct {
	M bn254.GT
}

type Ciphertext struct {
	C1 [3]bn254.G2Affine
	C2 bn254.GT
}

type SecretKey struct {
	Sk bn254.G1Affine
}

func Setup(B int) (*BatchIBEParams, error) {
	if B < 1 {
		return nil, errors.New("invalid B")
	}
	return &BatchIBEParams{
		B: B,
	}, nil
}

func KeyGen(params *BatchIBEParams) (*MasterPublicKey, *MasterSecretKey, error) {
	msk, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, err
	}
	tau, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, err
	}
	tauPower := new(fr.Element).Set(tau)
	g1ExpTaus := make([]bn254.G1Affine, params.B)
	for i := 0; i < params.B; i++ {
		g1ExpTaus[i] = *new(bn254.G1Affine).ScalarMultiplicationBase(tauPower.BigInt(new(big.Int)))
		tauPower.Mul(tauPower, tau)
	}
	g2ExpTau := *new(bn254.G2Affine).ScalarMultiplicationBase(tau.BigInt(new(big.Int)))
	g2ExpMsk := *new(bn254.G2Affine).ScalarMultiplicationBase(msk.BigInt(new(big.Int)))
	return &MasterPublicKey{
			G1ExpTauPower: g1ExpTaus,
			G2ExpTau:      g2ExpTau,
			G2ExpMsk:      g2ExpMsk,
		}, &MasterSecretKey{
			Msk: *msk,
		}, nil
}

func Encrypt(pk *MasterPublicKey, m *Message, id *Identity, t *BatchLabel) (*Ciphertext, error) {
	var a [2][3]bn254.G2Affine
	_, _, _, g2 := bn254.Generators()
	a[0][0] = g2
	g2ExpId := new(bn254.G2Affine).ScalarMultiplicationBase(id.Id.BigInt(new(big.Int)))
	g2ExpIdDivTau := new(bn254.G2Affine).Sub(g2ExpId, &pk.G2ExpTau)
	a[0][1] = *g2ExpIdDivTau
	a[0][2].SetInfinity()
	a[1][0] = pk.G2ExpMsk
	a[1][1].SetInfinity()
	negG2 := new(bn254.G2Affine).Neg(&g2)
	a[1][2] = *negG2

	var b [2]bn254.GT
	b[0] = *new(bn254.GT).SetOne()
	eHtG2ExpMsk, err := bn254.Pair([]bn254.G1Affine{
		h(t),
	}, []bn254.G2Affine{
		pk.G2ExpMsk,
	})
	if err != nil {
		return nil, err
	}
	b[1] = eHtG2ExpMsk

	r1, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}

	r2, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}

	// c1 = r^T * A
	var c1 [3]bn254.G2Affine
	for j := 0; j < 3; j++ {
		var temp1, temp2 bn254.G2Affine
		temp1.ScalarMultiplication(&a[0][j], r1.BigInt(new(big.Int)))
		temp2.ScalarMultiplication(&a[1][j], r2.BigInt(new(big.Int)))
		c1[j].Add(&temp1, &temp2)
	}

	// c2 = r^T · b + m
	var c2 bn254.GT
	// r^T · b = b[0]^r1 * b[1]^r2
	var bPart1, bPart2 bn254.GT
	bPart1.Exp(b[0], r1.BigInt(new(big.Int)))
	bPart2.Exp(b[1], r2.BigInt(new(big.Int)))

	c2.Mul(&bPart1, &bPart2)
	c2.Mul(&c2, &m.M)

	return &Ciphertext{
		C1: c1,
		C2: c2,
	}, nil

}

func Digest(pk *MasterPublicKey, identities []*Identity) (*BatchDigest, error) {
	if len(identities) == 0 {
		return nil, errors.New("identities is empty")
	}
	if len(identities) > len(pk.G1ExpTauPower) {
		return nil, errors.New("too many identities for batch size")
	}
	coefficients := computePolynomialCoeffs(identities)
	var d bn254.G1Affine
	_, _, g1, _ := bn254.Generators()

	d.ScalarMultiplication(&g1, coefficients[0].BigInt(new(big.Int)))

	for i := 1; i < len(coefficients); i++ {
		var temp bn254.G1Affine
		temp.ScalarMultiplication(&pk.G1ExpTauPower[i-1], coefficients[i].BigInt(new(big.Int)))
		d.Add(&d, &temp)
	}

	return &BatchDigest{
		D: d,
	}, nil
}

func ComputeKey(msk *MasterSecretKey, d *BatchDigest, t *BatchLabel) (*SecretKey, error) {
	ht := h(t)
	dMulHt := new(bn254.G1Affine).Add(&d.D, &ht)
	sk := *new(bn254.G1Affine).ScalarMultiplication(dMulHt, msk.Msk.BigInt(new(big.Int)))
	return &SecretKey{
		Sk: sk,
	}, nil
}

func Decrypt(c *Ciphertext, sk *SecretKey, d *BatchDigest, identities []*Identity, id *Identity, t *BatchLabel, pk *MasterPublicKey) (*Message, error) {
	// 1. 构造商多项式 q(X) = f(X) / (X - id)
	// q(X) 的根为 identities \ {id}
	var rootsWithoutId []*Identity
	for _, identity := range identities {
		if !identity.Id.Equal(&id.Id) {
			rootsWithoutId = append(rootsWithoutId, identity)
		}
	}

	if len(rootsWithoutId) != len(identities)-1 {
		return nil, errors.New("identity not found in identity list")
	}

	qCoeffs := computePolynomialCoeffs(rootsWithoutId)

	// 2. 计算 π = g1^q(τ)
	var pi bn254.G1Affine
	_, _, g1, _ := bn254.Generators()

	pi.ScalarMultiplication(&g1, qCoeffs[0].BigInt(new(big.Int)))

	for i := 1; i < len(qCoeffs); i++ {
		var term bn254.G1Affine
		term.ScalarMultiplication(&pk.G1ExpTauPower[i-1], qCoeffs[i].BigInt(new(big.Int)))
		pi.Add(&pi, &term)
	}

	// 3. 构造向量 w = (d, π, sk) ∈ (G1)^3
	w := [3]bn254.G1Affine{
		d.D,
		pi,
		sk.Sk,
	}

	// 4. 计算 c1 ∘ w = e(c1[0], w[0]) * e(c1[1], w[1]) * e(c1[2], w[2])
	pairing1, err := bn254.Pair([]bn254.G1Affine{w[0]}, []bn254.G2Affine{c.C1[0]})
	if err != nil {
		return nil, err
	}

	pairing2, err := bn254.Pair([]bn254.G1Affine{w[1]}, []bn254.G2Affine{c.C1[1]})
	if err != nil {
		return nil, err
	}

	pairing3, err := bn254.Pair([]bn254.G1Affine{w[2]}, []bn254.G2Affine{c.C1[2]})
	if err != nil {
		return nil, err
	}

	var c1DotW bn254.GT
	c1DotW.Mul(&pairing1, &pairing2)
	c1DotW.Mul(&c1DotW, &pairing3)

	// 5. 计算 m = c2 / (c1 ∘ w) = c2 * (c1 ∘ w)^(-1)
	var m bn254.GT
	m.Div(&c.C2, &c1DotW)

	return &Message{
		M: m,
	}, nil
}
