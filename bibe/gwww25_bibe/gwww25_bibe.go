package gwww25_bibe

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

type BatchIBEParams struct {
	B int
}

type MasterSecretKey struct {
	W     fr.Element
	V     fr.Element
	H     fr.Element
	Alpha fr.Element
}

type MasterPublicKey struct {
	G2ExpTauPowers []bn254.G2Affine
	G1ExpTau       bn254.G1Affine
	G1ExpW         bn254.G1Affine
	G1ExpWTau      bn254.G1Affine
	G1ExpV         bn254.G1Affine
	G1ExpH         bn254.G1Affine
	GTExpAlpha     bn254.GT
}

type Identity struct {
	Id fr.Element
}

type BatchLabel struct {
	Tg fr.Element
}

type BatchDigest struct {
	D bn254.G2Affine
}

type Message struct {
	M bn254.GT
}

type Ciphertext struct {
	Ct1 bn254.G1Affine
	Ct2 bn254.G1Affine
	Ct3 bn254.G1Affine
	Ct4 bn254.GT
}

type SecretKey struct {
	Y  fr.Element
	U1 bn254.G2Affine
	U2 bn254.G2Affine
}

func Setup(B int) (*BatchIBEParams, error) {
	if B < 1 {
		return nil, fmt.Errorf("invalid B")
	}
	return &BatchIBEParams{
		B: B,
	}, nil
}

func KeyGen(params *BatchIBEParams) (*MasterPublicKey, *MasterSecretKey, error) {
	elements := make([]*fr.Element, 5)
	for i := range elements {
		elements[i] = new(fr.Element)
		if _, err := elements[i].SetRandom(); err != nil {
			return nil, nil, err
		}
	}
	// tau,w,v,h,alpha <- Zp
	tau, w, v, h, alpha := elements[0], elements[1], elements[2], elements[3], elements[4]

	g1ExpTau := new(bn254.G1Affine).ScalarMultiplicationBase(tau.BigInt(new(big.Int))) // [τ]1
	g1ExpW := new(bn254.G1Affine).ScalarMultiplicationBase(w.BigInt(new(big.Int)))     // [w]1
	wMulTau := new(fr.Element).Mul(tau, w)
	g1ExpWTau := new(bn254.G1Affine).ScalarMultiplicationBase(wMulTau.BigInt(new(big.Int))) // [wτ]1
	g1ExpV := new(bn254.G1Affine).ScalarMultiplicationBase(v.BigInt(new(big.Int)))          // [v]1
	g1ExpH := new(bn254.G1Affine).ScalarMultiplicationBase(h.BigInt(new(big.Int)))          // [h]1
	gtExpAlpha := new(bn254.GT).SetOne()
	gtExpAlpha.Exp(*gtExpAlpha, alpha.BigInt(new(big.Int))) // [α]T

	g2ExpTauPowers := make([]bn254.G2Affine, params.B) // [τ]2, [τ^2]2, [τ^3]2, ..., [τ^B]2
	tauPower := tau
	for i := 0; i < params.B; i++ {
		g2ExpTauPowers[i] = *new(bn254.G2Affine).ScalarMultiplicationBase(tauPower.BigInt(new(big.Int)))
		tauPower = tauPower.Mul(tauPower, tau)
	}

	return &MasterPublicKey{
			G2ExpTauPowers: g2ExpTauPowers,
			G1ExpTau:       *g1ExpTau,
			G1ExpW:         *g1ExpW,
			G1ExpWTau:      *g1ExpWTau,
			G1ExpV:         *g1ExpV,
			G1ExpH:         *g1ExpH,
			GTExpAlpha:     *gtExpAlpha,
		}, &MasterSecretKey{
			W:     *w,
			V:     *v,
			H:     *h,
			Alpha: *alpha,
		}, nil
}

func Encrypt(pk *MasterPublicKey, m *Message, id *Identity, t *BatchLabel) (*Ciphertext, error) {
	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}

	// ct = [s]1
	ct1 := *new(bn254.G1Affine).ScalarMultiplicationBase(s.BigInt(new(big.Int))) // [s]1

	// ct2 = s[wτ]1-(s·id)[w]1
	swtau1 := new(bn254.G1Affine).ScalarMultiplication(&pk.G1ExpWTau, s.BigInt(new(big.Int)))
	sid := new(fr.Element).Mul(s, &id.Id)
	sidw1 := new(bn254.G1Affine).ScalarMultiplication(&pk.G1ExpW, sid.BigInt(new(big.Int)))
	ct2 := *new(bn254.G1Affine).Sub(swtau1, sidw1)

	// ct3 = s([v]1+tg·[h]1)
	tgh1 := new(bn254.G1Affine).ScalarMultiplication(&pk.G1ExpH, t.Tg.BigInt(new(big.Int)))
	v1Addtgh1 := new(bn254.G1Affine).Add(&pk.G1ExpV, tgh1)
	ct3 := *new(bn254.G1Affine).ScalarMultiplication(v1Addtgh1, s.BigInt(new(big.Int)))

	// c2 = s[α]T+[m]T
	sAlphaT := new(bn254.GT).Exp(pk.GTExpAlpha, s.BigInt(new(big.Int)))
	ct4 := *new(bn254.GT).Mul(sAlphaT, &m.M)

	return &Ciphertext{
		Ct1: ct1,
		Ct2: ct2,
		Ct3: ct3,
		Ct4: ct4,
	}, nil
}

func Digest(pk *MasterPublicKey, identities []*Identity) (*BatchDigest, error) {
	if len(identities) == 0 {
		return nil, errors.New("identities is empty")
	}
	if len(identities) > len(pk.G2ExpTauPowers) {
		return nil, errors.New("too many identities for batch size")
	}

	// Fs(x)=(x-id)
	coefficients := computePolynomialCoeffs(identities)
	var d bn254.G2Affine
	_, _, _, g2 := bn254.Generators()
	d.ScalarMultiplication(&g2, coefficients[0].BigInt(new(big.Int)))

	// dig = [Fs(τ)]2
	for i := 1; i < len(coefficients); i++ {
		var temp bn254.G2Affine
		temp.ScalarMultiplication(&pk.G2ExpTauPowers[i-1], coefficients[i].BigInt(new(big.Int)))
		d.Add(&d, &temp)
	}

	return &BatchDigest{
		D: d,
	}, nil
}

func ComputeKey(msk *MasterSecretKey, d *BatchDigest, t *BatchLabel) (*SecretKey, error) {
	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}
	y, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}

	// u1 = [r]2
	g2ExpR := new(bn254.G2Affine).ScalarMultiplicationBase(r.BigInt(new(big.Int)))

	// yw
	yw := new(fr.Element).Mul(y, &msk.W)
	// yw[d]2
	ywd2 := new(bn254.G2Affine).ScalarMultiplication(&d.D, yw.BigInt(new(big.Int)))

	temp := new(fr.Element).Mul(&msk.H, &t.Tg)
	temp.Add(&msk.V, temp)
	temp.Mul(r, temp)
	g2ExpTemp := new(bn254.G2Affine).ScalarMultiplicationBase(temp.BigInt(new(big.Int)))
	// u[2] = [α + r(v+h·tg)]2 + yw·[d]2, dig = [d]2
	u2 := new(bn254.G2Affine).Add(ywd2, g2ExpTemp)

	return &SecretKey{
		Y:  *y,
		U1: *g2ExpR,
		U2: *u2,
	}, nil
}

func Decrypt(mpk *MasterPublicKey, sk *SecretKey, identities []*Identity, id *Identity, tg *BatchLabel, ct *Ciphertext) (*Message, error) {
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

	// 2. 计算 π = g2^q(τ)
	var pi bn254.G2Affine
	pi.ScalarMultiplicationBase(qCoeffs[0].BigInt(new(big.Int)))
	for i := 1; i < len(qCoeffs); i++ {
		var term bn254.G2Affine
		term.ScalarMultiplication(&mpk.G2ExpTauPowers[i-1], qCoeffs[i].BigInt(new(big.Int)))
		pi.Add(&pi, &term)
	}

	// [ct1]1 · [u2]2
	eCt1U2, err := bn254.Pair([]bn254.G1Affine{ct.Ct1}, []bn254.G2Affine{sk.U2})
	if err != nil {
		return nil, err
	}
	yct2 := *new(bn254.G1Affine).ScalarMultiplication(&ct.Ct2, sk.Y.BigInt(new(big.Int)))
	eYCt2Pi, err := bn254.Pair([]bn254.G1Affine{yct2}, []bn254.G2Affine{pi})
	if err != nil {
		return nil, err
	}

	eCt3U1, err := bn254.Pair([]bn254.G1Affine{ct.Ct3}, []bn254.G2Affine{sk.U1})
	if err != nil {
		return nil, err
	}

	temp := new(bn254.GT).Div(&eCt1U2, &eYCt2Pi)
	temp.Div(temp, &eCt3U1)
	message := new(bn254.GT).Div(&ct.Ct4, temp)

	return &Message{
		M: *message,
	}, nil
}
