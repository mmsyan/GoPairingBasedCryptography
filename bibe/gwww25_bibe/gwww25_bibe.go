// Package gwww25_bibe
// implements the Junqing Gong, Brent Waters, Hoeteck Wee, David J. Wu's Batch Identity Based Encryption(GWWW25's BIBE)
// 作者: mmsyan
// 日期: 2026-01-13
// 参考论文:
// eprint: https://eprint.iacr.org/2025/2103
// @misc{cryptoeprint:2025/2103,
//
//	author = {Junqing Gong and Brent Waters and Hoeteck Wee and David J. Wu},
//	title = {Threshold Batched Identity-Based Encryption from Pairings in the Plain Model},
//	howpublished = {Cryptology {ePrint} Archive, Paper 2025/2103},
//	year = {2025},
//	url = {https://eprint.iacr.org/2025/2103}}
package gwww25_bibe

import (
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

	_, _, g1, g2 := bn254.Generators()
	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		return nil, nil, err
	}
	gtExpAlpha := new(bn254.GT).Exp(eG1G2, alpha.BigInt(new(big.Int))) // [α]T

	tauPower := new(fr.Element).Set(tau)
	g2ExpTauPowers := make([]bn254.G2Affine, params.B) // [τ]2, [τ^2]2, [τ^3]2, ..., [τ^B]2
	for i := 0; i < params.B; i++ {
		g2ExpTauPowers[i] = *new(bn254.G2Affine).ScalarMultiplicationBase(tauPower.BigInt(new(big.Int)))
		tauPower.Mul(tauPower, tau)
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

	// ct4 = s[α]T+[m]T
	sAlphaT := new(bn254.GT).Exp(pk.GTExpAlpha, s.BigInt(new(big.Int)))
	ct4 := *new(bn254.GT).Mul(sAlphaT, &m.M)

	return &Ciphertext{
		Ct1: ct1,
		Ct2: ct2,
		Ct3: ct3,
		Ct4: ct4,
	}, nil
}

func Digest(mpk *MasterPublicKey, identities []*Identity) (*BatchDigest, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("identities is empty")
	}
	if len(identities) > len(mpk.G2ExpTauPowers) {
		return nil, fmt.Errorf("too many identities for batch size")
	}
	// Fs(x)=(x-id)
	coef := computePolynomialCoeffs(identities)
	fmt.Printf("digest coefficients: %v\n", coef)
	d := computeG2PolynomialTau(mpk.G2ExpTauPowers, coef)
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

	temp := new(fr.Element).Mul(&msk.H, &t.Tg) // h·tg
	temp.Add(&msk.V, temp)                     // v + h·tg
	temp.Mul(r, temp)                          // r(v + h·tg)
	temp.Add(&msk.Alpha, temp)                 // α + r(v + h·tg)
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
		return nil, fmt.Errorf("identity not found in identity list")
	}
	qCoef := computePolynomialCoeffs(rootsWithoutId)
	fmt.Printf("qCoeffs: %v\n", qCoef)

	// 2. 计算 π = g2^q(τ)
	pi := computeG2PolynomialTau(mpk.G2ExpTauPowers, qCoef)

	// 3. 计算分量
	// [ct1]1 · [u2]2
	pairA, err := bn254.Pair([]bn254.G1Affine{ct.Ct1}, []bn254.G2Affine{sk.U2})
	if err != nil {
		return nil, fmt.Errorf("failed to calculate eCt1")
	}
	yct2 := *new(bn254.G1Affine).ScalarMultiplication(&ct.Ct2, sk.Y.BigInt(new(big.Int)))
	// y[ct]1 · pi
	pairB, err := bn254.Pair([]bn254.G1Affine{yct2}, []bn254.G2Affine{pi})
	if err != nil {
		return nil, fmt.Errorf("failed to calculate eYct2")
	}

	// [ct3]1 · [u1]2
	pairC, err := bn254.Pair([]bn254.G1Affine{ct.Ct3}, []bn254.G2Affine{sk.U1})
	if err != nil {
		return nil, fmt.Errorf("failed to calculate eCt3")
	}

	temp1 := new(bn254.GT).Div(&pairA, &pairB)
	temp2 := new(bn254.GT).Div(temp1, &pairC)
	message := new(bn254.GT).Div(&ct.Ct4, temp2)

	return &Message{
		M: *message,
	}, nil
}
