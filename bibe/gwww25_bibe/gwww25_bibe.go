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
	U     fr.Element
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
	Sk bn254.G1Affine
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
			U:     *v,
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
