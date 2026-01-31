package ibbe07

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GoPairingBasedCryptography/hash"
	"math/big"
)

type MasterSecretKey struct {
	G     bn254.G1Affine
	Gamma fr.Element
}

type PublicKey struct {
	W            bn254.G1Affine
	V            bn254.GT
	H            bn254.G2Affine
	HGammaPowers []bn254.G2Affine
}

type Identity struct {
	Id []byte
}

type UserSecretKey struct {
	Sk bn254.G1Affine
}

type Message struct {
}

type Ciphertext struct {
	C1 bn254.G1Affine
	C2 bn254.G2Affine
	K  bn254.GT
}

func Setup(m int) (*PublicKey, *MasterSecretKey, error) {
	elements := make([]*fr.Element, 5)
	for i := 0; i < len(elements); i++ {
		_, err := elements[i].SetRandom()
		if err != nil {
			return nil, nil, err
		}
	}
	gElement, hElement, gamma := elements[0], elements[1], elements[2]
	// g ∈ G1
	g := new(bn254.G1Affine).ScalarMultiplicationBase(gElement.BigInt(new(big.Int)))
	// h ∈ G2
	h := new(bn254.G2Affine).ScalarMultiplicationBase(hElement.BigInt(new(big.Int)))
	// w = g ^ Γ
	w := new(bn254.G1Affine).ScalarMultiplication(g, gamma.BigInt(new(big.Int)))
	// v = e(g, h)
	v, err := bn254.Pair([]bn254.G1Affine{*g}, []bn254.G2Affine{*h})
	if err != nil {
		return nil, nil, err
	}

	hGammaPowers := make([]bn254.G2Affine, m)
	gammaPower := new(fr.Element).SetOne()
	for i := 0; i < m; i++ {
		hGammaPowers[i] = *new(bn254.G2Affine).ScalarMultiplication(h, gammaPower.BigInt(new(big.Int)))
		gammaPower.Mul(gammaPower, gamma)
	}

	return &PublicKey{
			W:            *w,
			V:            v,
			H:            *h,
			HGammaPowers: hGammaPowers,
		}, &MasterSecretKey{
			G:     *g,
			Gamma: *gamma,
		}, nil
}

func Extract(msk *MasterSecretKey, id *Identity) (*UserSecretKey, error) {
	hid := hash.BytesToField(id.Id)
	gammaAddHid := new(fr.Element).Add(&msk.Gamma, &hid)
	inverseGammaAddHid := new(fr.Element).Inverse(gammaAddHid)
	// sk_{id} = g ^ {1 / gamma+H(id)}
	sk := new(bn254.G1Affine).ScalarMultiplication(&msk.G, inverseGammaAddHid.BigInt(new(big.Int)))
	return &UserSecretKey{
		Sk: *sk,
	}, nil
}

//func Encrypt(s []Identity, pk *PublicKey) (*Ciphertext, error) {
//k, err := new(fr.Element).SetRandom()
//if err != nil {
//	return nil, err
//}
//
//negK := new(fr.Element).Neg(k)
//// c1 = w^{-k}
//C1 := new(bn254.G1Affine).ScalarMultiplication(&pk.W, negK.BigInt(new(big.Int)))
//
//// c2 = h^{k }
//prodIdentity := new(fr.Element).SetOne()
//for _, id := range s {
//	hid := hash.BytesToField(id.Id)
//	temp := new(fr.Element).Add(pk.)
//}
//
//C2 := new(bn254.G2Affine).ScalarMultiplication(&pk.H, negK.BigInt(new(big.Int)))
//
//K := new(bn254.GT).Exp(pk.V, k.BigInt(new(big.Int)))
//}
