package bls

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
)

type BLSParams struct {
	G1Generator bn254.G1Affine
	DST         []byte
}

type BLSKeyPair struct {
	PrivateKey *big.Int
	PublicKey  bn254.G1Affine
}

type BLSSignature struct {
	Message   []byte
	Signature bn254.G2Affine
}

// BLS签名初始化操作
// 返回域的大小、G1群的生成元、BLS签名的DST
func SetUp() (*BLSParams, error) {
	_, _, g1, _ := bn254.Generators()
	return &BLSParams{
		G1Generator: g1,
		DST:         []byte("signature Signature"),
	}, nil
}

func KeyGeneration(blsParams BLSParams) (*BLSKeyPair, error) {
	x, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}
	var g1x bn254.G1Affine
	g1x.ScalarMultiplication(&blsParams.G1Generator, x)

	// private key: x <- Zq
	// public key: g1^x
	return &BLSKeyPair{
		PrivateKey: x,
		PublicKey:  g1x,
	}, nil
}

func Sign(blsParams BLSParams, privateKey *big.Int, message []byte) (*BLSSignature, error) {
	// compute h(m): message to point
	hm, err := bn254.HashToG2(message, blsParams.DST)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %v", err)
	}
	var hmx bn254.G2Affine
	// compute h(m)^x
	hmx.ScalarMultiplication(&hm, privateKey)

	// signature signature: (m, h(m)^x)
	return &BLSSignature{
		Message:   message,
		Signature: hmx,
	}, nil
}

func Verify(blsParams BLSParams, publicKey bn254.G1Affine, blsSignature BLSSignature) (bool, error) {
	hm, err := bn254.HashToG2(blsSignature.Message, blsParams.DST)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %v", err)
	}

	var negSignature bn254.G2Affine
	negSignature.Neg(&blsSignature.Signature)
	// e(g1^x, h(m)) =?= e(g1, h(m)^x)
	// e(publicKey, hm) =?= e(G1Generator, Signature)
	// e(publicKey, hm) * e(G1Generator, negSignature) =?= 1
	isValid, err := bn254.PairingCheck(
		[]bn254.G1Affine{publicKey, blsParams.G1Generator},
		[]bn254.G2Affine{hm, negSignature},
	)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %v", err)
	}
	return isValid, nil
}
