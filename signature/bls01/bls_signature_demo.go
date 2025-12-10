package bls01

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func main() {
	// (1) Set Up
	q := ecc.BN254.ScalarField()
	_, _, g1, _ := bn254.Generators()

	// (2) PrivateKey Generation
	x, err := rand.Int(rand.Reader, q) // secret key: x <- Zq
	if err != nil {
		panic(err)
	}
	var gx bn254.G1Affine
	gx.ScalarMultiplication(&g1, x) // public key: G1Generator^x = G1Generator^x in G1Generator

	// (3) SigmaSignature
	message := []byte("Hello, I am a message for signature signing.")
	messagePointG2, err := bn254.HashToG2(message, []byte("signature SigmaSignature")) // compute h(m) in G2
	if err != nil {
		panic(err)
	}
	var sigmaG2 bn254.G2Affine
	sigmaG2.ScalarMultiplication(&messagePointG2, x) // compute sigma = h(m)^x in G2

	// (4) Verification
	// 要验证：e(G1Generator^x, h(m)) == e(G1Generator, sigma)
	// 等价于：e(G1Generator^x, h(m)) * e(G1Generator, -sigma) == 1
	var negSigmaG2 bn254.G2Affine
	negSigmaG2.Neg(&sigmaG2)
	isValid, err := bn254.PairingCheck(
		[]bn254.G1Affine{gx, g1},
		[]bn254.G2Affine{messagePointG2, negSigmaG2},
	)
	if err != nil {
		panic(err)
	}
	if isValid {
		fmt.Println("SigmaSignature verification successful!")
	} else {
		fmt.Println("SigmaSignature verification failed!")
	}
}
