package agka09

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type PublicKey struct {
	R bn254.G2Affine
	A bn254.GT
}

type PrivateKey struct {
	R fr.Element
	X bn254.G1Affine
}

type Message struct {
	S []byte
}

type Signature struct {
	Sigma bn254.G1Affine
}

type PlainText struct {
	M bn254.GT
}

type CipherText struct {
	C1 bn254.G2Affine
	C2 bn254.G2Affine
	C3 bn254.GT
}

func KeyGen() {

}

func Sign() {

}

func Verify() {

}

func Encrypt() {

}

func Decrypt() {

}
