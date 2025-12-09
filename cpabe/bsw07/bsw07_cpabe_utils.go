package bsw07

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func Hash1BSw07(attr fr.Element) bn254.G1Affine {
	sha256 := sha256.New()
	attrBytes := attr.Bytes()
	sha256.Write(attrBytes[:])
	hashBytes := sha256.Sum(nil)

	var result bn254.G1Affine
	result.SetBytes(hashBytes)
	return result
}

func Hash2BSw07(attr fr.Element) bn254.G2Affine {
	sha256 := sha256.New()
	attrBytes := attr.Bytes()
	sha256.Write(attrBytes[:])
	hashBytes := sha256.Sum(nil)

	var result bn254.G2Affine
	result.SetBytes(hashBytes)
	return result
}
