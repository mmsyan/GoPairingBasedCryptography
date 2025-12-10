package bsw07

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func Hash1BSw07(attr fr.Element) bn254.G1Affine {
	//sha256 := sha256.New()
	//attrBytes := attr.Bytes()
	//sha256.Write(attrBytes[:])
	//hashBytes := sha256.Sum(nil)
	//
	//var result bn254.G1Affine
	//result.SetBytes(hashBytes)
	//return result
	_, _, g1, _ := bn254.Generators()
	return g1
}

func Hash2BSw07(attr fr.Element) bn254.G2Affine {
	//sha256 := sha256.New()
	//attrBytes := attr.Bytes()
	//sha256.Write(attrBytes[:])
	//hashBytes := sha256.Sum(nil)
	//
	//var result bn254.G2Affine
	//result.SetBytes(hashBytes)
	//return result
	_, _, _, g2 := bn254.Generators()
	return g2
}
