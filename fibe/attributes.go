package fibe

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// SW05FIBEAttributes represents a set of attributes used in the SW05 FIBE scheme.
//
// It encapsulates an ordered list of attributes as elements in the finite field
// fr.Element (BN254 scalar field). The attributes are typically used either as
// the policy set in ciphertexts or as the attribute set embedded in private keys.
//
// The underlying slice is immutable from the outside after construction.
type SW05FIBEAttributes struct {
	attributes []fr.Element // 属性集合 S，一个有序的有限域元素列表
}

// NewFIBEAttributes creates a new SW05FIBEAttributes instance from a list of int64 values.
//
// This is the recommended way to construct an attribute set. Each int64 value is
// converted to a canonical fr.Element representation in the BN254 scalar field.
//
// This function performs a defensive copy and canonical reduction, ensuring that
// the resulting fr.Element values are normalized and safe for cryptographic use.
//
// Parameters:
//
//	attributes - the list of attribute values as int64 slice
//
// Returns:
//
//	a pointer to a fully initialized SW05FIBEAttributes instance
//
// Example:
//
//	attrs := fibe.NewFIBEAttributes([]int64{1, 2, 5, 8})
//	// attrs now contains the corresponding fr.Element values
func NewFIBEAttributes(attributes []int64) *SW05FIBEAttributes {
	result := make([]fr.Element, len(attributes))
	for i, a := range attributes {
		// SetInt64 returns *fr.Element, so we must dereference then copy
		result[i] = *new(fr.Element).SetInt64(a)
	}
	return &SW05FIBEAttributes{
		attributes: result,
	}
}
