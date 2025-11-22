package fibe

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// SW05FIBEAttributes 封装了用户的属性集或密文的属性集。
type SW05FIBEAttributes struct {
	attributes []fr.Element // 属性集合 S，一个整数数组。
}

// NewFIBEAttributes 创建一个新的 SW05FIBEAttributes 结构体实例。
//
// 参数:
//   - attributes: 属性列表。
//
// 返回值:
//   - *SW05FIBEAttributes: 属性结构体指针。
func NewFIBEAttributes(attributes []int64) *SW05FIBEAttributes {
	result := make([]fr.Element, len(attributes))
	for i, a := range attributes {
		result[i] = *new(fr.Element).SetInt64(a)
	}
	return &SW05FIBEAttributes{
		attributes: result,
	}
}
