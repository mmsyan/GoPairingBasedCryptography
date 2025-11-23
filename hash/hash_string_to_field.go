package hash

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func HashStringToFidld(str string) fr.Element {
	// 创建 SHA-256 哈希器
	sha256 := sha256.New()
	sha256.Write([]byte(str))
	hashBytes := sha256.Sum(nil)

	// 将哈希值转换为有限域元素
	var result fr.Element
	result.SetBytes(hashBytes)
	return result
}
