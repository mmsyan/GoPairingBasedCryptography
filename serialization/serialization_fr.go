package serialization

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func MarshalFr(element fr.Element) []byte {
	return element.Marshal()
}

func UnmarshalFr(data []byte) fr.Element {
	var element fr.Element
	element.Unmarshal(data)
	return element
}

func FrToAes256Key(element fr.Element) []byte {
	return element.Marshal()
}

func Aes256KeyToFr(key []byte) (fr.Element, error) {
	if len(key) != 32 {
		return fr.Element{}, errors.New("AES-256 key must be exactly 32 bytes")
	}
	var element fr.Element
	err := element.SetBytesCanonical(key) // 严格检查：必须 < r，且是规范 32 字节表示
	if err != nil {
		return fr.Element{}, err
	}
	return element, nil
}
