package dabe

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func GlobalParamsToJson() {

}

func JsonToGlobalParams() {

}

func AttributePKToJson() {

}

func JsonToAttributePK() {

}

func AttributeSKToJson() {

}

func JsonToAttributeSK() {

}

func UserKeyToJson() {

}

func JsonToUserKey() {

}

func CiphertextToJson() {

}

func JsonToCiphertext() {

}

func KeyToMessage(key []byte) (*LW11DABEMessage, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key must be exactly 32 bytes")
	}
	var element bn254.GT
	err := element.SetBytes(key) // 严格检查：必须 < r，且是规范 32 字节表示
	if err != nil {
		return nil, err
	}
	return &LW11DABEMessage{
		Message: element,
	}, nil
}

func MessageToKey(message *LW11DABEMessage) ([]byte, error) {
	key := message.Message.Marshal()
	if len(key) != 32 {
		return nil, errors.New("AES-256 key must be exactly 32 bytes")
	}
	return key, nil
}
