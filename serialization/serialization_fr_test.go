package serialization

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"testing"
)

func TestSerialization(t *testing.T) {

	keyElement, err := new(fr.Element).SetRandom()
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := MarshalFr(*keyElement)
	recoveredKeyElement := UnmarshalFr(keyBytes)

	fmt.Println(*keyElement)
	fmt.Println(recoveredKeyElement)
	if !recoveredKeyElement.Equal(keyElement) {
		t.Errorf("serialization fail")
	}
}

func TestAes256KeyToFr_InvalidLength(t *testing.T) {
	badLengths := [][]byte{
		nil,
		{},
		make([]byte, 31),
		make([]byte, 33),
		[]byte("too short"),
	}

	for _, bad := range badLengths {
		_, err := Aes256KeyToFr(bad)
		if err == nil || err.Error() != "AES-256 key must be exactly 32 bytes" {
			t.Errorf("expected length error for len=%d, got: %v", len(bad), err)
		}
	}
}

func TestAes256KeyToFr_AllZeroBytes_Accepted(t *testing.T) {
	// 全 0 是合法的（对应标量 0）
	var zeroKey [32]byte
	elem, err := Aes256KeyToFr(zeroKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if !elem.IsZero() {
		t.Error("all-zero bytes should map to fr.Element zero")
	}
}
