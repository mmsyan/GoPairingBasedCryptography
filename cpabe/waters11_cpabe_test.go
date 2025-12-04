package cpabe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/lsss"
	"testing"
)

func TestWatersCPABE1(t *testing.T) {

	universe := []fr.Element{fr.NewElement(1), fr.NewElement(2), fr.NewElement(3), fr.NewElement(4)}

	instance, err := NewWaters11CPABEInstance(universe)
	if err != nil {
		t.Fatal(err)
	}

	pp, msk, err := instance.SetUp()
	if err != nil {
		t.Fatal(err)
	}

	accessTree1 := lsss.And(
		lsss.Leaf(fr.NewElement(1)),
		lsss.Leaf(fr.NewElement(2)),
		//lsss.Leaf(fr.NewElement(3)),
	)
	accessMatrix1 := lsss.NewLSSSMatrixFromTree(accessTree1)
	ap := &Waters11CPABEAccessPolicy{
		matrix: accessMatrix1,
	}

	userAttributes := []fr.Element{
		fr.NewElement(1), fr.NewElement(2),
	}
	ua := &Waters11CPABEAttributes{Attributes: userAttributes}
	usk, err := instance.KeyGenerate(ua, msk, pp)
	if err != nil {
		t.Fatal(err)
	}

	message, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(*message)
	m := &Waters11CPABEMessage{
		Message: *message,
	}

	ciphertext, err := instance.Encrypt(m, ap, pp)
	if err != nil {
		t.Fatal(err)
	}

	recoveredMessage, err := instance.Decrypt(ciphertext, usk, pp)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(recoveredMessage.Message)
}

func TestWatersCPABE2(t *testing.T) {

	universe := []fr.Element{fr.NewElement(1), fr.NewElement(2), fr.NewElement(3), fr.NewElement(4)}

	instance, err := NewWaters11CPABEInstance(universe)
	if err != nil {
		t.Fatal(err)
	}

	pp, msk, err := instance.SetUp()
	if err != nil {
		t.Fatal(err)
	}

	accessTree1 := lsss.And(
		lsss.Leaf(fr.NewElement(1)),
		lsss.Leaf(fr.NewElement(2)),
		lsss.Leaf(fr.NewElement(3)),
	)
	accessMatrix1 := lsss.NewLSSSMatrixFromTree(accessTree1)
	ap := &Waters11CPABEAccessPolicy{
		matrix: accessMatrix1,
	}

	userAttributes := []fr.Element{
		fr.NewElement(1), fr.NewElement(2),
	}
	ua := &Waters11CPABEAttributes{Attributes: userAttributes}
	usk, err := instance.KeyGenerate(ua, msk, pp)
	if err != nil {
		t.Fatal(err)
	}

	message, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(*message)
	m := &Waters11CPABEMessage{
		Message: *message,
	}

	ciphertext, err := instance.Encrypt(m, ap, pp)
	if err != nil {
		t.Fatal(err)
	}

	recoveredMessage, err := instance.Decrypt(ciphertext, usk, pp)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(recoveredMessage.Message)
}
