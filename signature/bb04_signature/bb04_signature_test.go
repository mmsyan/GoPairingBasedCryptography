package bb04_signature

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
	"testing"
)

// TestKeyGenerate tests the key generation function
func TestKeyGenerate(t *testing.T) {
	pk, sk, err := KeyGenerate()

	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	if pk == nil {
		t.Fatal("Public key is nil")
	}

	if sk == nil {
		t.Fatal("Private key is nil")
	}

	// Check that alpha and beta are not zero
	if sk.Alpha.IsZero() {
		t.Error("Alpha is zero")
	}

	if sk.Beta.IsZero() {
		t.Error("Beta is zero")
	}

	// Check that Y and Z are valid points
	if !pk.Y.IsInSubGroup() {
		t.Error("Y is not in the correct subgroup")
	}

	if !pk.Z.IsInSubGroup() {
		t.Error("Z is not in the correct subgroup")
	}
}

// TestKeyGenerateMultiple tests that multiple key generations produce different keys
func TestKeyGenerateMultiple(t *testing.T) {
	pk1, sk1, err1 := KeyGenerate()
	pk2, sk2, err2 := KeyGenerate()

	if err1 != nil || err2 != nil {
		t.Fatalf("KeyGenerate failed: %v, %v", err1, err2)
	}

	// Keys should be different
	if sk1.Alpha.Equal(&sk2.Alpha) {
		t.Error("Two key generations produced the same alpha")
	}

	if sk1.Beta.Equal(&sk2.Beta) {
		t.Error("Two key generations produced the same beta")
	}

	if pk1.Y.Equal(&pk2.Y) {
		t.Error("Two key generations produced the same Y")
	}
}

// TestSignBasic tests basic signing functionality
func TestSignBasic(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate failed: %v", err)
	}

	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	// Create a test message
	msg := &Message{}
	msg.MessageFr.SetUint64(42)

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if sig == nil {
		t.Fatal("Signature is nil")
	}

	// Check that r is not zero
	if sig.R.IsZero() {
		t.Error("Signature r component is zero")
	}

	// Check that sigma is a valid point
	if !sig.Sigma.IsInSubGroup() {
		t.Error("Sigma is not in the correct subgroup")
	}

	// Verify the signature
	valid, err := Verify(pk, msg, sig, pp)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("Valid signature failed verification")
	}
}

// TestSignVerifyZeroMessage tests signing and verifying a zero message
func TestSignVerifyZeroMessage(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate failed: %v", err)
	}

	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	msg := &Message{}
	msg.MessageFr.SetZero()

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	valid, err := Verify(pk, msg, sig, pp)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("Valid signature for zero message failed verification")
	}
}

// TestSignVerifyLargeMessage tests signing with a large message value
func TestSignVerifyLargeMessage(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate failed: %v", err)
	}

	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	msg := &Message{}
	bigVal := new(big.Int).SetBytes([]byte("large message value for testing"))
	msg.MessageFr.SetBigInt(bigVal)

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	valid, err := Verify(pk, msg, sig, pp)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !valid {
		t.Error("Valid signature for large message failed verification")
	}
}

// TestVerifyWrongMessage tests that verification fails with wrong message
func TestVerifyWrongMessage(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate failed: %v", err)
	}

	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	msg1 := &Message{}
	msg1.MessageFr.SetUint64(42)

	sig, err := Sign(sk, msg1)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Try to verify with a different message
	msg2 := &Message{}
	msg2.MessageFr.SetUint64(43)

	valid, err := Verify(pk, msg2, sig, pp)
	if valid {
		t.Error("Signature verified with wrong message")
	}
}

// TestVerifyWrongKey tests that verification fails with wrong public key
func TestVerifyWrongKey(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate failed: %v", err)
	}

	pk1, sk1, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	pk2, _, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	msg := &Message{}
	msg.MessageFr.SetUint64(42)

	sig, err := Sign(sk1, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with correct key should succeed
	valid, err := Verify(pk1, msg, sig, pp)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Signature failed verification with correct key")
	}

	// Verify with wrong key should fail
	valid, err = Verify(pk2, msg, sig, pp)
	if valid {
		t.Error("Signature verified with wrong public key")
	}
}

// TestMultipleSignatures tests that signing the same message twice produces different signatures
func TestMultipleSignatures(t *testing.T) {
	_, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	msg := &Message{}
	msg.MessageFr.SetUint64(42)

	sig1, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	sig2, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Signatures should be different due to random r
	if sig1.R.Equal(&sig2.R) {
		t.Error("Two signatures have the same r value")
	}

	if sig1.Sigma.Equal(&sig2.Sigma) {
		t.Error("Two signatures have the same sigma value")
	}
}

// TestSignVerifyMultipleMessages tests signing and verifying multiple different messages
func TestSignVerifyMultipleMessages(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate failed: %v", err)
	}
	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	messages := []uint64{1, 100, 999, 123456}

	for _, msgVal := range messages {
		msg := &Message{}
		msg.MessageFr.SetUint64(msgVal)

		sig, err := Sign(sk, msg)
		if err != nil {
			t.Fatalf("Sign failed for message %d: %v", msgVal, err)
		}

		valid, err := Verify(pk, msg, sig, pp)
		if err != nil {
			t.Fatalf("Verify failed for message %d: %v", msgVal, err)
		}

		if !valid {
			t.Errorf("Valid signature failed verification for message %d", msgVal)
		}
	}
}

// TestModifiedSignature tests that verification fails with modified signature
func TestModifiedSignature(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate failed: %v", err)
	}
	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	msg := &Message{}
	msg.MessageFr.SetUint64(42)

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Modify the r value
	modifiedSig := &Signature{
		R:     sig.R,
		Sigma: sig.Sigma,
	}
	modifiedSig.R.Add(&modifiedSig.R, new(fr.Element).SetOne())

	valid, err := Verify(pk, msg, modifiedSig, pp)
	//if err != nil {
	//	t.Fatalf("Verify failed: %v", err)
	//}

	if valid {
		t.Error("Modified signature passed verification")
	}
}

// BenchmarkKeyGenerate benchmarks key generation
func BenchmarkKeyGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = KeyGenerate()
	}
}

// BenchmarkSign benchmarks signature generation
func BenchmarkSign(b *testing.B) {
	_, sk, _ := KeyGenerate()
	msg := &Message{}
	msg.MessageFr.SetUint64(42)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(sk, msg)
	}
}

// BenchmarkVerify benchmarks signature verification
func BenchmarkVerify(b *testing.B) {
	pp, _ := ParamsGenerate()
	pk, sk, _ := KeyGenerate()
	msg := &Message{}
	msg.MessageFr.SetUint64(42)
	sig, _ := Sign(sk, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(pk, msg, sig, pp)
	}
}
