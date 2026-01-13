package gwww25_bibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
	"testing"
)

// Helper function: create a new identity
func NewIdentity(id int64) *Identity {
	elem := new(fr.Element).SetInt64(id)
	return &Identity{
		Id: *elem,
	}
}

// Helper function: create a new batch label
func NewBatchLabel(tg int64) *BatchLabel {
	elem := new(fr.Element).SetInt64(tg)
	return &BatchLabel{
		Tg: *elem,
	}
}

// Helper function: generate a random message
func RandomMessage() (*Message, error) {
	msg := new(bn254.GT).SetOne()
	randomScalar, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}
	msg.Exp(*msg, randomScalar.BigInt(new(big.Int)))
	return &Message{M: *msg}, nil
}

func TestSetup(t *testing.T) {
	tests := []struct {
		name    string
		B       int
		wantErr bool
	}{
		{"Valid batch size 10", 10, false},
		{"Valid batch size 1", 1, false},
		{"Valid batch size 100", 100, false},
		{"Invalid batch size 0", 0, true},
		{"Invalid batch size -1", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := Setup(tt.B)
			if (err != nil) != tt.wantErr {
				t.Errorf("Setup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && params.B != tt.B {
				t.Errorf("Setup() B = %v, want %v", params.B, tt.B)
			}
		})
	}
}

func TestKeyGen(t *testing.T) {
	params, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Check that master public key components are non-nil
	if mpk == nil {
		t.Fatal("Master public key is nil")
	}
	if msk == nil {
		t.Fatal("Master secret key is nil")
	}

	// Check that G2ExpTauPowers has correct length
	if len(mpk.G2ExpTauPowers) != params.B {
		t.Errorf("G2ExpTauPowers length = %v, want %v", len(mpk.G2ExpTauPowers), params.B)
	}

	// Check that G1 points are not infinity
	if mpk.G1ExpTau.IsInfinity() {
		t.Error("G1ExpTau is infinity")
	}
	if mpk.G1ExpW.IsInfinity() {
		t.Error("G1ExpW is infinity")
	}
	if mpk.G1ExpWTau.IsInfinity() {
		t.Error("G1ExpWTau is infinity")
	}
}

func TestEncryptDecrypt_SingleIdentity(t *testing.T) {
	// Setup
	params, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Create identity and batch label
	id := NewIdentity(42)
	batchLabel := NewBatchLabel(7)
	identities := []*Identity{id}

	// Generate digest
	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	// Compute key
	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}

	// Create and encrypt message
	originalMsg, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}

	ct, err := Encrypt(mpk, originalMsg, id, batchLabel)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	decryptedMsg, err := Decrypt(mpk, sk, identities, id, batchLabel, ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify decryption
	if !originalMsg.M.Equal(&decryptedMsg.M) {
		t.Error("Decrypted message does not match original message")
	}
}

func TestEncryptDecrypt_MultipleIdentities1(t *testing.T) {
	// Setup
	params, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Create multiple identities
	batchLabel := NewBatchLabel(500)
	id1 := NewIdentity(1)
	id2 := NewIdentity(2)
	id3 := NewIdentity(3)
	id4 := NewIdentity(4)
	id5 := NewIdentity(5)
	identities := []*Identity{
		id1, id2, id3, id4, id5,
	}

	// Generate digest for all identities
	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	// Compute key
	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}

	// Create and encrypt message
	originalMsg, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}

	ct, err := Encrypt(mpk, originalMsg, id1, batchLabel)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	decryptedMsg, err := Decrypt(mpk, sk, identities, id1, batchLabel, ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify decryption
	if !originalMsg.M.Equal(&decryptedMsg.M) {
		t.Error("Decrypted message does not match original message")
	}
}

func TestEncryptDecrypt_MultipleIdentities2(t *testing.T) {
	// Setup
	params, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Create multiple identities
	batchLabel := NewBatchLabel(5)
	identities := []*Identity{
		NewIdentity(1),
		NewIdentity(2),
		NewIdentity(3),
		NewIdentity(4),
		NewIdentity(5),
	}

	// Generate digest for all identities
	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	// Compute key
	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}

	// Test encryption/decryption for each identity
	for i, id := range identities {
		t.Run(fmt.Sprintf("Identity_%d", i+1), func(t *testing.T) {
			// Create and encrypt message
			originalMsg, err := RandomMessage()
			if err != nil {
				t.Fatalf("RandomMessage failed: %v", err)
			}

			ct, err := Encrypt(mpk, originalMsg, id, batchLabel)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Decrypt
			decryptedMsg, err := Decrypt(mpk, sk, identities, id, batchLabel, ct)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Verify decryption
			if !originalMsg.M.Equal(&decryptedMsg.M) {
				t.Error("Decrypted message does not match original message")
			}
		})
	}
}

func TestDigest_EmptyIdentities(t *testing.T) {
	params, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, _, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Test with empty identities slice
	_, err = Digest(mpk, []*Identity{})
	if err == nil {
		t.Error("Expected error for empty identities, got nil")
	}
}

func TestDecrypt_IdentityNotInList(t *testing.T) {
	// Setup
	params, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Create identities for batch
	batchLabel := NewBatchLabel(5)
	identities := []*Identity{
		NewIdentity(1),
		NewIdentity(2),
		NewIdentity(3),
	}

	// Generate digest
	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	// Compute key
	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}

	// Try to decrypt for identity not in the list
	idNotInList := NewIdentity(99)
	originalMsg, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}

	ct, err := Encrypt(mpk, originalMsg, idNotInList, batchLabel)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// This should fail
	_, err = Decrypt(mpk, sk, identities, idNotInList, batchLabel, ct)
	if err == nil {
		t.Error("Expected error when decrypting for identity not in list, got nil")
	}
	fmt.Println(err)
}

func TestEncryptDecrypt_DifferentBatchLabels(t *testing.T) {
	// Setup
	params, err := Setup(10)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Create identity
	id := NewIdentity(42)
	identities := []*Identity{id}

	// Use different batch labels for key generation and encryption
	batchLabel1 := NewBatchLabel(7)
	batchLabel2 := NewBatchLabel(13)

	// Generate digest
	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	// Compute key with batchLabel1
	sk, err := ComputeKey(msk, digest, batchLabel1)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}

	// Encrypt with batchLabel2
	originalMsg, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}

	ct, err := Encrypt(mpk, originalMsg, id, batchLabel2)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt (should fail or produce wrong result)
	decryptedMsg, err := Decrypt(mpk, sk, identities, id, batchLabel2, ct)
	if err != nil {
		// Error is acceptable
		t.Logf("Decrypt failed as expected with different batch labels: %v", err)
		return
	}

	// If no error, the decrypted message should NOT match
	if originalMsg.M.Equal(&decryptedMsg.M) {
		t.Error("Decryption succeeded with mismatched batch labels, which should not happen")
	}
}

func TestComputePolynomialCoeffs(t *testing.T) {
	// Test with simple identities
	identities := []*Identity{
		NewIdentity(1),
		NewIdentity(2),
	}

	coeffs := computePolynomialCoeffs(identities)

	// For (x-1)(x-2) = x^2 - 3x + 2
	// coeffs should be [2, -3, 1]
	if len(coeffs) != 3 {
		t.Errorf("Expected 3 coefficients, got %d", len(coeffs))
	}

	expected2 := new(fr.Element).SetInt64(2)
	expectedNeg3 := new(fr.Element).SetInt64(-3)
	expected1 := new(fr.Element).SetInt64(1)

	if !coeffs[0].Equal(expected2) {
		t.Errorf("coeffs[0] = %v, want 2", coeffs[0].String())
	}
	if !coeffs[1].Equal(expectedNeg3) {
		t.Errorf("coeffs[1] = %v, want -3", coeffs[1].String())
	}
	if !coeffs[2].Equal(expected1) {
		t.Errorf("coeffs[2] = %v, want 1", coeffs[2].String())
	}
}

func BenchmarkKeyGen(b *testing.B) {
	params, _ := Setup(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = KeyGen(params)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	params, _ := Setup(10)
	mpk, _, _ := KeyGen(params)
	id := NewIdentity(42)
	batchLabel := NewBatchLabel(7)
	msg, _ := RandomMessage()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(mpk, msg, id, batchLabel)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	params, _ := Setup(10)
	mpk, msk, _ := KeyGen(params)
	id := NewIdentity(42)
	batchLabel := NewBatchLabel(7)
	identities := []*Identity{id}

	digest, _ := Digest(mpk, identities)
	sk, _ := ComputeKey(msk, digest, batchLabel)
	msg, _ := RandomMessage()
	ct, _ := Encrypt(mpk, msg, id, batchLabel)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt(mpk, sk, identities, id, batchLabel, ct)
	}
}
