package bsw07

type CPABEInstance struct {
}

type CPABEPublicParameters struct{}

type CPABEMasterSecretKey struct{}

type CPABEUserAttributes struct{}

type CPABEUserSecretKey struct{}

type CPABEMessage struct{}

type CPABEAccessPolicy struct{}

type CPABECiphertext struct{}

func (instance *CPABEInstance) SetUp() (*CPABEPublicParameters, *CPABEMasterSecretKey, error) {}

func (instance *CPABEInstance) KeyGenerate(attr *CPABEUserAttributes, msk *CPABEMasterSecretKey, pp *CPABEPublicParameters) (*CPABEUserSecretKey, error) {
}

func (instance *CPABEInstance) Encrypt(message *CPABEMessage, accessPolicy *CPABEAccessPolicy, pp *CPABEPublicParameters) (*CPABECiphertext, error) {
}

func (instance *CPABEInstance) Decrypt(ciphertext *CPABECiphertext, usk *CPABEUserSecretKey) (*CPABEMessage, error) {
}

func (instance *CPABEInstance) Delegate(usk *CPABEUserSecretKey, subsetAttr *CPABEUserAttributes) (*CPABEUserSecretKey, error) {
}
