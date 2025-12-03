package cpabe

type Waters11CPABEInstance struct {
}

type Waters11CPABEPublicParameters struct {
}

type Waters11CPABEAttributes struct{}

type Waters11CPABESecretKey struct{}

type Waters11CPABEAccessPolicy struct{}

type Waters11CPABEMessage struct{}

type Waters11CPABECiphertext struct{}

func NewWaters11CPABEInstance() (*Waters11CPABEInstance, error) {

}

func (instance *Waters11CPABEInstance) SetUp() {}

func (instance *Waters11CPABEInstance) KeyGenerate(userAttributes *Waters11CPABEAttributes, gp *Waters11CPABEPublicParameters) (*Waters11CPABESecretKey, error) {
}

func (instance *Waters11CPABEInstance) Encrypt(message *Waters11CPABEMessage, accessPolicy *Waters11CPABEAccessPolicy, gp *Waters11CPABEPublicParameters) (*Waters11CPABECiphertext, error) {
}

func (instance *Waters11CPABEInstance) Decrypt(ciphertext *Waters11CPABECiphertext, secretKey *Waters11CPABESecretKey, gp *Waters11CPABEPublicParameters) (*Waters11CPABEMessage, error) {
}
