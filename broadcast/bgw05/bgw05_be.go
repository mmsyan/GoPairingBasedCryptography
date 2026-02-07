package bgw05

type MasterPublicKey struct {
}

type MasterSecretKey struct {
}

type UserIdentity struct {
}

type UserSecretKey struct {
}

type Message struct {
}

type Ciphertext struct {
}

func Setup(n int) (*MasterPublicKey, *MasterSecretKey, error) {

}

func Extract(i *UserIdentity, msk *MasterSecretKey) (*UserSecretKey, error) {

}

func Encrypt(s []*UserIdentity, mpk *MasterPublicKey, m *Message) (*Ciphertext, error) {}

func Decrypt(i *UserIdentity, sk *UserSecretKey, s []*UserIdentity, mpk *MasterPublicKey, c *Ciphertext) (*Message, error) {

}
