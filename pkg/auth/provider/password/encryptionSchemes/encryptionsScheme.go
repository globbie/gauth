package encryptionSchemes

type EncryptionScheme interface {
	Encrypt(password string) (string, error)
	Compare(encryptedPassword, password string) bool
	ToString() string
}

var DefaultEncryptionScheme EncryptionScheme = New(10)
