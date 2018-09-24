package encryptionSchemes

type EncryptionScheme interface {
	Encrypt(password string) (string, error)
	Compare(encryptedPassword, password string) bool
}

var defaultEncryptionScheme EncryptionScheme = New(10)
