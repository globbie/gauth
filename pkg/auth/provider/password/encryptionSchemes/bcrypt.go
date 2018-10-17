package encryptionSchemes

import "golang.org/x/crypto/bcrypt"

type bcryptScheme struct {
	cost int
}

func New(cost int) *bcryptScheme {
	if cost <= 0 {
		cost = bcrypt.DefaultCost
	}
	return &bcryptScheme{
		cost: cost,
	}
}

func (e *bcryptScheme) Encrypt(password string) (string, error) {
	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), e.cost)
	return string(encryptedPassword), err
}

func (e *bcryptScheme) Compare(encryptedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(encryptedPassword), []byte(password))
	if err != nil {
		return false
	}
	return true
}

func (e *bcryptScheme) ToString() string {
	return ""
}
