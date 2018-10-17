package password

import "github.com/globbie/gnode/pkg/auth/provider/password/encryptionSchemes"

type Credentials struct {
	Login             string                             `json:"login"`
	EncryptedPassword string                             `json:"encrypted-password"`
	EncryptionSchema  encryptionSchemes.EncryptionScheme `json:"encryption-scheme"`
}
