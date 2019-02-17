package auth

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/globbie/gauth/pkg/auth/storage"
	"time"
)

type Claims struct {
	*jwt.StandardClaims
	Email string `json:"email,omitempty"`
}

func CreateToken(claims storage.Claims, signKey *rsa.PrivateKey) (string, error) {
	// todo: make signing method configurable
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims = &Claims{
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		},
		Email: claims.UserEmail,
	}
	return token.SignedString(signKey)
}
