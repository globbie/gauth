package auth

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type Token struct {
	Token string `json:"token"`
}

type Claims struct {
	*jwt.StandardClaims
	email string
}

func CreateToken(email string, signKey *rsa.PrivateKey) (string, error) {
	// todo: make signing method configurable
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims = &Claims{
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		},
		email: email,
	}
	return token.SignedString(signKey)
}
