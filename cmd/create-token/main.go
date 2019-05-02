package main

import (
	"crypto/rsa"
	"flag"
	"github.com/dgrijalva/jwt-go"
	"github.com/globbie/gauth/pkg/auth"
	"github.com/globbie/gauth/pkg/auth/storage"
	"io/ioutil"
	"log"
)

func main() {
	var (
		signKeyPath string
		signKey *rsa.PrivateKey

		userEmail string
	)
	flag.StringVar(&signKeyPath, "sign-key-path", "cmd/server/example.rsa", "path to the private rsa key")
	flag.StringVar(&userEmail, "email", "john@example.com", "user email")

	signKeyBytes, err := ioutil.ReadFile(signKeyPath)
	if err != nil {
		log.Fatalln("failed to open sing key, error:", err)
	}
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signKeyBytes)
	if err != nil {
		log.Fatalln("failed to parse private key, error:", err)
	}

	claims := storage.Claims{
		UserEmail: userEmail,
	}

	token, err := auth.CreateToken(claims, signKey)
	if err != nil {
		log.Fatalln("failed to create token, error:", err)
	}

	log.Println(token)
}