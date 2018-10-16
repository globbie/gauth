package password

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/globbie/gnode/pkg/auth/ctx"
	"github.com/globbie/gnode/pkg/auth/provider/password/encryptionSchemes"
	"github.com/globbie/gnode/pkg/auth/storage"
	"log"
	"net/http"
	"strings"
	"time"
)

type Token struct {
	Token string `json:"token"`
}

type Claims struct {
	*jwt.StandardClaims
	email string
}

type Provider struct {
	storage storage.Storage
}

func NewProvider(s storage.Storage) *Provider {
	return &Provider{storage: s}
}

func (p *Provider) Login(ctx *ctx.Ctx) {
	// todo: get user credentials from knowdy
	// todo: compare credentials
	// todo: give user a new jwt
}

func (p *Provider) Logout(ctx *ctx.Ctx) {
	// nothing to do here
}

func (p *Provider) Register(c *ctx.Ctx) {
	authInfo := &storage.UserCredentials{}

	log.Println("3", c.R)
	err := c.R.ParseForm()
	if err != nil {
		http.Error(c.W, "internal server error", http.StatusInternalServerError)
	}
	log.Println("4", c.R.Form)


	email := strings.TrimSpace(c.R.Form.Get("login"))
	password := strings.TrimSpace(c.R.Form.Get("password"))

	if email == "" {
		log.Println("login is not set")
		http.Error(c.W, "login is not set", http.StatusBadRequest)
		return
	}
	if password == "" {
		log.Println("password is not set")
		http.Error(c.W, "password is not set", http.StatusBadRequest)
		return
	}
	encryptedPassword, err := encryptionSchemes.DefaultEncryptionScheme.Encrypt(password)
	if err != nil {
		log.Println("failed to encrypt password:", err)
		http.Error(c.W, "internal server error", http.StatusInternalServerError)
		return
	}
	authInfo.UID = email
	authInfo.EncryptedPassword = encryptedPassword
	authInfo.EncryptionScheme = encryptionSchemes.DefaultEncryptionScheme

	// 1. try to create user in storage
	// 2. get reply from storage
	// 3. create JWT

	token, err := createToken(email, c.SignKey)
	if err != nil {
		log.Println("failed to create token", err)
		http.Error(c.W, "internal error", http.StatusInternalServerError)
		return
	}
	response, err := json.Marshal(Token{token})
	if err != nil {
		log.Print("failed to marshal json:", err)
		http.Error(c.W, "internal server error", http.StatusInternalServerError)
		return
	}
	c.W.WriteHeader(http.StatusOK)
	c.W.Header().Set("Content-Type", "application/json")
	c.W.Write(response)
}

func createToken(email string, signKey *rsa.PrivateKey) (string, error) {
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
