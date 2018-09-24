package password

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/globbie/gnode/pkg/auth/ctx"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

type Credentials struct {
	Email             string
	EncryptedPassword []byte
	//EncryptionScheme EncryptionScheme
}

type Token struct {
	Token string `json:"token"`
}

type Claims struct {
	*jwt.StandardClaims
	email string
}

type Provider struct {
}

func NewProvider() *Provider {
	return &Provider{}
}

func (p *Provider) Login(ctx *ctx.Ctx) {
	// todo: get user credentials from knowdy
	// todo: compare credentials
	// todo: give user a new jwt
}

func (p *Provider) Logout(ctx *ctx.Ctx) {
	// nothing to do here
}

func (p *Provider) Register(ctx *ctx.Ctx) {
	authInfo := &Credentials{}

	email := ctx.R.URL.Query().Get("email")
	if email == "" {
		http.Error(ctx.W, "email is not set", http.StatusBadRequest)
		return
	}
	password := ctx.R.URL.Query().Get("password")
	if password == "" {
		http.Error(ctx.W, "password is not set", http.StatusBadRequest)
		return
	}
	// todo: use encryption scheme
	encryptedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	authInfo.Email = email
	authInfo.EncryptedPassword = encryptedPassword

	token, err := createToken(email, ctx.SignKey)
	if err != nil {
		log.Println("failed to create token", err)
		http.Error(ctx.W, "internal error", http.StatusInternalServerError)
		return
	}

	//users[email] = authInfo
	// todo: create gsl user struct and validate it with knowdy

	response, err := json.Marshal(Token{token})
	if err != nil {
		http.Error(ctx.W, "intertal server error", http.StatusInternalServerError)
		return
	}
	ctx.W.WriteHeader(http.StatusOK)
	ctx.W.Header().Set("Content-Type", "application/json")
	ctx.W.Write(response)
}

func createToken(email string, signKey *rsa.PrivateKey) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims = &Claims{
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		},
		email,
	}
	return token.SignedString(signKey)
}
