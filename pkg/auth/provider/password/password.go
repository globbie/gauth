package password

import (
	"encoding/json"
	"errors"
	"github.com/globbie/gnode/pkg/auth"
	"github.com/globbie/gnode/pkg/auth/ctx"
	"github.com/globbie/gnode/pkg/auth/provider"
	"github.com/globbie/gnode/pkg/auth/provider/password/encryptionSchemes"
	"github.com/globbie/gnode/pkg/auth/storage"
	"log"
	"net/http"
	"strings"
)

// todo: use provider name
const providerID = "password-provider"

type Config struct {
}

func (c *Config) New(s storage.Storage) (provider.IdentityProvider, error) {
	return NewProvider(s), nil
}

type Credentials struct {
	Login             string                             `json:"login"`
	EncryptedPassword string                             `json:"encrypted-password"`
	EncryptionScheme  encryptionSchemes.EncryptionScheme `json:"encryption-scheme"`
}

func (c Credentials) UID() string {
	return c.Login
}

type Provider struct {
	storage storage.Storage
}

func NewProvider(s storage.Storage) *Provider {
	p := Provider{storage: s}
	err := s.ProviderCreate(providerID)
	if err != nil {
		log.Panicln("could not register p, error:", err)
	}
	return &p
}

// todo: login & password validation
func getCredentials(c *ctx.Ctx) (login string, password string, err error) {
	err = c.R.ParseForm()
	if err != nil {
		http.Error(c.W, "internal server error", http.StatusInternalServerError)
		return
	}
	login = c.R.Form.Get("login")
	password = strings.TrimSpace(c.R.Form.Get("password"))
	if login == "" {
		err = errors.New("login is not set")
		http.Error(c.W, "login is not set", http.StatusBadRequest)
		return
	}
	if password == "" {
		err = errors.New("password is not set")
		http.Error(c.W, "password is not set", http.StatusBadRequest)
		return
	}
	return
}

func (p *Provider) Login(c *ctx.Ctx) {
	login, password, err := getCredentials(c)
	if err != nil {
		// todo: all http errors should be set here
		return
	}
	creds, err := p.storage.UserRead(providerID, login)
	if err == storage.ErrNotFound {
		http.Error(c.W, "user not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(c.W, "internal server error", http.StatusInternalServerError)
		return
	}
	credentials := creds.(*Credentials)
	passwordMatches := encryptionSchemes.DefaultEncryptionScheme.Compare(credentials.EncryptedPassword, password)
	if !passwordMatches {
		http.Error(c.W, "invalid login or password", http.StatusBadRequest)
		return
	}
	token, err := auth.CreateToken(login, c.SignKey)
	if err != nil {
		log.Println("failed to create token", err)
		http.Error(c.W, "internal error", http.StatusInternalServerError)
		return
	}
	response, err := json.Marshal(auth.Token{Token: token})
	if err != nil {
		log.Print("failed to marshal json:", err)
		http.Error(c.W, "internal server error", http.StatusInternalServerError)
		return
	}
	c.W.WriteHeader(http.StatusOK)
	c.W.Header().Set("Content-Type", "application/json")
	c.W.Write(response)
}

func (p *Provider) Logout(ctx *ctx.Ctx) {
	// nothing to do here
}

func (p *Provider) Register(c *ctx.Ctx) {
	err := c.R.ParseForm()
	if err != nil {
		http.Error(c.W, "internal server error", http.StatusInternalServerError)
	}
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
	authInfo := Credentials{
		Login:             email,
		EncryptedPassword: encryptedPassword,
		EncryptionScheme:  encryptionSchemes.DefaultEncryptionScheme,
	}
	err = p.storage.UserCreate(providerID, &authInfo)
	if err != nil {
		// todo
		http.Error(c.W, "could not create user", http.StatusBadRequest)
		return
	}
	token, err := auth.CreateToken(email, c.SignKey)
	if err != nil {
		log.Println("failed to create token", err)
		http.Error(c.W, "internal error", http.StatusInternalServerError)
		return
	}
	response, err := json.Marshal(auth.Token{Token: token})
	if err != nil {
		log.Print("failed to marshal json:", err)
		http.Error(c.W, "internal server error", http.StatusInternalServerError)
		return
	}
	c.W.WriteHeader(http.StatusOK)
	c.W.Header().Set("Content-Type", "application/json")
	c.W.Write(response)
}

func (p *Provider) Callback(ctx *ctx.Ctx) {
}
