package password

import (
	"errors"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/provider/password/encryptionSchemes"
	"github.com/globbie/gauth/pkg/auth/storage"
	"log"
	"net/http"
	"strings"
)

const ProviderType = "password"

type Config struct {
}

func (c *Config) New(s storage.Storage, id string) (provider.IdentityProvider, error) {
	p := Provider{
		storage: s,
		id:      id,
	}
	err := s.ProviderCreate(id)
	if err != nil {
		log.Panicf("could not register provider %v:%v, error: %v", ProviderType, id, err)
	}
	return &p, nil
}

type Provider struct {
	storage storage.Storage
	id      string
}

func (p *Provider) Type() string {
	return ProviderType
}

// todo: login & password validation
// todo: error handling
func getCredentials(w http.ResponseWriter, r *http.Request) (login string, password string, err error) {
	err = r.ParseForm()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	login = r.Form.Get("login")
	password = strings.TrimSpace(r.Form.Get("password"))
	if login == "" {
		err = errors.New("login is not set")
		http.Error(w, "login is not set", http.StatusBadRequest)
		return
	}
	if password == "" {
		err = errors.New("password is not set")
		http.Error(w, "password is not set", http.StatusBadRequest)
		return
	}
	return
}

func (p *Provider) Login(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	login, password, err := getCredentials(w, r)
	if err != nil {
		// todo: all http errors should be set here
		return
	}
	creds, err := p.storage.UserRead(p.id, login)
	if err == storage.ErrNotFound {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	credentials := creds.(*Credentials)
	passwordMatches := encryptionSchemes.DefaultEncryptionScheme.Compare(credentials.EncryptedPassword, password)
	if !passwordMatches {
		http.Error(w, "invalid login or password", http.StatusBadRequest)
		return
	}

	response := []byte("to be done")
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (p *Provider) Logout(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	// nothing to do here
}

func (p *Provider) Register(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
	email := strings.TrimSpace(r.Form.Get("login"))
	password := strings.TrimSpace(r.Form.Get("password"))
	if email == "" {
		log.Println("login is not set")
		http.Error(w, "login is not set", http.StatusBadRequest)
		return
	}
	if password == "" {
		log.Println("password is not set")
		http.Error(w, "password is not set", http.StatusBadRequest)
		return
	}
	encryptedPassword, err := encryptionSchemes.DefaultEncryptionScheme.Encrypt(password)
	if err != nil {
		log.Println("failed to encrypt password:", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	authInfo := Credentials{
		Login:             email,
		EncryptedPassword: encryptedPassword,
		EncryptionScheme:  encryptionSchemes.DefaultEncryptionScheme,
	}
	err = p.storage.UserCreate(p.id, &authInfo)
	if err != nil {
		// todo
		http.Error(w, "could not create user", http.StatusBadRequest)
		return
	}

	response := []byte("to be done")
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (p *Provider) Callback(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) error {
	return nil
}

type Credentials struct {
	Login             string                             `json:"login"`
	EncryptedPassword string                             `json:"encrypted-password"`
	EncryptionScheme  encryptionSchemes.EncryptionScheme `json:"encryption-scheme"`
}

func (c Credentials) UID() string {
	return c.Login
}
