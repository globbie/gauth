package auth

import (
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/globbie/gnode/pkg/auth/provider"
	"github.com/globbie/gnode/pkg/auth/storage"
	"log"
	"net/http"
	"net/url"
)

type Auth struct {
	URLPrefix string

	idProviders     map[string]provider.IdentityProvider

	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey
}

// todo: delete this factory
func New(verifyKey *rsa.PublicKey, signKey *rsa.PrivateKey, storage storage.Storage) *Auth {
	auth := &Auth{
		idProviders: make(map[string]provider.IdentityProvider),
		VerifyKey:   verifyKey,
		SignKey:     signKey,
	}
	return auth
}

func (a *Auth) NewServeMux() http.Handler {
	return &serveMux{a}
}

func (a *Auth) GetIdentityProvider(name string) (provider.IdentityProvider, error) {
	p, ok := a.idProviders[name]
	if !ok {
		return nil, errors.New("p not found")
	}
	return p, nil
}

func (a *Auth) AddIdentityProvider(name string, provider provider.IdentityProvider) {
	_, ok := a.idProviders[name]
	if ok {
		log.Fatalf("provider %v is already registered", name)
	}
	a.idProviders[name] = provider
}

func (a *Auth) AuthorizationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
		}

		redirectURI, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
		}
		clientID := r.Form.Get("client_id")
		state := r.Form.Get("state")
		responseType := r.Form.Get("response_type")
		clientSecret := r.Form.Get("client_secret")

		_ = redirectURI
		_ = clientID
		_ = state
		_ = responseType
		_ = clientSecret
	})
}

// todo: change handler name
func (a *Auth) AuthHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
			return a.VerifyKey, nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		log.Println("welcome:", token.Claims)
		h.ServeHTTP(w, r)
	})
}
