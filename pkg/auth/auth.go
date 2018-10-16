package auth

import (
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/globbie/gnode/pkg/auth/provider"
	"github.com/globbie/gnode/pkg/auth/provider/password"
	"log"
	"net/http"
)

type Auth struct {
	URLPrefix string

	idProviders     map[string]provider.IdentityProvider
	defaultProvider provider.IdentityProvider

	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey
}

func New(VerifyKey *rsa.PublicKey, SignKey *rsa.PrivateKey) *Auth {
	auth := &Auth{
		idProviders: make(map[string]provider.IdentityProvider),
		VerifyKey:   VerifyKey,
		SignKey:     SignKey,
	}

	auth.defaultProvider = password.NewProvider()
	auth.AddIdentityProvider("password", auth.defaultProvider)

	return auth
}

func (a *Auth) NewServeMux() http.Handler {
	return &serveMux{a}
}

func (a *Auth) GetIdentityProvider(name string) (provider.IdentityProvider, error) {
	provider, ok := a.idProviders[name]
	if !ok {
		return nil, errors.New("provider not found")
	}
	return provider, nil
}

func (a *Auth) AddIdentityProvider(name string, provider provider.IdentityProvider) {
	_, ok := a.idProviders[name]
	if ok {
		log.Fatalf("provider %v is already registered", name)
	}
	a.idProviders[name] = provider
}

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
