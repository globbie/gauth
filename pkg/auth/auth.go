package auth

import (
	"errors"
	IDP "github.com/globbie/gnode/pkg/identity-provider"
	"log"
	"net/http"
)

type Auth struct {
	URLPrefix string

	idProviders map[string] IDP.IdentityProvider
	defaultProvider IDP.IdentityProvider
}

func New() *Auth {
	return &Auth{
		idProviders: make(map[string] IDP.IdentityProvider),
	}
}

func (a *Auth) NewServeMux() http.Handler {
	return &serveMux{a}
}

func (a *Auth) GetIdentityProvider(name string) (IDP.IdentityProvider, error) {
	provider, ok := a.idProviders[name]
	if !ok {
		return nil, errors.New("provider not found")
	}
	return provider, nil
}

func (a *Auth) AddIdentityProvider(name string, provider IDP.IdentityProvider) {
	_, ok := a.idProviders[name]
	if ok {
		log.Fatalf("provider %v is already registered", name)
	}
	a.idProviders[name] = provider
}

