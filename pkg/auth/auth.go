package auth

import (
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"log"
	"net/http"
	"net/url"
)

type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
}

type Auth struct {
	URLPrefix string

	idProviders map[string]provider.IdentityProvider
	clients     map[string]Client

	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey
}

// todo: delete this factory
func New(verifyKey *rsa.PublicKey, signKey *rsa.PrivateKey, storage storage.Storage) *Auth {
	auth := &Auth{
		idProviders: make(map[string]provider.IdentityProvider),
		clients:     make(map[string]Client),
		VerifyKey:   verifyKey,
		SignKey:     signKey,
	}
	return auth
}

func (a *Auth) NewServeMux() http.Handler {
	return &serveMux{a}
}

func (a *Auth) AddClient(client Client) {
	_, ok := a.clients[client.ID]
	if ok {
		log.Fatalf("client %v is already registered", client.ID)
	}
	a.clients[client.ID] = client
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

func (a *Auth) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// todo
		// 4.1.3.  Access Token Request
		// https://tools.ietf.org/html/rfc6749#section-4.1.3

		// todo
		// 4.1.4.  Access Token Response
		// https://tools.ietf.org/html/rfc6749#section-4.1.4
	})
}

// todo: validate all request fields
func (a *Auth) parseAuthRequest(r *http.Request) (authReq storage.AuthRequest, err error) {
	if err = r.ParseForm(); err != nil {
		err = errors.New("bad request") // todo
		return
	}
	redirectURI, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
	if err != nil {
		err = errors.New("bad request") // todo
		return
	}
	clientID := r.Form.Get("client_id")
	client, ok := a.clients[clientID]
	if !ok {
		log.Printf("client %v not found", clientID)
		err = errors.New("bad request") // todo
		return
	}
	uriValid := false
	for _, uri := range client.RedirectURIs {
		if redirectURI == uri {
			uriValid = true
		}
	}
	if !uriValid {
		log.Println("no matching uri found")
		err = errors.New("bad request") // todo
		return
	}
	state := r.Form.Get("state")
	if state == "" {
		log.Println("'state' is empty")
		err = errors.New("bad request") // todo
		return
	}
	responseType := r.Form.Get("response_type")
	if responseType != "code" { // temporary hardcoded for authorization code grant type
		log.Println("response_type must be 'code'")
		err = errors.New("bad request") // todo
		return
	}

	// todo: setup all parse fields
	return storage.AuthRequest{
		ID:           "todo: generate id",
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		State:        state,
		ResponseType: responseType,
	}, nil
}

// only authorization code grant flow for now
func (a *Auth) AuthorizationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authReq, err := a.parseAuthRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = authReq

		// todo: render login/register page with AuthRequestID set as a parameter of login/register button
		// /auth/<provider>/<action>?req-id=<id>
		// so view must be injected into auth

		// from https://tools.ietf.org/html/rfc6749#section-4.1
		// The authorization server authenticates the resource owner (via
		// the user-agent) and establishes whether the resource owner
		// grants or denies the client's access request.

		// todo: move code below into new separate function
		// from https://tools.ietf.org/html/rfc6749#section-4.1
		// Assuming the resource owner grants access, the authorization
		// server redirects the user-agent back to the client using the
		// redirection URI provided earlier (in the request or during
		// client registration).  The redirection URI includes an
		// authorization code and any local state provided by the client
		// earlier.

		/*
		u, err := url.Parse(redirectURI)
		if err != nil {
			log.Printf("failed to parse redirect uri '%v', error: %v", redirectURI, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		q := u.Query()
		q.Set("code", "123") // todo
		q.Set("state", state)
		u.RawQuery = q.Encode()

		http.Redirect(w, r, u.String(), http.StatusSeeOther)
		*/
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
