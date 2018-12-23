package auth

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/golang/gddo/httputil/header"

	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"github.com/globbie/gauth/pkg/auth/view"

	"github.com/google/uuid"
	"log"
	"net/http"
	"net/url"
	"strconv"
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

	Storage    storage.Storage
	ViewRouter view.Router
}

// todo: delete this factory
func New(verifyKey *rsa.PublicKey, signKey *rsa.PrivateKey, storage storage.Storage, vr view.Router) *Auth {
	auth := &Auth{
		idProviders: make(map[string]provider.IdentityProvider),
		clients:     make(map[string]Client),
		VerifyKey:   verifyKey,
		SignKey:     signKey,
		Storage:     storage,
		ViewRouter:  vr,
	}
	return auth
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
		return nil, errors.New("provider not found")
	}
	return p, nil
}

func (a *Auth) AddIdentityProvider(id string, provider provider.IdentityProvider) {
	_, ok := a.idProviders[id]
	if ok {
		log.Fatalf("provider '%v' is already registered", id)
	}
	a.idProviders[id] = provider
}

func (a *Auth) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 4.1.3.  Access Token Request
		// https://tools.ietf.org/html/rfc6749#section-4.1.3
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		var err error
		if clientID, err = url.QueryUnescape(clientID); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if clientSecret, err = url.QueryUnescape(clientSecret); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		client, ok := a.clients[clientID]
		if !ok {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		if client.Secret != clientSecret {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		grantType := r.PostFormValue("grant_type") // todo: add refresh token
		if grantType != "authorization_code" {     // todo: fix hardcoded value
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		code := r.PostFormValue("code")
		_ = r.PostFormValue("redirect_uri") // todo

		_, err = a.Storage.AuthCodeRead(code)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		err = a.Storage.AuthCodeDelete(code)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// 4.1.4.  Access Token Response
		// https://tools.ietf.org/html/rfc6749#section-4.1.4

		jwt, err := CreateToken("hardcoded string", a.SignKey) // todo: fix hardcode
		if err != nil {
			log.Println("failed to create token", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp := struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			RefreshToken string `json:"refresh_token,omitempty"`
			ExpiresIn    int    `json:"expires_in"`
		}{
			AccessToken:  jwt,
			TokenType:    "Bearer",
			RefreshToken: "",   // todo
			ExpiresIn:    3600, // todo
		}
		data, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
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

	reqID, err := uuid.NewRandom()
	if err != nil {
		log.Println("failed to generate random uuid for auth request, error:", err)
		err = errors.New("bad request") // todo
		return
	}

	// todo: setup all parse fields
	return storage.AuthRequest{
		ID:           reqID.String(),
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		State:        state,
		ResponseType: responseType,
	}, nil
}

// only authorization code grant flow for now
func (a *Auth) AuthorizationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		specs := header.ParseAccept(r.Header, "Accept")
		v, err := a.ViewRouter.NegotiateView(specs)
		if err != nil {
			http.Error(w, "Not Acceptable", http.StatusNotAcceptable)
			return
		}
		authReq, err := a.parseAuthRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = a.Storage.AuthRequestCreate(authReq)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		providersInfo := make([]view.ProviderInfo, 0, len(a.idProviders))
		for name, p := range a.idProviders {
			providersInfo = append(providersInfo, view.ProviderInfo{
				Name: name,
				Url:  "/auth/" + name + "/login" + "?req=" + authReq.ID,
				Type: p.Type(),
			})
		}
		err = v.Login(w, providersInfo)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	})
}

// todo: change handler name
func (a *Auth) ResourceHandler(h http.Handler) http.Handler {
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
