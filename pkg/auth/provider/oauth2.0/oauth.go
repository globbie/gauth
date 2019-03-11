package oauth2_0

import (
	"context"
	"fmt"
	"github.com/globbie/gauth/pkg/auth"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"golang.org/x/oauth2"
	"net/http"
)

type Config struct {
	ClientID     string `json:"client-id"`
	ClientSecret string `json:"client-secret"`
	RedirectURI  string `json:"redirect-uri"`
}

func (c *Config) New(s storage.Storage, id string) (provider.IdentityProvider, error) {
	p := Provider{
		id:      id,
		storage: s,
		oauthConfig: oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			RedirectURL:  c.RedirectURI,
			Scopes:       []string{"TODO"},  // todo
			Endpoint:     oauth2.Endpoint{}, //todo
		},
	}
	err := s.ProviderCreate(id)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

type Provider struct {
	id          string
	storage     storage.Storage
	oauthConfig oauth2.Config
}

func (p *Provider) Type() string {
	return "OAuth2.0"
}

func (p *Provider) Login(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	url := p.oauthConfig.AuthCodeURL(authReq.ID, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (p *Provider) Logout(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
}

func (p *Provider) Register(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	p.Login(w, r, authReq)
}

func (p *Provider) Callback(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) (provider.UserIdentity, error) {
	code := r.FormValue("code")
	token, err := p.oauthConfig.Exchange(context.TODO(), code)
	if err != nil {
		return provider.UserIdentity{}, auth.Error{
			StatusCode:    http.StatusBadRequest,
			Message:       fmt.Sprint("oauth exchange failed:", err.Error()),
			PublicMessage: "Bad Request",
		}
	}

	_ = token
	// provider specific user read/create functions
	return provider.UserIdentity{}, nil
}
