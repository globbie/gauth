package facebook

import (
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"net/http"
)

const ProviderType = "facebook"

type Config struct {
	ClientID     string `json:"client-id"`
	ClientSecret string `json:"client-secret"`
}

func (c *Config) New(s storage.Storage, id string) (provider.IdentityProvider, error) {
	p := Provider{
		storage: s,
		oauthConfig: oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       []string{},
			Endpoint:     facebook.Endpoint,
		},
		state: "random-string", // todo: this should be a random string
	}
	err := s.ProviderCreate(id)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

type Provider struct {
	storage     storage.Storage
	oauthConfig oauth2.Config
	state       string
}

func (p *Provider) Type() string {
	return ProviderType
}

func (p *Provider) Login(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	panic("implement me")
}

func (p *Provider) Logout(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	panic("implement me")
}

func (p *Provider) Register(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	panic("implement me")
}

func (p *Provider) Callback(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) error {
	panic("implement me")
}
