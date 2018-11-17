package facebook

import (
	"github.com/globbie/gauth/pkg/auth/ctx"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

type Provider struct {
	storage     storage.Storage
	oauthConfig oauth2.Config
	state       string
}

func (p *Provider) Login(ctx *ctx.Ctx) {
	panic("implement me")
}

func (p *Provider) Logout(ctx *ctx.Ctx) {
	panic("implement me")
}

func (p *Provider) Register(ctx *ctx.Ctx) {
	panic("implement me")
}

func (p *Provider) Callback(ctx *ctx.Ctx) {
	panic("implement me")
}

type Config struct {
	ClientID     string `json:"client-id"`
	ClientSecret string `json:"client-secret"`
}

func (c *Config) New(s storage.Storage) (provider.IdentityProvider, error) {
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
	err := s.ProviderCreate("github")
	if err != nil {
		return nil, err
	}
	return &p, nil
}

