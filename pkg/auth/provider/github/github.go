package github

import (
	"context"
	"github.com/globbie/gnode/pkg/auth/ctx"
	"github.com/globbie/gnode/pkg/auth/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"log"
	"net/http"
)

type Provider struct {
	storage     storage.Storage
	oauthConfig oauth2.Config
}

func NewProvider(s storage.Storage) *Provider {
	p := Provider{
		storage: s,
		oauthConfig: oauth2.Config{
			ClientID:     "",
			ClientSecret: "",
			Scopes:       []string{},
			Endpoint:     github.Endpoint,
		},
	}
	return &p
}

func (p *Provider) Login(ctx *ctx.Ctx) {
	// todo: set state
	// todo: use AccessTypeOffLine
	url := p.oauthConfig.AuthCodeURL("", oauth2.AccessTypeOnline)
	http.Redirect(ctx.W, ctx.R, url, http.StatusFound)
}

func (p *Provider) Logout(ctx *ctx.Ctx) {
}

func (p *Provider) Register(ctx *ctx.Ctx) {
}

func (p *Provider) Callback(ctx *ctx.Ctx) {
	req := ctx.R

	state := req.FormValue("state")
	_ = state // todo: check state

	code := req.FormValue("code")
	token, err := p.oauthConfig.Exchange(context.TODO(), code)
	if err != nil {
		log.Printf("failed to get token, error: '%v'", err)
		http.Error(ctx.W, "failed to authorize", http.StatusUnauthorized)
		return
	}
	_ = token

	// todo: get user info
	// todo: find user in storage
	// todo: create user if not exists
	// todo: store token for later use
	// todo: redirect and issue jwt for user if needed
}

