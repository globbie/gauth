package github

import (
	"context"
	"github.com/globbie/gnode/pkg/auth/ctx"
	"github.com/globbie/gnode/pkg/auth/provider"
	"github.com/globbie/gnode/pkg/auth/storage"
	goGithub "github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"log"
	"net/http"
)

type Provider struct {
	storage     storage.Storage
	oauthConfig oauth2.Config
	state       string
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
			Endpoint:     github.Endpoint,
		},
		state: "random-string", // todo: this should be a random string
	}
	return &p, nil
}

func (p *Provider) Login(ctx *ctx.Ctx) {
	url := p.oauthConfig.AuthCodeURL(p.state, oauth2.AccessTypeOnline) // todo: use AccessTypeOffLine
	http.Redirect(ctx.W, ctx.R, url, http.StatusFound)
}

func (p *Provider) Logout(ctx *ctx.Ctx) {
}

func (p *Provider) Register(ctx *ctx.Ctx) {
}

func (p *Provider) Callback(ctx *ctx.Ctx) {
	var (
		w = ctx.W
		r = ctx.R
	)
	state := r.FormValue("state")
	if state != p.state {
		log.Printf("oauth state does not match, expected '%s', got '%s'\n", p.state, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	code := r.FormValue("code")
	token, err := p.oauthConfig.Exchange(context.TODO(), code)
	if err != nil {
		log.Printf("failed to get token, error: '%v'", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	client := p.oauthConfig.Client(context.TODO(), token)
	githubClient := goGithub.NewClient(client)
	user, _, err := githubClient.Users.Get(context.TODO(), "")
	if err != nil {
		log.Println("failed to get github user info, error:", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	_ = user
	// todo: find user in storage
	// todo: create user if not exists
	// todo: store token for later use
	// todo: redirect and issue jwt for user if needed
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
