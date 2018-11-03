package github

import (
	"context"
	"encoding/json"
	"github.com/globbie/gauth/pkg/auth"
	"github.com/globbie/gauth/pkg/auth/ctx"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	goGithub "github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"log"
	"net/http"
	"strconv"
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
	err := s.ProviderCreate("github")
	if err != nil {
		return nil, err
	}
	return &p, nil
}

type Credentials struct {
	ID string `json:"id"`
	Email string `json:"email"`
}

func (c Credentials) UID() string {
	return c.ID
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
	// todo: use provider name as a pid
	creds, err := p.storage.UserRead("github", strconv.FormatInt(*user.ID, 10))
	if err != nil && err != storage.ErrNotFound {
		log.Println("failed to get user from stroage, error:", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err == storage.ErrNotFound {
		creds = Credentials{
			ID: strconv.FormatInt(*user.ID, 10),
			Email: *user.Email,
		}
		err = p.storage.UserCreate("github", creds)
		if err != nil {
			http.Error(w, "could not create user", http.StatusInternalServerError)
			return
		}
	}
	// todo: store github token for later use
	// todo: redirect and issue jwt for user if needed

	jwt, err := auth.CreateToken(user.GetEmail(), ctx.SignKey)
	if err != nil {
		log.Println("failed to create token", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	response, err := json.Marshal(auth.Token{Token: jwt})
	if err != nil {
		log.Print("failed to marshal json:", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}
