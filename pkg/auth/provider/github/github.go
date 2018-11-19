package github

import (
	"context"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	goGithub "github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"log"
	"net/http"
	"strconv"
)

const ProviderType = "github"

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
			Endpoint:     github.Endpoint,
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
	url := p.oauthConfig.AuthCodeURL(p.state, oauth2.AccessTypeOnline) // todo: use AccessTypeOffLine
	http.Redirect(w, r, url, http.StatusFound)
}

func (p *Provider) Logout(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
}

func (p *Provider) Register(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
}

func (p *Provider) Callback(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
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
			ID:    strconv.FormatInt(*user.ID, 10),
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

	//jwt, err := auth.CreateToken(user.GetEmail(), ctx.SignKey)
	//if err != nil {
	//	log.Println("failed to create token", err)
	//	http.Error(w, "internal error", http.StatusInternalServerError)
	//	return
	//}
	//response, err := json.Marshal(auth.Token{Token: jwt})
	//if err != nil {
	//	log.Print("failed to marshal json:", err)
	//	http.Error(w, "internal server error", http.StatusInternalServerError)
	//	return
	//}
	response := []byte("to be done")
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

type Credentials struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (c Credentials) UID() string {
	return c.ID
}
