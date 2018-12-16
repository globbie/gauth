package github

import (
	"context"
	"fmt"
	"github.com/globbie/gauth/pkg/auth"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	goGithub "github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
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
		id:      id,
		storage: s,
		oauthConfig: oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       []string{},
			Endpoint:     github.Endpoint,
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
	return ProviderType
}

// todo: use AccessTypeOffLine
func (p *Provider) Login(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
	url := p.oauthConfig.AuthCodeURL(authReq.ID, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (p *Provider) Logout(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
}

func (p *Provider) Register(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) {
}

func (p *Provider) Callback(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) error {
	code := r.FormValue("code")
	token, err := p.oauthConfig.Exchange(context.TODO(), code)
	if err != nil {
		return auth.Error{
			StatusCode: http.StatusBadRequest,
			Message: fmt.Sprint("oauth exchange failed:", err.Error()),
			PublicMessage: "Bad Request",
		}
	}
	client := p.oauthConfig.Client(context.TODO(), token)
	githubClient := goGithub.NewClient(client)
	user, _, err := githubClient.Users.Get(context.TODO(), "")
	if err != nil {
		return auth.Error{
			StatusCode: http.StatusBadRequest,
			Message: fmt.Sprint("oauth exchange failed:", err.Error()),
			PublicMessage: "Bad Request",
		}
	}
	creds, err := p.storage.UserRead(p.id, strconv.FormatInt(*user.ID, 10))
	if err != nil && err != storage.ErrNotFound {
		return auth.Error{
			StatusCode: http.StatusInternalServerError,
			Message: fmt.Sprint("failed to get user from storage:", err.Error()),
			PublicMessage: "Internal Error",
		}
	}
	if err == storage.ErrNotFound {
		creds = Credentials{
			ID:    strconv.FormatInt(*user.ID, 10),
			Email: *user.Email,
		}
		err = p.storage.UserCreate("github", creds)
		if err != nil {
			return auth.Error{
				StatusCode: http.StatusInternalServerError,
				Message: fmt.Sprint("could not create user:", err.Error()),
				PublicMessage: "Internal Error",
			}
		}
	}
	return nil
}

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
//response := []byte("to be done")
//w.WriteHeader(http.StatusOK)
//w.Header().Set("Content-Type", "application/json")
//w.Write(response)

type Credentials struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (c Credentials) UID() string {
	return c.ID
}
