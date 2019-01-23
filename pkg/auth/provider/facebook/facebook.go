package facebook

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/globbie/gauth/pkg/auth"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"io/ioutil"
	"net/http"
)

const (
	ProviderType = "facebook"
	userInfoURL  = "https://graph.facebook.com/me"
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
			Scopes:       []string{"email"},
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
	id          string
	storage     storage.Storage
	oauthConfig oauth2.Config
	state       string
}

func (p *Provider) Type() string {
	return ProviderType
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

func (p *Provider) Callback(w http.ResponseWriter, r *http.Request, authReq storage.AuthRequest) error {
	code := r.FormValue("code")
	token, err := p.oauthConfig.Exchange(context.TODO(), code)
	if err != nil {
		return auth.Error{
			StatusCode:    http.StatusBadRequest,
			Message:       fmt.Sprint("oauth exchange failed:", err.Error()),
			PublicMessage: "Bad Request",
		}
	}
	client := p.oauthConfig.Client(context.TODO(), token)
	resp, err := client.Get(userInfoURL)
	if err != nil {
		return auth.Error{
			StatusCode:    http.StatusInternalServerError,
			Message:       fmt.Sprint("failed to get google user info:", err.Error()),
			PublicMessage: "Internal Server Error",
		}
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	userInfo := UserInfo{}
	err = json.Unmarshal(body, &userInfo)

	creds, err := p.storage.UserRead(p.id, userInfo.Email)
	if err != nil && err != storage.ErrNotFound {
		return auth.Error{
			StatusCode:    http.StatusInternalServerError,
			Message:       fmt.Sprint("failed to get user from storage:", err.Error()),
			PublicMessage: "Internal Error",
		}
	}
	if err == storage.ErrNotFound {
		creds = Credentials{
			Email: userInfo.Email,
		}
		err = p.storage.UserCreate(p.id, creds)
		if err != nil {
			return auth.Error{
				StatusCode:    http.StatusInternalServerError,
				Message:       fmt.Sprint("could not create user:", err.Error()),
				PublicMessage: "Internal Error",
			}
		}
	}
	return nil
}

type UserInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	GivenName  string `json:"first_name"`
	FamilyName string `json:"last_name"`
	Picture    string `json:"picture"`
	Profile    string `json:"link"`
	Email      string `json:"email"`
	Gender     string `json:"gender"`
	Locale     string `json:"locale"`
	Verified   bool   `json:"verified"`
}

type Credentials struct {
	Email string `json:"email"`
}

func (c Credentials) UID() string {
	return c.Email
}
