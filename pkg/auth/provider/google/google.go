package google

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/globbie/gauth/pkg/auth"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"net/http"
)

const (
	ProviderType = "google"
	UserInfoURL  = "https://www.googleapis.com/oauth2/v3/userinfo"
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
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			Endpoint:     google.Endpoint,
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
			StatusCode:    http.StatusBadRequest,
			Message:       fmt.Sprint("oauth exchange failed:", err.Error()),
			PublicMessage: "Bad Request",
		}
	}
	client := p.oauthConfig.Client(context.TODO(), token)
	resp, err := client.Get(UserInfoURL)
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
		err = p.storage.UserCreate("github", creds)
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
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
}

type Credentials struct {
	Email string `json:"email"`
}

func (c Credentials) UID() string {
	return c.Email
}
