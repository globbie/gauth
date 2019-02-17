package vkontakte

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/globbie/gauth/pkg/auth"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/vk"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	ProviderType = "vkontakte"
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
			Endpoint:     vk.Endpoint,
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
	// todo(n.rodionov): golang libraries lacks VK.com API library

	client := p.oauthConfig.Client(context.TODO(), token)

	u := fmt.Sprintf("https://api.vk.com/method/users.get?v=5.92")
	response, err := client.Get(u)
	if err != nil {
		log.Print("failed to fetch user info, error:", err)
		return provider.UserIdentity{}, err
	}
	defer func() {
		err = response.Body.Close()
		if err != nil {
			log.Print("failed to close response body, error:", err)
		}
	}()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Print("failed read response body, error:", err)
		return provider.UserIdentity{}, err
	}

	userInfoResp := userInfoResponse{}
	err = json.Unmarshal(body, &userInfoResp)
	if err != nil {
		log.Print("failed to unmarshal response, error:", err)
		return provider.UserIdentity{}, err
	}

	if len(userInfoResp.Response) != 1 {
		log.Print("user info response contains unexpected number of results:", len(userInfoResp.Response))
		return provider.UserIdentity{}, err
	}

	identity := provider.UserIdentity{
	}
	return identity, nil
}

type userInfoResponse struct {
	Response []userInfo `json:"response"`
}

type userInfo struct {
	ID int `json:"id"`
}
