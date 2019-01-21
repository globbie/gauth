package main

import (
	"encoding/json"
	"github.com/globbie/gauth/cmd/server/view"
	"log"

	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/provider/facebook"
	"github.com/globbie/gauth/pkg/auth/provider/github"
	"github.com/globbie/gauth/pkg/auth/provider/google"
	"github.com/globbie/gauth/pkg/auth/provider/password"

	"github.com/globbie/gauth/pkg/auth/storage"
	"github.com/globbie/gauth/pkg/auth/storage/knowdy"
	"github.com/globbie/gauth/pkg/auth/storage/memory"

	"github.com/globbie/gauth/pkg/auth/view"
	jsonView "github.com/globbie/gauth/pkg/auth/view/json"
)

type Config struct {
	Web       Web        `json:"web"`
	Token     Token      `json:"token"`
	Storage   Storage    `json:"storage"`
	Providers []Provider `json:"providers"`
	Frontend  Frontend   `json:"frontend"`
	Clients   []Client   `json:"clients"`
	Views     []View     `json:"views"`
}

type Web struct {
	HTTPAddress string `json:"http"`
}

type Token struct {
	PrivateKeyPath string `json:"private-key-path"`
	PublicKeyPath  string `json:"public-key-path"`
}

type Frontend struct {
	Dir string `json:"dir"`
}

type Client struct {
	ID           string   `json:"client-id"`
	Secret       string   `json:"client-secret"`
	RedirectURIs []string `json:"redirect-uris"`
	PKCE         bool     `json:"pkce"`
}

type Storage struct {
	Type   string        `json:"type"`
	Config StorageConfig `json:"config"`
}

type StorageConfig interface {
	New() (storage.Storage, error)
}

var storageConfigs = map[string]func() StorageConfig{
	"in-memory": func() StorageConfig { return new(memoryStorage.Config) },
	"knowdy":    func() StorageConfig { return new(knowdyStorage.Config) },
}

func (s *Storage) UnmarshalJSON(b []byte) error {
	var data struct {
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		log.Fatalln("parse storage:", err)
	}
	f, ok := storageConfigs[data.Type]
	if !ok {
		log.Fatalf("%v storage type is not implemented", data.Type)
	}
	config := f()
	if len(data.Config) != 0 {
		configData := []byte(string(data.Config))
		err := json.Unmarshal(configData, &config)
		if err != nil {
			log.Fatalf("failed to parse %v storage config, error: %v", data.Type, err)
		}
	}
	*s = Storage{
		Type:   data.Type,
		Config: config,
	}
	return nil
}

type Provider struct {
	Type   string         `json:"type"`
	Name   string         `json:"name"`
	ID     string         `json:"id"`
	Config ProviderConfig `json:"config"`
}

type ProviderConfig interface {
	New(s storage.Storage, id string) (provider.IdentityProvider, error)
}

var providerConfigs = map[string]func() ProviderConfig{
	password.ProviderType: func() ProviderConfig { return new(password.Config) },
	github.ProviderType:   func() ProviderConfig { return new(github.Config) },
	facebook.ProviderType: func() ProviderConfig { return new(facebook.Config) },
	google.ProviderType:   func() ProviderConfig { return new(google.Config) },
}

func (p *Provider) UnmarshalJSON(b []byte) error {
	var prov struct {
		Type   string          `json:"type"`
		Name   string          `json:"name"`
		ID     string          `json:"id"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(b, &prov); err != nil {
		log.Fatalln("parse provider config:", err)
	}
	f, ok := providerConfigs[prov.Type]
	if !ok {
		log.Fatalf("%v provider type is not implemented", prov.Type)
	}
	config := f()
	if len(prov.Config) != 0 {
		configData := []byte(string(prov.Config))
		if err := json.Unmarshal(configData, &config); err != nil {
			log.Fatalf("failed to parse %v provider config, error: %v", prov.Type, err)
		}

	}
	*p = Provider{
		Type:   prov.Type,
		Name:   prov.Name,
		ID:     prov.ID,
		Config: config,
	}
	return nil
}

type View struct {
	ContentType string     `json:"content-type"`
	Type        string     `json:"type"`
	Config      ViewConfig `json:"config"`
}

// todo: such an interfaces should be moved to corresponded modules
type ViewConfig interface {
	New(contentType string) (view.View, error)
}

var viewConfigs = map[string]func() ViewConfig{
	jsonView.ViewType:   func() ViewConfig { return new(jsonView.Config) },
	staticView.ViewType: func() ViewConfig { return new(staticView.Config) },
}

func (v *View) UnmarshalJSON(b []byte) error {
	var viewCfg struct {
		ContentType string          `json:"content-type"`
		Type        string          `json:"type"`
		Config      json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(b, &viewCfg); err != nil {
		log.Fatalln("parse view config:", err)
	}
	f, ok := viewConfigs[viewCfg.Type]
	if !ok {
		log.Fatalf("%v view type is not implemented", viewCfg.Type)
	}
	config := f()
	if len(viewCfg.Config) != 0 {
		configData := []byte(string(viewCfg.Config))
		if err := json.Unmarshal(configData, &config); err != nil {
			log.Fatalf("failed to parse %v view config, error: %v", viewCfg.Type, err)
		}
	}
	*v = View{
		ContentType: viewCfg.ContentType,
		Type:        viewCfg.Type,
		Config:      config,
	}
	return nil
}
