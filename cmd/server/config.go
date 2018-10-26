package main

import (
	"encoding/json"
	"github.com/globbie/gnode/pkg/auth/provider"
	"github.com/globbie/gnode/pkg/auth/storage"
	"github.com/globbie/gnode/pkg/auth/storage/knowdy"
	"github.com/globbie/gnode/pkg/auth/storage/memory"
	"log"
)

type Config struct {
	Web       Web        `json:"web"`
	Token     Token      `json:"token"`
	Storage   Storage    `json:"storage"`
	Providers []Provider `json:"providers"`
}

type Web struct {
	HTTPAddress string `json:"http"`
}

type Token struct {
	PrivateKeyPath string `json:"private-key-path"`
	PublicKeyPath  string `json:"public-key-path"`
}

type Storage struct {
	Type   string        `json:"type"`
	Config StorageConfig `json:"config"`
}

type StorageConfig interface {
	New() (storage.Storage, error)
}

var implementations = map[string]func() StorageConfig{
	"in-memory": func() StorageConfig { return new(memoryStorage.Config) },
	"knowdy":    func() StorageConfig { return new(knowdyStorage.Config) },
}

func (s *Storage) UnmarshalJSON(b []byte) error {
	var data struct {
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(b, &data); err != nil {
		log.Fatalf("parse storage: %v", err)
	}
	f, ok := implementations[data.Type]
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
	Type string `json:"type"`
	Name string `json:"name"`

	Config provider.Config `json:"config"`
}
