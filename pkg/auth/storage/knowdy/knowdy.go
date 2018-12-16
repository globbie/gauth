package knowdyStorage

import (
	"errors"
	"github.com/globbie/gauth/pkg/auth/storage"
	"github.com/globbie/gnode/pkg/knowdy"
)

type KnowdyStorage struct {
	*knowdy.Shard
}

func New(conf string) (*KnowdyStorage, error) {
	shard, err := knowdy.New(conf)
	if err != nil {
		return nil, err
	}
	return &KnowdyStorage{Shard: shard}, nil
}

func (s *KnowdyStorage) Close() error {
	return s.Del()
}

func (s *KnowdyStorage) ProviderCreate(pid string) error {
	return errors.New("not implemented")
}

func (s *KnowdyStorage) UserCreate(pid string, c storage.Credentials) error {
	return errors.New("not implemented")
}

func (s *KnowdyStorage) UserRead(pid string, uid string) (storage.Credentials, error) {
	return nil, errors.New("not implemented")
}

func (s *KnowdyStorage) UserUpdate(pid string, uid string, updater func(c storage.Credentials) (storage.Credentials, error)) error {
	return errors.New("not implemented")
}

func (s *KnowdyStorage) UserDelete(pid string, uid string) error {
	return errors.New("not implemented")
}

func (s *KnowdyStorage) AuthRequestCreate(a storage.AuthRequest) error {
	return errors.New("not implemented")
}

func (s *KnowdyStorage) AuthRequestRead(uid string) (storage.AuthRequest, error) {
	return storage.AuthRequest{}, errors.New("not implemented")
}

func (s *KnowdyStorage) AuthRequestDelete(uid string) error {
	return errors.New("not implemented")
}

func (s *KnowdyStorage) AuthCodeCreate(a storage.AuthCode) error {
	return errors.New("not implemented")
}

func (s *KnowdyStorage) AuthCodeRead(uid string) (storage.AuthCode, error) {
	return storage.AuthCode{}, errors.New("not implemented")
}

func (s *KnowdyStorage) AuthCodeDelete(uid string) error {
	return errors.New("not implemented")
}

type Config struct {
	ConfigPath string `json:"config-path"`
}

func (c *Config) New() (storage.Storage, error) {
	shard, err := knowdy.New(c.ConfigPath)
	if err != nil {
		return nil, err
	}
	return &KnowdyStorage{Shard: shard}, nil
}
