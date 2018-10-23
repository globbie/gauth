package knowdyStorage

import (
	"errors"
	"github.com/globbie/gnode/pkg/auth/storage"
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

func (s *KnowdyStorage) CreateUserRequest(u *storage.UserCredentials) error {
	return errors.New("not implemented")
}

func (s *KnowdyStorage) DeleteUserRequest(u *storage.UserCredentials) error {
	return errors.New("not implemented")
}
