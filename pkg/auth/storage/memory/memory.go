package memoryStorage

import (
	"github.com/globbie/gnode/pkg/auth/storage"
)

type MemoryStorage struct {
	data map[string]storage.UserCredentials
}

func New() *MemoryStorage {
	s := MemoryStorage{}
	s.data = make(map[string]storage.UserCredentials)
	return &s
}

func (s *MemoryStorage) Close() error {
	return nil
}

func (s *MemoryStorage) UserCreate(c storage.UserCredentials) error {
	_, ok := s.data[c.UID]
	if ok {
		return storage.ErrAlreadyExists
	}
	s.data[c.UID] = c
	return nil
}

func (s *MemoryStorage) UserRead(uid string) (u storage.UserCredentials, err error) {
	u, ok := s.data[uid]
	if !ok {
		err = storage.ErrNotFound
		return
	}
	return
}

func (s *MemoryStorage) UserUpdate(uid string, updater func(c storage.UserCredentials) (storage.UserCredentials, error)) error {
	return storage.ErrNotImplemented
}

func (s *MemoryStorage) UserDelete(uid string) error {
	_, ok := s.data[uid]
	if !ok {
		return storage.ErrNotFound
	}
	delete(s.data, uid)
	return nil
}

