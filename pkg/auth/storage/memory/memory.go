package memoryStorage

import (
	"github.com/globbie/gnode/pkg/auth/storage"
	"log"
)

type MemoryStorage struct {
	data map[string]map[string]storage.Credentials
}

func New() *MemoryStorage {
	s := MemoryStorage{}
	s.data = make(map[string]map[string]storage.Credentials)
	return &s
}

func (s *MemoryStorage) Close() error {
	return nil
}

func (s *MemoryStorage) ProviderCreate(pid string) error {
	s.data[pid] = make(map[string]storage.Credentials)
	return nil
}

func (s *MemoryStorage) UserCreate(pid string, c storage.Credentials) error {
	providerData, ok := s.data[pid]
	if !ok {
		log.Panicf("'%v' provider not found", pid)
	}
	_, ok = providerData[c.UID()]
	if ok {
		return storage.ErrAlreadyExists
	}
	providerData[c.UID()] = c
	return nil
}

func (s *MemoryStorage) UserRead(pid string, uid string) (c storage.Credentials, err error) {
	providerData, ok := s.data[pid]
	if !ok {
		log.Panicf("'%v' provider not found", pid)
	}
	c, ok = providerData[uid]
	if !ok {
		err = storage.ErrNotFound
	}
	return
}

func (s *MemoryStorage) UserUpdate(pid string, uid string, updater func(c storage.Credentials) (storage.Credentials, error)) error {
	return storage.ErrNotImplemented
}

func (s *MemoryStorage) UserDelete(pid string, uid string) error {
	providerData, ok := s.data[pid]
	if !ok {
		log.Panicf("'%v' provider not found", pid)
	}
	_, ok = providerData[uid]
	if !ok {
		return storage.ErrNotFound
	}
	delete(providerData, uid)
	return nil
}

type Config struct {
	// there is nothing to config
}

func (c *Config) New() (storage.Storage, error) {
	s := MemoryStorage{}
	s.data = make(map[string]map[string]storage.Credentials)
	return &s, nil
}
