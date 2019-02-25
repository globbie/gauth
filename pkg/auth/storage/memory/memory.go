package memoryStorage

import (
	"github.com/globbie/gauth/pkg/auth/storage"
	"log"
)

// todo: select consistent function prototype style

type Config struct {
	// there is nothing to config
}

func (c *Config) New() (storage.Storage, error) {
	s := New()
	return &s, nil
}

// todo: decompose memory storage into separate storages according to their roles
type MemoryStorage struct {
	credentials  map[string]map[string]storage.Credentials
	authRequests map[string]storage.AuthRequest
	authCodes    map[string]storage.AuthCode
}

func New() MemoryStorage {
	s := MemoryStorage{}
	s.credentials = make(map[string]map[string]storage.Credentials)
	s.authRequests = make(map[string]storage.AuthRequest)
	s.authCodes = make(map[string]storage.AuthCode)
	return s
}

func (s *MemoryStorage) Close() error {
	return nil
}

func (s *MemoryStorage) ProviderCreate(pid string) error {
	s.credentials[pid] = make(map[string]storage.Credentials)
	return nil
}

func (s *MemoryStorage) UserCreate(pid string, c storage.Credentials) error {
	providerData, ok := s.credentials[pid]
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
	providerData, ok := s.credentials[pid]
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
	providerData, ok := s.credentials[pid]
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

func (s *MemoryStorage) AuthRequestCreate(a storage.AuthRequest) error {
	_, ok := s.authRequests[a.ID]
	if ok {
		return storage.ErrAlreadyExists
	}
	s.authRequests[a.ID] = a
	return nil
}

func (s *MemoryStorage) AuthRequestRead(uid string) (a storage.AuthRequest, err error) {
	a, ok := s.authRequests[uid]
	if !ok {
		err = storage.ErrNotFound
		return
	}
	return
}

func (s *MemoryStorage) AuthRequestUpdate(uid string, updater func (a storage.AuthRequest) (storage.AuthRequest, error)) error {
	a, ok := s.authRequests[uid]
	if !ok {
		return storage.ErrNotFound
	}
	aNew, err := updater(a)
	if err != nil {
		return err
	}
	s.authRequests[uid] = aNew
	return nil
}

func (s *MemoryStorage) AuthRequestDelete(uid string) error {
	_, ok := s.authRequests[uid]
	if !ok {
		return storage.ErrNotFound
	}
	delete(s.authRequests, uid)
	return nil
}

func (s *MemoryStorage) AuthCodeCreate(a storage.AuthCode) error {
	_, ok := s.authCodes[a.ID]
	if ok {
		return storage.ErrAlreadyExists
	}
	s.authCodes[a.ID] = a
	return nil
}

func (s *MemoryStorage) AuthCodeRead(uid string) (a storage.AuthCode, err error) {
	a, ok := s.authCodes[uid]
	if !ok {
		err = storage.ErrNotFound
		return
	}
	return
}

func (s *MemoryStorage) AuthCodeDelete(uid string) error {
	_, ok := s.authCodes[uid]
	if !ok {
		return storage.ErrNotFound
	}
	return nil
}
