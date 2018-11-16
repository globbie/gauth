package storage

import (
	"errors"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrAlreadyExists  = errors.New("already exists")
	ErrNotImplemented = errors.New("not implemented")
)

type Storage interface {
	Close() error

	// todo: move provider into separate storage
	ProviderCreate(pid string) error
	//ProviderDelete(pid string) error
	//ProviderList() error

	UserCreate(pid string, c Credentials) error
	UserRead(pid string, uid string) (Credentials, error)
	UserUpdate(pid string, uid string, updater func(c Credentials) (Credentials, error)) error
	UserDelete(pid string, uid string) error
}

type Credentials interface {
	UID() string
}

type AuthRequestStorage interface {
	Close() error

	AuthRequestCreate(a AuthRequest) error
	AuthRequestRead(uid string) (AuthRequest, error)
	AuthRequestDelete(uid string) error
}

type AuthRequest struct {
	ID           string
	ClientID     string
	RedirectURI  string
	State        string
	ResponseType string

	//expiry time.Time todo
}
