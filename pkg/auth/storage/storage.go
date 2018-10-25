package storage

import (
	"errors"
)

type Storage interface {
	Close() error

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

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrNotImplemented = errors.New("not implemented")
)
