package storage

import (
	"errors"
	"github.com/globbie/gnode/pkg/auth/provider/password/encryptionSchemes"
)

type Storage interface {
	Close() error

	UserCreate(c UserCredentials) error
	UserRead(uid string) (UserCredentials, error)
	UserUpdate(uid string, updater func (c UserCredentials) (UserCredentials, error)) error
	UserDelete(uid string) error
}

type UserCredentials struct {
	UID               string

	// fixme: this fields breaks encapsulation
	EncryptedPassword string
	EncryptionScheme  encryptionSchemes.EncryptionScheme
}

var (
	ErrNotFound = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")

	ErrNotImplemented = errors.New("not implemented")
)
