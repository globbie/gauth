package auth

import (
	"errors"
	"time"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrAlreadyExists  = errors.New("already exists")
	ErrNotImplemented = errors.New("not implemented")
)

type Repository interface {
}

type RefreshToken struct {
	ID string `json:"id"`

	Token string `json:"token"`

	CreatedAt time.Time `json:"created-at"`

	ClientID   string `json:"client-id"`
	ProviderID string `json:"provider-id"`
}

type RefreshTokenRepository interface {
	Create(token RefreshToken) error
	Read(id string) (RefreshToken, error)
	Update(tokenID string, updater func(token RefreshToken) (RefreshToken, error)) error
	Delete(id string) error
}

type RefreshTokenRepositoryConfig interface {
	New() (RefreshTokenRepository, error)
}

