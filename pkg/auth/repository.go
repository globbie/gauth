package auth

import (
	"errors"
	"math/rand"
	"time"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrAlreadyExists  = errors.New("already exists")
	ErrNotImplemented = errors.New("not implemented")
)

func NewRandomID() string {
	const (
		alphabet = "abcdefghijklmnopqrstuvwxuzABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789"
		idLen    = 22
	)

	randSource := rand.NewSource(time.Now().UnixNano())
	buff := make([]byte, idLen)
	for i := range buff {
		buff[i] = alphabet[randSource.Int63()%int64(len(alphabet))]
	}
	return string(buff)
}

type Repository interface {
}

type RefreshToken struct {
	Token string `json:"token"`

	CreatedAt time.Time `json:"created-at"`

	ClientID string `json:"client-id"`
	//ProviderID string `json:"provider-id"` // todo(n.rodionov)
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
