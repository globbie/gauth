package storage

import (
	"errors"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrAlreadyExists  = errors.New("already exists")
	ErrNotImplemented = errors.New("not implemented")
)

// todo: make separate interfaces for users, auth-requests and providers
// todo: move storage interface to auth module

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

	AuthRequestCreate(a AuthRequest) error
	AuthRequestRead(uid string) (AuthRequest, error)
	AuthRequestDelete(uid string) error

	AuthCodeCreate(a AuthCode) error
	AuthCodeRead(uid string) (AuthCode, error)
	AuthCodeDelete(uid string) error
}

type Credentials interface {
	UID() string
}

// todo(n.rodionov): move this struct to auth module
type AuthRequest struct {
	ID           string
	ClientID     string
	RedirectURI  string
	State        string
	ResponseType string

	// PKCE extension
	CodeChallenge       string
	CodeChallengeMethod string

	//expiry time.Time todo
}

type AuthCode struct {
	ID       string
	ClientID string

	CodeChallenge       string
	CodeChallengeMethod string

	//Expiry time.Time
}
