package in_memory

import (
	"github.com/globbie/gauth/pkg/auth"
)

type RefreshTokenRepository struct {
	tokens map[string]auth.RefreshToken
}

func (r *RefreshTokenRepository) Create(token auth.RefreshToken) error {
	_, ok := r.tokens[token.Token]
	if ok {
		return auth.ErrAlreadyExists
	}
	r.tokens[token.Token] = token
	return nil
}

func (r *RefreshTokenRepository) Read(id string) (auth.RefreshToken, error) {
	token, ok := r.tokens[id]
	if !ok {
		return auth.RefreshToken{}, auth.ErrNotFound
	}
	return token, nil
}

func (r *RefreshTokenRepository) Update(id string, updater func(token auth.RefreshToken) (auth.RefreshToken, error)) error {
	token, ok := r.tokens[id]
	if !ok {
		return auth.ErrNotFound
	}
	tokenNew, err := updater(token)
	if err != nil {
		return err
	}
	r.tokens[id] = tokenNew
	return nil
}

func (r *RefreshTokenRepository) Delete(id string) error {
	_, ok := r.tokens[id]
	if !ok {
		return auth.ErrNotFound
	}
	delete(r.tokens, id)
	return nil
}

type Config struct {
	// there is nothing to config
}

func (c *Config) New() (auth.RefreshTokenRepository, error) {
	r := RefreshTokenRepository{
		tokens: make(map[string]auth.RefreshToken),
	}
	return &r, nil
}
