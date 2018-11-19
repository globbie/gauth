package provider

import (
	"github.com/globbie/gauth/pkg/auth/storage"
	"net/http"
)

type IdentityProvider interface {
	Type() string

	Login(w http.ResponseWriter, r *http.Request, request storage.AuthRequest)
	Register(w http.ResponseWriter, r *http.Request, request storage.AuthRequest)
	Logout(w http.ResponseWriter, r *http.Request, request storage.AuthRequest)
	Callback(w http.ResponseWriter, r *http.Request, request storage.AuthRequest)
}
