package provider

import (
	"github.com/globbie/gauth/pkg/auth/storage"
	"net/http"
)

/*
 * todo-list:
 * 1. OAuth providers do not need to implement RegisterContentType methods. So, there should be another interface.
 * 2. OAuth providers do not need to implement Logout. So, ...
 * 3. Password providers do not need to implement Callback. So, ...
 * 4. OAuth callback functions are 85% the same. So, there should be common methods.
 * 5. OAuth callback function are the same. So, redirect should be placed upper throw the stack.
 *            This function should return url.
 */

type IdentityProvider interface {
	Type() string

	Login(w http.ResponseWriter, r *http.Request, request storage.AuthRequest)
	Register(w http.ResponseWriter, r *http.Request, request storage.AuthRequest)
	Logout(w http.ResponseWriter, r *http.Request, request storage.AuthRequest)
	Callback(w http.ResponseWriter, r *http.Request, request storage.AuthRequest) error
}
