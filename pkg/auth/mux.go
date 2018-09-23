package auth

import (
	"net/http"
	"strings"
)

type serveMux struct {
	*Auth
}

func (mux *serveMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	paths := strings.Split(strings.TrimPrefix(r.URL.Path, mux.URLPrefix), "/")

	provider := mux.defaultProvider

	if len(paths) == 0 {
		http.NotFound(w, r)
		return
	}
	if len(paths) >= 2 {
		providerName := paths[1]
		var err error
		provider, err = mux.GetIdentityProvider(providerName)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}

	switch paths[0] {
	case "login":
		provider.Login()
	case "logout":
		provider.Logout()
	case "register":
		provider.Register()
	default:
		http.NotFound(w, r)
	}

	_ = provider
}