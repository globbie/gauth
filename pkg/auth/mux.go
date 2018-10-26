package auth

import (
	"github.com/globbie/gnode/pkg/auth/ctx"
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
	context := &ctx.Ctx{
		W:         w,
		R:         r,
		SignKey:   mux.SignKey,
		VerifyKey: mux.VerifyKey,
	}
	switch paths[0] {
	case "login":
		provider.Login(context)
	case "logout":
		provider.Logout(context)
	case "register":
		provider.Register(context)
	case "callback":
		provider.Callback(context)
	default:
		http.NotFound(w, r)
	}
}
