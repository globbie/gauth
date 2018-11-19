package auth

import (
	"log"
	"net/http"
	"strings"
)

type serveMux struct {
	*Auth
}



// todo: here lies a common part of all connectors. state, code etc..
func (mux *serveMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	paths := strings.Split(strings.TrimPrefix(r.URL.Path, mux.URLPrefix), "/")
	if len(paths) < 2 { // todo
		http.NotFound(w, r)
		return
	}

	providerID := paths[0]
	action := paths[1]

	authReqID := r.FormValue("req")
	log.Println("authenticate request id:", authReqID)

	var err error
	provider, err := mux.GetIdentityProvider(providerID)
	if err != nil { // todo
		http.NotFound(w, r)
		return
	}
	authReq, err := mux.Storage.AuthRequestRead(authReqID)
	if err != nil { // todo
		http.NotFound(w, r)
		return
	}
	// todo: move keys out from context and create token here

	switch action {
	case "login":
		provider.Login(w, r, authReq)
	case "logout":
		provider.Logout(w, r, authReq)
	case "register":
		provider.Register(w, r, authReq)
	case "callback":
		provider.Callback(w, r, authReq)
	default:
		http.NotFound(w, r)
	}

	// todo: move keys out from context and create token here
}
