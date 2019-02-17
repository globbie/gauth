package auth

import (
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"github.com/google/uuid"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func (a *Auth) LoginHandler(w http.ResponseWriter, r *http.Request, p provider.IdentityProvider) {
	authReqID := r.FormValue("req")
	log.Println("authenticate request id:", authReqID)

	authReq, err := a.Storage.AuthRequestRead(authReqID)
	if err != nil { // todo
		log.Printf("getting authentication request '%v' failed, error: %v", authReqID, err)
		http.NotFound(w, r)
		return
	}

	p.Login(w, r, authReq)
}

func (a *Auth) CallbackHandler(w http.ResponseWriter, r *http.Request, p provider.IdentityProvider) {
	authReqID := r.FormValue("state")
	log.Println("authenticate request id:", authReqID)

	authReq, err := a.Storage.AuthRequestRead(authReqID)
	if err != nil { // todo
		log.Printf("getting authentication request '%v' failed, error: %v", authReqID, err)
		http.NotFound(w, r)
		return
	}
	identity, err := p.Callback(w, r, authReq)
	if err != nil {
		aErr := err.(*Error) // todo(n.rodionov): fix
		log.Printf("CallbackHandler[%v] failed: %v", p.Type(), aErr.Message)
		http.Error(w, aErr.PublicMessage, aErr.StatusCode)
		return
	}

	err = a.Storage.AuthRequestUpdate(authReq.ID, func(a storage.AuthRequest) (request storage.AuthRequest, e error) {
		a.Claims.UserEmail = identity.Email
		a.Claims.UserID = identity.UserID
		return a, nil
	})

	u, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid Redirect URI", http.StatusInternalServerError)
		return
	}

	authCodeUUID, err := uuid.NewRandom()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	authCode := storage.AuthCode{
		ID:                  authCodeUUID.String(),
		ClientID:            authReq.ClientID,
		CodeChallenge:       authReq.CodeChallenge,
		CodeChallengeMethod: authReq.CodeChallengeMethod,
		Claims:              authReq.Claims,
	}
	err = a.Storage.AuthCodeCreate(authCode)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	q := u.Query()
	q.Set("code", authCode.ID)
	q.Set("state", authReq.State)
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}

func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	paths := strings.Split(strings.TrimPrefix(r.URL.Path, a.URLPrefix), "/")
	if len(paths) < 2 { // todo
		http.NotFound(w, r)
		return
	}
	action := paths[1]
	providerID := paths[0]
	p, err := a.GetIdentityProvider(providerID)
	if err != nil { // todo
		log.Printf("getting '%v' provider failed, error: %v", providerID, err)
		http.NotFound(w, r)
		return
	}
	log.Println("got a request:", r)

	switch action {
	case "login":
		a.LoginHandler(w, r, p)
	case "callback":
		a.CallbackHandler(w, r, p)
	case "logout":
		fallthrough
	case "register":
		fallthrough
	default:
		log.Println("not found")
		http.NotFound(w, r)
	}
}
