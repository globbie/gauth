package auth

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/golang/gddo/httputil/header"

	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"github.com/globbie/gauth/pkg/auth/view"

	"github.com/google/uuid"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
	PKCE         bool
}

type Auth struct {
	URLPrefix string

	idProviders map[string]provider.IdentityProvider
	clients     map[string]*Client

	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey

	Storage    storage.Storage
	ViewRouter view.Router
}

// todo: delete this factory
func New(verifyKey *rsa.PublicKey, signKey *rsa.PrivateKey, storage storage.Storage, vr view.Router) *Auth {
	auth := &Auth{
		idProviders: make(map[string]provider.IdentityProvider),
		clients:     make(map[string]*Client),
		VerifyKey:   verifyKey,
		SignKey:     signKey,
		Storage:     storage,
		ViewRouter:  vr,
	}
	return auth
}

func (a *Auth) AddClient(client Client) {
	_, ok := a.clients[client.ID]
	if ok {
		log.Fatalf("client %v is already registered", client.ID)
	}
	a.clients[client.ID] = &client
}

func (a *Auth) GetIdentityProvider(name string) (provider.IdentityProvider, error) {
	p, ok := a.idProviders[name]
	if !ok {
		return nil, errors.New("provider not found")
	}
	return p, nil
}

func (a *Auth) AddIdentityProvider(id string, provider provider.IdentityProvider) {
	_, ok := a.idProviders[id]
	if ok {
		log.Fatalf("provider '%v' is already registered", id)
	}
	a.idProviders[id] = provider
}

func (a *Auth) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 4.1.3.  Access Token Request
		// https://tools.ietf.org/html/rfc6749#section-4.1.3
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			log.Println("r.BasicAuth() failed")
			return
		}
		var err error
		if clientID, err = url.QueryUnescape(clientID); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			log.Println("QueryUnescape(clientID) failed, err:", err)
			return
		}
		if clientSecret, err = url.QueryUnescape(clientSecret); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			log.Println("QueryUnescape(clientSecret) failed, err:", err)
			return
		}
		client, ok := a.clients[clientID]
		if !ok {
			http.Error(w, "Not Found", http.StatusNotFound)
			log.Printf("client not found: '%s'", clientID)
			return
		}

		code := r.PostFormValue("code")

		authCode, err := a.Storage.AuthCodeRead(code)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			log.Println("failed to get auth code")
			return
		}

		if client.PKCE {
			codeVerifier := r.PostFormValue("code_verifier")
			if codeVerifier == "" {
				http.Error(w, "invalid_grant", http.StatusBadRequest) // todo
				log.Println("missing code_verifier")
				return
			}
			codeChallenge, err := NewCodeChallengeFromString(codeVerifier, authCode.CodeChallengeMethod)
			if err == ErrUnsupportedTransformation {
				http.Error(w, "invalid_grant", http.StatusBadRequest) // todo
				log.Println("unknown code challenge method")
				return
			}
			err = CompareVerifierAndChallenge(CodeVerifier(codeVerifier), codeChallenge)
			if err != nil {
				http.Error(w, "invalid_grant", http.StatusBadRequest) // todo
				log.Println("invalid code verifier")
				return
			}
		} else {
			if client.Secret != clientSecret {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				log.Printf("clientSecret mismatch: '%s' != '%s'", client.Secret, clientSecret)
				return
			}
		}

		grantType := r.PostFormValue("grant_type") // todo: add refresh token
		if grantType != "authorization_code" {     // todo: fix hardcoded value
			http.Error(w, "Bad Request", http.StatusBadRequest)
			log.Println("grant_type is not set")
			return
		}

		_ = r.PostFormValue("redirect_uri") // todo

		err = a.Storage.AuthCodeDelete(code)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			log.Println("failed to delete auth code")
			return
		}

		// 4.1.4.  Access Token Response
		// https://tools.ietf.org/html/rfc6749#section-4.1.4

		jwt, err := CreateToken("hardcoded string", a.SignKey) // todo: fix hardcode
		if err != nil {
			log.Println("failed to create token", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp := struct {
			AccessToken  string `json:"access_token"`
			TokenType    string `json:"token_type"`
			RefreshToken string `json:"refresh_token,omitempty"`
			ExpiresIn    int    `json:"expires_in"`
		}{
			AccessToken:  jwt,
			TokenType:    "Bearer",
			RefreshToken: "",   // todo
			ExpiresIn:    3600, // todo
		}
		data, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	})
}

func uniqueParameter(name string, form url.Values) (string, bool) {
	vals, ok := form[name]
	if ok && len(vals) == 1 {
		return vals[0], true
	}
	return "", !ok // true if not specified, false if included more than once
}

func filterParameters(allowedNames []string, form url.Values) (map[string]string, bool) {
	// Parameters sent without a value MUST be treated as if they were
	// omitted from the request.  The authorization server MUST ignore
	// unrecognized request parameters.  Request and response parameters
	// MUST NOT be included more than once.
	result := make(map[string]string)
	success := true
	for _, name := range allowedNames {
		if vals, ok := form[name]; ok {
			if len(vals) != 1 {
				success = false
				// `name` is included more than once, but continue processing to return all valid parameters
			} else if vals[0] != "" {
				result[name] = vals[0]
			}
		}
	}
	return result, success
}

func (a *Auth) validateAuthorizationRequest(w http.ResponseWriter, r *http.Request) map[string]string {
	//
	// At this point, we have to send errors directly to resource owner:
	//

	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		log.Printf("405 method not allowed, method: %v", r.Method)
		return nil
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "non-parsable request", http.StatusBadRequest)
		log.Printf("400 http.Request.ParseForm() failed, err: %v", err)
		return nil
	}

	clientID, ok := uniqueParameter("client_id", r.Form)
	if !ok || clientID == "" {
		http.Error(w, "client_id is missing or invalid", http.StatusBadRequest)
		log.Printf("400 client_id is missing or included more than once, form: %v", r.Form["client_id"])
		return nil
	}
	client := a.clients[clientID]
	if client == nil {
		http.Error(w, "client_id is missing or invalid", http.StatusBadRequest)
		log.Printf("400 client_id not registered, client_id: %v", clientID)
		return nil
	}

	redirectURI, ok := uniqueParameter("redirect_uri", r.Form)
	if !ok {
		http.Error(w, "redirect_uri is missing or invalid", http.StatusBadRequest)
		log.Printf("400 redirect_uri is included more than once, form: %v", r.Form["redirect_uri"])
		return nil
	}
	if redirectURI != "" {
		var err error
		redirectURI, err = url.QueryUnescape(redirectURI) // TODO(k15tfu): is it really required?
		if err != nil {
			http.Error(w, "redirect_uri is missing or invalid", http.StatusBadRequest)
			log.Printf("400 url.QueryUnescape() failed, err: %v", err)
			return nil
		}

		exists := false
		for _, uri := range client.RedirectURIs {
			if redirectURI == uri {
				exists = true
			}
		}
		if !exists {
			http.Error(w, "redirect_uri is missing or invalid", http.StatusBadRequest)
			log.Printf("400 redirect_uri is mismatched, cliend_id: %v redirect_uri: %v", clientID, redirectURI)
			return nil
		}
	} else {
		if len(client.RedirectURIs) != 1 {
			http.Error(w, "redirect_uri is missing or invalid", http.StatusBadRequest)
			log.Printf("400 redirect_uri is missing, client_id: %v", clientID)
			return nil
		}

		// TODO(k15tfu): What does it mean?
		//   [...], if only part of the redirection URI has been registered, or
		//   [...], the client MUST include a redirection URI with the
		//   authorization request using the "redirect_uri" request parameter
		redirectURI = client.RedirectURIs[0]
	}

	//
	// From this point, we have to send errors by redirecting to `redirectURI`:
	//

	allowedNames := []string{
		// OAuth2.0 request parameters:
		"response_type", "client_id", "redirect_uri", "scope", "state",
		// PKCE request parameters:
		"code_challenge", "code_challenge_method",
	}
	params, ok := filterParameters(allowedNames, r.Form)
	if !ok {
		http.Redirect(w, r, ErrorURL(redirectURI, ErrInvalidRequest, "duplicate parameters found", params["state"]), http.StatusFound)
		log.Printf("302 invalid_request duplicate parameters found, form: %v", r.Form)
		return nil
	}

	// TODO(k15tfu): ?? require state

	// OAuth2.0:
	switch params["response_type"] {
	case "code":
		break
	case "token":
		http.Redirect(w, r, ErrorURL(redirectURI, ErrUnsupportedResponseType, "response_type not supported", params["state"]), http.StatusFound)
		log.Printf("302 unsupported_response_type response_type not supported, response_type: %v", params["response_type"])
		return nil
	default:
		http.Redirect(w, r, ErrorURL(redirectURI, ErrInvalidRequest, "response_type is missing or invalid", params["state"]), http.StatusFound)
		log.Printf("302 invalid_request response_type is missing or invalid, form: %v", r.Form)
		return nil
	}

	// PKCE:
	if client.PKCE && params["response_type"] == "code" {
		if _, ok := params["code_challenge"]; !ok {
			http.Redirect(w, r, ErrorURL(redirectURI, ErrInvalidRequest, "code_challenge is missing", params["state"]), http.StatusFound)
			log.Printf("302 invalid_request code_challenge is missing, form: %v", r.Form)
			return nil
		}
		if _, ok := params["code_challenge_method"]; !ok {
			http.Redirect(w, r, ErrorURL(redirectURI, ErrInvalidRequest, "code_challenge_method is missing", params["state"]), http.StatusFound)
			log.Printf("302 invalid_request code_challenge_method is missing, form: %v", r.Form)
			return nil
		}
	} else { // Otherwise, ignore these parameters.
		delete(params, "code_challenge")
		delete(params, "code_challenge_method")
	}

	// Set actual redirect_uri because it may be empty.
	params["redirect_uri"] = redirectURI

	return params

	// TODO(k15tfu):
	//   The redirection endpoint URI MUST be an absolute URI as defined by
	//   [RFC3986] Section 4.3.  The endpoint URI MAY include an
	//   "application/x-www-form-urlencoded" formatted (per Appendix B) query
	//   component ([RFC3986] Section 3.4), which MUST be retained when adding
	//   additional query parameters.  The endpoint URI MUST NOT include a
	//   fragment component.

	// TODO(k15tfu):
	//   If an authorization request fails validation due to a missing,
	//   invalid, or mismatching redirection URI, the authorization server
	//   SHOULD inform the resource owner of the error and MUST NOT
	//   automatically redirect the user-agent to the invalid redirection URI.
	//redirectURI, err := url.Parse(r.Form.Get("redirect_uri"))
	//if err != nil {
	//	err = errors.New("bad request") // todo
	//	return
	//}
	//if !redirectURI.IsAbs() || redirectURI.Fragment == "" {
	//	err = errors.New("bad request") // todo
	//	return
	//}
}

// only authorization code grant flow for now
func (a *Auth) AuthorizationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		specs := header.ParseAccept(r.Header, "Accept")
		v, err := a.ViewRouter.NegotiateView(specs)
		if err != nil {
			http.Error(w, "Not Acceptable", http.StatusNotAcceptable)
			return
		}

		// TODO(k15tfu):
		//   The endpoint URI MAY include an "application/x-www-form-urlencoded"
		//   formatted (per Appendix B) query component ([RFC3986] Section 3.4),
		//   which MUST be retained when adding additional query parameters.  The
		//   endpoint URI MUST NOT include a fragment component.

		// TODO(k15tfu):
		//   Since requests to the authorization endpoint result in user
		//   authentication and the transmission of clear-text credentials (in the
		//   HTTP response), the authorization server MUST require the use of TLS
		//   as described in Section 1.6 when sending requests to the
		//   authorization endpoint.

		// TODO(k15tfu):
		//   If TLS is not available, the authorization server
		//   SHOULD warn the resource owner about the insecure endpoint prior to
		//   redirection (e.g., display a message during the authorization
		//   request).

		params := a.validateAuthorizationRequest(w, r)
		if params == nil {
			return // error is already reported
		}
		redirectURI, state := params["redirect_uri"], params["state"]

		reqID, err := uuid.NewRandom()
		if err != nil {
			http.Redirect(w, r, ErrorURL(redirectURI, ErrServerError, "", state), http.StatusFound)
			log.Printf("302 server_error uuid.NewRandom() failed, err: %v", err)
			return
		}

		authReq := storage.AuthRequest{
			ID:                  reqID.String(),
			ClientID:            params["client_id"],
			RedirectURI:         params["redirect_uri"],
			State:               params["state"],
			ResponseType:        params["response_type"],
			CodeChallenge:       params["code_challenge"],
			CodeChallengeMethod: params["code_challenge_method"],
		}

		err = a.Storage.AuthRequestCreate(authReq)
		if err != nil {
			http.Redirect(w, r, ErrorURL(redirectURI, ErrServerError, "", state), http.StatusFound)
			log.Printf("302 server_error storage.Storage.AuthRequestCreate() failed, err: %v", err)
			return
		}
		providersInfo := make([]view.ProviderInfo, 0, len(a.idProviders))
		for name, p := range a.idProviders {
			providersInfo = append(providersInfo, view.ProviderInfo{
				Name: name,
				Url:  "/auth/" + name + "/login" + "?req=" + authReq.ID,
				Type: p.Type(),
			})
		}
		err = v.Login(w, providersInfo)
		if err != nil {
			http.Redirect(w, r, ErrorURL(redirectURI, ErrServerError, "", state), http.StatusFound)
			log.Printf("302 server_error view.View.Login() failed, err: %v", err)
			return
		}
	})
}

// todo: change handler name
func (a *Auth) ResourceHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
			return a.VerifyKey, nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		log.Println("welcome:", token.Claims)
		h.ServeHTTP(w, r)
	})
}
