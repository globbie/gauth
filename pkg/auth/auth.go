package auth

import (
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/globbie/gauth/pkg/auth/provider"
	"github.com/globbie/gauth/pkg/auth/storage"
	"github.com/globbie/gauth/pkg/auth/view"
	"github.com/golang/gddo/httputil/header"
	"github.com/google/uuid"
	"log"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
	PKCE         bool
}

type Config struct {
	RefreshTokenRepositoryConfig
}

type Auth struct {
	URLPrefix string

	idProviders map[string]provider.IdentityProvider
	clients     map[string]*Client

	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey

	Storage storage.Storage

	RefreshTokenRepository

	ViewRouter view.Router
}

// todo(n.rodionov): move parameters into config
func New(verifyKey *rsa.PublicKey, signKey *rsa.PrivateKey, storage storage.Storage, vr view.Router, c Config) (*Auth, error) {
	refreshTokenRepository, err := c.RefreshTokenRepositoryConfig.New()
	if err != nil {
		return nil, err
	}
	auth := &Auth{
		idProviders:            make(map[string]provider.IdentityProvider),
		clients:                make(map[string]*Client),
		VerifyKey:              verifyKey,
		SignKey:                signKey,
		Storage:                storage,
		ViewRouter:             vr,
		RefreshTokenRepository: refreshTokenRepository,
	}
	return auth, nil
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
			log.Printf("406 Accept is missing or invalid, accept: %v", r.Header.Get("Accept"))
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

// todo(n.rodionov): break this structure on to code -> token & refresh token -> token request structures
type AccessTokenRequestParams struct {
	// OAuth2.0 request parameters
	GrantType string

	// access token request parameters
	AuthCodeID  string
	RedirectURI string
	ClientID    string

	// refreshing access token parameters
	RefreshToken string
	Scope        string // not implemented

	// PKCE request parameters
	CodeVerifier string
}

func accessTokenRequestParamsNew(form url.Values) (result AccessTokenRequestParams, err error) {
	// todo(n.rodionov): may be reflection could help to avoid repeated checks
	if values, ok := form["grant_type"]; ok {
		if len(values) != 1 {
			return result, errors.New("'grant_type' parameter is included more than once")
		}
		result.GrantType = values[0]
	}
	if values, ok := form["code"]; ok {
		if len(values) != 1 {
			err = errors.New("'code' parameter is included more than once")
			return
		}
		result.AuthCodeID = values[0]
	}
	if values, ok := form["redirect_uri"]; ok {
		if len(values) != 1 {
			err = errors.New("'redirect_uri' parameter is included more than once")
			return
		}
		result.RedirectURI = values[0]
	}
	if values, ok := form["client_id"]; ok {
		if len(values) != 1 {
			err = errors.New("'client_id' parameter is included more than once")
			return
		}
		result.ClientID = values[0]
	}
	if values, ok := form["code_verifier"]; ok {
		if len(values) != 1 {
			err = errors.New("'code_verifier' parameter is included more than once")
			return
		}
		result.CodeVerifier = values[0]
	}
	if values, ok := form["refresh_token"]; ok {
		if len(values) != 1 {
			err = errors.New("'refresh_token' parameter is included more than once")
			return
		}
		result.RefreshToken = values[0]
	}
	return
}

func (a *Auth) clientAuthenticate(w http.ResponseWriter, r *http.Request, params AccessTokenRequestParams) (storage.AuthCode, error) {
	var (
		authCode storage.AuthCode
		err      error
	)

	clientID, clientSecret, ok := r.BasicAuth()
	clientID, _ = url.QueryUnescape(clientID) // TODO(k15tfu): ?? done implicitly
	if clientSecret != "" { // client_secret can be an empty string
		if clientSecret, err = url.QueryUnescape(clientSecret); err != nil { // TODO(k15tfu): ?? done implicitly
			ok = false
		}
	}
	if !ok || clientID == "" {
		w.Header().Set("WWW-Authenticate", "Basic")
		http.Error(w, ErrorContent(ErrTknInvalidClient, "auth is missing or invalid"), http.StatusUnauthorized)
		log.Printf("401 invalid_client Authorization is missing or invalid, auth: %v", r.Header.Get("Authorization"))
		return authCode, errors.New("authentication failed")
	}
	client, ok := a.clients[clientID]
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic")
		http.Error(w, ErrorContent(ErrTknInvalidClient, "auth is missing or invalid"), http.StatusUnauthorized)
		log.Printf("401 invalid_client client_id not registered, client_id: %v", clientID)
		return authCode, errors.New("authentication failed")
	}

	if !client.PKCE && subtle.ConstantTimeCompare([]byte(client.Secret), []byte(clientSecret)) != 1 {
		w.Header().Set("WWW-Authenticate", "Basic")
		http.Error(w, ErrorContent(ErrTknInvalidClient, "auth is missing or invalid"), http.StatusUnauthorized)
		log.Printf("401 invalid_client client_secret is mismatched, clientID: %v", clientID)
		return authCode, errors.New("authentication failed")
	}

	authCode, err = a.Storage.AuthCodeRead(params.AuthCodeID)
	if err != nil {
		http.Error(w, ErrorContent(ErrTknInvalidGrant, "code is missing or invalid"), http.StatusBadRequest)
		log.Printf("400 invalid_grant storage.Storage.AuthCodeRead() failed, err: %v", err)
		return authCode, err
	}
	if authCode.ClientID != client.ID {
		http.Error(w, ErrorContent(ErrTknInvalidGrant, "code is missing or invalid"), http.StatusBadRequest)
		log.Printf("400 invalid_grant authCode.ClientID is mismatched, authCode.ClientID: %v client.ID: %v", authCode.ClientID, client.ID)
		return authCode, errors.New("authentication failed")
	}

	if params.ClientID == "" {
		// clientID is required only if for unauthenticated client (See 3.2.1.)
	} else if params.ClientID != client.ID {
		// TODO(k15tfu): ?? invalid_grant or invalid_client or invalid_request
		http.Error(w, ErrorContent(ErrTknInvalidGrant, "clientID is missing or invalid"), http.StatusBadRequest)
		log.Printf("400 invalid_grant clientID is mismatched, clientID: %v client.ID: %v", params.ClientID, client.ID)
		return authCode, errors.New("authentication failed")
	}

	if client.PKCE {
		codeVerifier := params.CodeVerifier
		if codeVerifier == "" {
			http.Error(w, ErrorContent(ErrTknInvalidGrant, "code_verifier is missing or invalid"), http.StatusBadRequest) // FIXME(k15tfu): ?? invalid_grant or invalid_request
			log.Printf("400 invalid_grant code_verifier is missing or invalid, form: %v", r.PostForm)
			return authCode, errors.New("authentication failed")
		}
		codeChallenge, err := NewCodeChallengeFromString(codeVerifier, authCode.CodeChallengeMethod)
		if err == ErrUnsupportedTransformation {
			http.Error(w, ErrorContent(ErrTknInvalidGrant, "code_challenge_method not supported"), http.StatusBadRequest)
			log.Printf("400 invalid_grant code_challenge_method not supported, code_challenge_method: %v", authCode.CodeChallengeMethod)
			return authCode, errors.New("authentication failed")
		}
		err = CompareVerifierAndChallenge(CodeVerifier(codeVerifier), codeChallenge)
		if err != nil {
			http.Error(w, ErrorContent(ErrTknInvalidGrant, "code_verifier is missing or invalid"), http.StatusBadRequest)
			log.Printf("400 invalid_grant code_verifier is mismatched, clientID: %v", clientID)
			return authCode, errors.New("authentication failed")
		}
	}
	return authCode, nil
}

// TODO(k15tfu):
//   The endpoint URI MAY include an "application/x-www-form-urlencoded"
//   formatted (per Appendix B) query component ([RFC3986] Section 3.4),
//   which MUST be retained when adding additional query parameters.  The
//   endpoint URI MUST NOT include a fragment component.

// TODO(k15tfu):
//   Since requests to the token endpoint result in the transmission of
//   clear-text credentials (in the HTTP request and response), the
//   authorization server MUST require the use of TLS as described in
//   Section 1.6 when sending requests to the token endpoint.

// TODO(k15tfu):
//   Since this client authentication method involves a password, the
//   authorization server MUST protect any endpoint utilizing it against
//   brute force attacks.
func (a *Auth) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, ErrorContent(ErrTknInvalidRequest, "method not allowed"), http.StatusBadRequest)
			log.Printf("400 invalid_request method not allowed, method: %v", r.Method)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, ErrorContent(ErrTknInvalidRequest, "non-parsable request"), http.StatusBadRequest)
			log.Printf("400 invalid_request http.Request.ParseForm() failed, err: %v", err)
			return
		}

		params, err := accessTokenRequestParamsNew(r.Form)
		if err != nil {
			http.Error(w, ErrorContent(ErrInvalidRequest, err.Error()), http.StatusBadRequest)
			log.Printf("400 invalid_request accessTokenRequestParamsNew() failed, err: %v", err)
			return
		}
		authCode, err := a.clientAuthenticate(w, r, params)
		if err != nil {
			return // error has already been reported
		}

		switch params.GrantType {
		case "authorization_code":
			a.handleAuthorizationCode(w, r, authCode, params)
		case "refresh_token":
			a.handleRefreshToken(w, r, authCode, params)
		default:
			http.Error(w, ErrorContent(ErrTknUnsupportedGrantType, "unsupported grant type"), http.StatusBadRequest)
			log.Println("unrecognized grant_type:", params.GrantType)
			return
		}
	})
}

func (a *Auth) handleAuthorizationCode(w http.ResponseWriter, r *http.Request, authCode storage.AuthCode, params AccessTokenRequestParams) {
	a.issueToken(w, r, authCode, params)
}

func (a *Auth) handleRefreshToken(w http.ResponseWriter, r *http.Request, authCode storage.AuthCode, params AccessTokenRequestParams) {
	refreshToken, err := a.RefreshTokenRepository.Read(params.RefreshToken)
	if err == ErrNotFound {
		http.Error(w, "Not Found", http.StatusNotFound)
		log.Println("refresh token was not found")
		return
	} else if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("RefreshTokenRepository.Read() failed, error:", err)
		return
	}

	if refreshToken.ClientID != authCode.ClientID {
		http.Error(w, ErrorContent(ErrTknInvalidClient, "invalid client"), http.StatusBadRequest)
		log.Printf("400 invalid_grant authCode.ClientID is mismatched, authCode.ClientID: %v client.ID: %v", refreshToken.ClientID, authCode.ClientID)
		return
	}

	a.issueToken(w, r, authCode, params)

	err = a.RefreshTokenRepository.Delete(params.RefreshToken)
	if err != nil {
		log.Println("could not delete refresh token")
		return
	}
}

func (a *Auth) issueToken(w http.ResponseWriter, r *http.Request, authCode storage.AuthCode, params AccessTokenRequestParams) {
	token, err := CreateToken(authCode.Claims, a.SignKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("auth.CreateToken() failed, err:", err)
		return
	}
	refreshToken := RefreshToken{
		Token:     NewRandomID(),
		CreatedAt: time.Now(),
		ClientID:  params.ClientID,
	}

	err = a.RefreshTokenRepository.Create(refreshToken)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("failed to store refresh token, err:", err)
		return
	}

	resp := struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token, omitempty"`
		ExpiresIn    int
	}{
		AccessToken:  token,
		TokenType:    "Bearer",
		RefreshToken: refreshToken.Token,
		ExpiresIn:    3600, // todo
	}

	data, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Println("json.Marshal() failed, err:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(data)
	if err != nil {
		log.Println("w.Write() failed, err:", err)
	}
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
