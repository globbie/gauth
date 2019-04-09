package auth_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/globbie/gauth/pkg/auth"
	"github.com/globbie/gauth/pkg/auth/storage"
	"github.com/globbie/gauth/pkg/auth/storage/memory"
	"github.com/globbie/gauth/pkg/auth/view"
	"github.com/globbie/gauth/pkg/auth/view/json"
	"github.com/globbie/gauth/pkg/repositories/in-memory"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var ath *auth.Auth

func init() {
	signKey, _ := rsa.GenerateKey(rand.Reader, 512)

	storage := memoryStorage.New()

	viewRouter := view.NewRouter()
	viewRouter.RegisterContentType("application/json", &json.View{})

	refreshTokenRepositoryConfig := in_memory.Config{}

	ath, _ = auth.New(nil, signKey, &storage, viewRouter, auth.Config{
		RefreshTokenRepositoryConfig: &refreshTokenRepositoryConfig})
	ath.AddClient(auth.Client{ID: ""}) // to catch lookups for client with an empty ID.
	ath.AddClient(
		auth.Client{
			ID:     "test-client",
			Secret: "test-secret",
			RedirectURIs: []string{
				"http://test-client.com/callback?name1=val1&name%202=val%202",
				"http://test-client.net/callback"},
			PKCE: false})

	//p, _ := vkontakte.Config{
	//	ClientID:     "test-client",
	//	ClientSecret: "test-secret",
	//	RedirectURI:  "http://test-client.net/callback"}.New(&storage, "???")
	//ath.AddIdentityProvider("???", p)
}

type Option func(*http.Request)

func withMethod(method string) Option {
	return func(req *http.Request) { req.Method = method }
}
func withAccept(accept string) Option {
	return func(req *http.Request) { req.Header.Set("Accept", accept) }
}
func withBasicAuth(username, password string) Option {
	return func(req *http.Request) { req.SetBasicAuth(username, password) }
}
func withURLParams(params url.Values) Option {
	return func(req *http.Request) { req.URL.RawQuery = params.Encode() }
}
func withContentParams(params url.Values) Option {
	return func(req *http.Request) {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = ioutil.NopCloser(bytes.NewReader([]byte(params.Encode())))
	}
}

func newAuthRequest(t *testing.T, opts ...Option) *http.Request {
	req, err := http.NewRequest("GET", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Body = ioutil.NopCloser(bytes.NewReader([]byte{}))
	for _, opt := range opts {
		opt(req)
	}

	return req
}

func serveAuthRequest(req *http.Request, t *testing.T) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	ath.AuthorizationHandler().ServeHTTP(rr, req)
	return rr
}

func newTokenRequest(t *testing.T, opts ...Option) *http.Request {
	req, err := http.NewRequest("POST", "/token", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Body = ioutil.NopCloser(bytes.NewReader([]byte{}))
	for _, opt := range opts {
		opt(req)
	}

	return req
}

func serveTokenRequest(req *http.Request, t *testing.T) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	ath.TokenHandler().ServeHTTP(rr, req)
	return rr
}

func TestAuthNoAccept(t *testing.T) {
	req := newAuthRequest(t)

	rr := serveAuthRequest(req, t) // Not Acceptable
	if rr.Code != http.StatusNotAcceptable {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
}

func TestAuthInvalidAccept(t *testing.T) {
	req := newAuthRequest(t, withAccept("image/png"))

	rr := serveAuthRequest(req, t) // 405 method not allowed
	if rr.Code != http.StatusNotAcceptable {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "Not Acceptable\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthInvalidMethod(t *testing.T) {
	for _, method := range []string{"HEAD", "PUT"} {
		req := newAuthRequest(t, withMethod(method), withAccept("application/json"))

		rr := serveAuthRequest(req, t) // 400 http.Request.ParseForm() failed
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("unexpected status code: %v", rr.Code)
		}
		if rr.Body.String() != "method not allowed\n" {
			t.Errorf("unexpected body: %v", rr.Body)
		}
	}
}

func TestAuthNonParsableRequest(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id": {"test-client"},
	}))
	req.URL.RawQuery = req.URL.RawQuery + "%"

	rr := serveAuthRequest(req, t) // 400 http.Request.ParseForm() failed
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "non-parsable request\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthNoClientId(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{}))

	rr := serveAuthRequest(req, t) // 400 client_id is missing or included more than once
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "client_id is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthEmptyClientId(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id": {""},
	}))

	rr := serveAuthRequest(req, t) // 400 client_id is missing or included more than once
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "client_id is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthMultipleClientId(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id": {"test-client", "test-client"},
	}))

	rr := serveAuthRequest(req, t) // 400 client_id is missing or included more than once
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "client_id is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthUnknownClientId(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id": {"unknown-client"},
	}))

	rr := serveAuthRequest(req, t) // 400 client_id not registered
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "client_id is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthMultipleRedirectUri(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id": {"test-client"},
		"redirect_uri": {
			"http://test-client.net/callback",
			"http://test-client.net/callback"},
	}))

	rr := serveAuthRequest(req, t) // 400 redirect_uri is included more than once
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "redirect_uri is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthNonParsableRedirectUri(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id":    {"test-client"},
		"redirect_uri": {"http://test-client.net/callback%"},
	}))

	rr := serveAuthRequest(req, t) // 400 url.QueryUnescape() failed
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "redirect_uri is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthUnknownRedirectUri(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id":    {"test-client"},
		"redirect_uri": {"http://test-client.net/unknown-callback"},
	}))

	rr := serveAuthRequest(req, t) // 400 redirect_uri is mismatched
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "redirect_uri is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthNoRedirectUri(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id": {"test-client"},
	}))

	rr := serveAuthRequest(req, t) // 400 redirect_uri is missing
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "redirect_uri is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthEmptyRedirectUri(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id":    {"test-client"},
		"redirect_uri": {""},
	}))

	rr := serveAuthRequest(req, t) // 400 redirect_uri is missing
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "redirect_uri is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

// TODO(k15tfu): func TestAuthDefaultRedirectUri(t *testing.T) {}

func TestAuthEmptyParam(t *testing.T) {
	params := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://test-client.net/callback"},
		"response_type": {""},
		"state":         {"test-state"}}
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(params))

	rr := serveAuthRequest(req, t) // 302 invalid_request response_type is missing or invalid
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             {"invalid_request"},
		"error_description": {"response_type is missing or invalid"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthUnknownParam(t *testing.T) {
	params := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://test-client.net/callback"},
		"unknown-param": {"1", "2"},
		"state":         {"test-state"}}
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(params))

	rr := serveAuthRequest(req, t) // 302 invalid_request response_type is missing or invalid
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             {"invalid_request"},
		"error_description": {"response_type is missing or invalid"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthDuplicateParams(t *testing.T) {
	params := url.Values{
		"client_id":    {"test-client"},
		"redirect_uri": {"http://test-client.net/callback"},
		"state":        {"1", "2"}}
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(params))

	rr := serveAuthRequest(req, t) // 302 invalid_request duplicate parameters found
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             {"invalid_request"},
		"error_description": {"duplicate parameters found"},
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthNoResponseType(t *testing.T) {
	params := url.Values{
		"client_id":    {"test-client"},
		"redirect_uri": {"http://test-client.net/callback"},
		"state":        {"test-state"}}
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(params))

	rr := serveAuthRequest(req, t) // 302 invalid_request duplicate parameters found
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             {"invalid_request"},
		"error_description": {"response_type is missing or invalid"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthUnknownResponseType(t *testing.T) {
	params := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://test-client.net/callback"},
		"response_type": {"unknown-type"},
		"state":         {"test-state"}}
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(params))

	rr := serveAuthRequest(req, t) // 302 invalid_request duplicate parameters found
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             {"invalid_request"},
		"error_description": {"response_type is missing or invalid"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthUnsupportedResponseType(t *testing.T) {
	params := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://test-client.net/callback"},
		"response_type": {"token"},
		"state":         {"test-state"}}
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(params))

	rr := serveAuthRequest(req, t) // 302 invalid_request duplicate parameters found
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             {"unsupported_response_type"},
		"error_description": {"response_type not supported"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthSuccess(t *testing.T) {
	req := newAuthRequest(t, withAccept("application/json"), withURLParams(url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://test-client.net/callback"},
		"response_type": {"code"},
		"state":         {"test-state"},
	}))

	rr := serveAuthRequest(req, t)
	if rr.Code != http.StatusOK {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	//t.Errorf("unexpected body: %v", rr.Body)
}

func TestTokenInvalidMethod(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "PUT"} {
		req := newTokenRequest(t)
		req.Method = method

		rr := serveTokenRequest(req, t) // 400 invalid_request method not allowed
		if rr.Code != http.StatusBadRequest {
			t.Errorf("unexpected status code: %v", rr.Code)
		}
		if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidRequest, "method not allowed")+"\n" {
			t.Errorf("unexpected body: %v", rr.Body)
		}
	}
}

func TestTokenNoBasicAuth(t *testing.T) {
	req := newTokenRequest(t)

	rr := serveTokenRequest(req, t) // 401 invalid_client Authorization is missing or invalid
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") != "Basic" {
		t.Errorf("unexpected WWW-Authenticate: %v", rr.Header().Get("WWW-Authenticate"))
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidClient, "auth is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenBasicAuthNoClientId(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("", ""))

	rr := serveTokenRequest(req, t) // 401 invalid_client Authorization is missing or invalid
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") != "Basic" {
		t.Errorf("unexpected WWW-Authenticate: %v", rr.Header().Get("WWW-Authenticate"))
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidClient, "auth is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

// func TestTokenBasicAuthNonParsableClientId(t *testing.T) {} // ??

func TestTokenBasicAuthUnknownClientId(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("unknown-client", ""))

	rr := serveTokenRequest(req, t) // 401 invalid_client client_id not registered
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") != "Basic" {
		t.Errorf("unexpected WWW-Authenticate: %v", rr.Header().Get("WWW-Authenticate"))
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidClient, "auth is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenBasicAuthNoClientSecret(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", ""))

	rr := serveTokenRequest(req, t) // 400 invalid_request http.Request.ParseForm() failed
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidRequest, "non-parsable request")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

// func TestTokenBasicAuthNonParsableClientSecret(t *testing.T) {} // ??

func TestTokenNonParsableRequest(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", ""), withContentParams(url.Values{
		"grant_type": {""},
	}))
	req.Body = ioutil.NopCloser(io.MultiReader(req.Body, bytes.NewReader([]byte("%"))))

	rr := serveTokenRequest(req, t) // 400 invalid_request http.Request.ParseForm() failed
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidRequest, "non-parsable request")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenEmptyParam(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"grant_type": {""},
	}))

	rr := serveTokenRequest(req, t) // 400 invalid_request grant_type is missing or invalid
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidRequest, "grant_type is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenUnknownParam(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"unknown-param": {"1", "2"},
	}))

	rr := serveTokenRequest(req, t) // 400 invalid_request grant_type is missing or invalid
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidRequest, "grant_type is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenDuplicateParams(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"code": {"1", "2"},
	}))

	rr := serveTokenRequest(req, t) // 400 invalid_request duplicate parameters found
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidRequest, "'code' parameter is included more than once")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenNoGrantType(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"code": {"1"},
	}))

	rr := serveTokenRequest(req, t) // 400 invalid_request grant_type is missing or invalid
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidRequest, "grant_type is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenUnknownGrantType(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"grant_type": {"unknown-grant"},
	}))

	rr := serveTokenRequest(req, t) // 400 invalid_request grant_type is missing or invalid
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidRequest, "grant_type is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenUnsupportedGrantType(t *testing.T) {
	for _, grant_type := range []string{"password", "client_credentials"} {
		req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
			"grant_type": {grant_type},
		}))

		rr := serveTokenRequest(req, t) // 400 invalid_request grant_type is missing or invalid
		if rr.Code != http.StatusBadRequest {
			t.Errorf("unexpected status code: %v", rr.Code)
		}
		if rr.Body.String() != auth.ErrorContent(auth.ErrTknUnsupportedGrantType, "grant_type not supported")+"\n" {
			t.Errorf("unexpected body: %v", rr.Body)
		}
	}
}

func TestTokenAuthCodeInvalidClientSecret(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", "invalid-secret"), withContentParams(url.Values{
		"grant_type": {"authorization_code"},
	}))

	rr := serveTokenRequest(req, t) // 401 invalid_client client_secret is mismatched
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") != "Basic" {
		t.Errorf("unexpected WWW-Authenticate: %v", rr.Header().Get("WWW-Authenticate"))
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidClient, "auth is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenAuthCodeNoCode(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"grant_type": {"authorization_code"},
	}))

	rr := serveTokenRequest(req, t) // 400 invalid_request code is missing or invalid
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidRequest, "code is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenAuthCodeInvalidCode(t *testing.T) {
	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"invalid-code"},
	}))

	rr := serveTokenRequest(req, t) // 400 invalid_grant storage.Storage.AuthCodeRead() failed
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidGrant, "code is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenAuthCodeInvalidCodeOwner(t *testing.T) {
	ath.Storage.AuthCodeCreate(storage.AuthCode{ID: "test-code", ClientID: "another-client"})
	defer func() { ath.Storage.AuthCodeDelete("test-code") }()

	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"test-code"},
	}))

	rr := serveTokenRequest(req, t) // 400 invalid_grant authCode.ClientID is mismatched
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidGrant, "code is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenAuthCodeNoClientId(t *testing.T) {
	ath.Storage.AuthCodeCreate(storage.AuthCode{ID: "test-code", ClientID: "test-client"})
	defer func() { ath.Storage.AuthCodeDelete("test-code") }()

	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"test-code"},
	}))

	rr := serveTokenRequest(req, t)
	if rr.Code != http.StatusOK {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "access_token") {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenAuthCodeInvalidClientId(t *testing.T) {
	ath.Storage.AuthCodeCreate(storage.AuthCode{ID: "test-code", ClientID: "test-client"})
	defer func() { ath.Storage.AuthCodeDelete("test-code") }()

	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"test-code"},
		"client_id":  {"another-client"},
	}))

	rr := serveTokenRequest(req, t) // 400 invalid_grant clientID is mismatched
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != auth.ErrorContent(auth.ErrTknInvalidGrant, "clientID is missing or invalid")+"\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestTokenAuthCodeSuccess(t *testing.T) {
	ath.Storage.AuthCodeCreate(storage.AuthCode{ID: "test-code", ClientID: "test-client"})
	defer func() { ath.Storage.AuthCodeDelete("test-code") }()

	req := newTokenRequest(t, withBasicAuth("test-client", "test-secret"), withContentParams(url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"test-code"},
		"client_id":  {"test-client"},
	}))

	rr := serveTokenRequest(req, t)
	if rr.Code != http.StatusOK {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "access_token") {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}
