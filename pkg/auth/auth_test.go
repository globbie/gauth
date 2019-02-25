package auth

import (
	"github.com/globbie/gauth/pkg/auth/storage/memory"
	"github.com/globbie/gauth/pkg/auth/view"
	"github.com/globbie/gauth/pkg/auth/view/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

var auth *Auth

func init() {
	storage := memoryStorage.New()

	viewRouter := view.NewRouter()
	viewRouter.RegisterContentType("application/json", &json.View{})

	auth = New(nil, nil, &storage, viewRouter)
	auth.AddClient(Client{ID: ""}) // to catch lookups for client with an empty ID.
	auth.AddClient(
		Client{
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
	//auth.AddIdentityProvider("???", p)
}

func newAuthRequest(t *testing.T /*, method, accept string, params url.Values*/) *http.Request {
	req, err := http.NewRequest("GET", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func serveAuthRequest(req *http.Request, t *testing.T) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	auth.AuthorizationHandler().ServeHTTP(rr, req)
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
	req := newAuthRequest(t)
	req.Header.Set("Accept", "image/png")

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
		req := newAuthRequest(t)
		req.Header.Set("Accept", "application/json")
		req.Method = method

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
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{"client_id": []string{"test-client"}}
	req.URL.RawQuery = params.Encode() + "%"

	rr := serveAuthRequest(req, t) // 400 http.Request.ParseForm() failed
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "non-parsable request\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthNoClientId(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 400 client_id is missing or included more than once
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "client_id is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthEmptyClientId(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{"client_id": []string{""}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 400 client_id is missing or included more than once
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "client_id is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthMultipleClientId(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{"client_id": []string{"test-client", "test-client"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 400 client_id is missing or included more than once
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "client_id is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthUnknownClientId(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{"client_id": []string{"unknown-client"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 400 client_id not registered
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "client_id is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthMultipleRedirectUri(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id": []string{"test-client"},
		"redirect_uri": []string{
			"http://test-client.net/callback",
			"http://test-client.net/callback"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 400 redirect_uri is included more than once
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "redirect_uri is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthNonParsableRedirectUri(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id":    []string{"test-client"},
		"redirect_uri": []string{"http://test-client.net/callback%"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 400 url.QueryUnescape() failed
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "redirect_uri is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthUnknownRedirectUri(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id":    []string{"test-client"},
		"redirect_uri": []string{"http://test-client.net/unknown-callback"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 400 redirect_uri is mismatched
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "redirect_uri is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthNoRedirectUri(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{"client_id": []string{"test-client"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 400 redirect_uri is missing
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	if rr.Body.String() != "redirect_uri is missing or invalid\n" {
		t.Errorf("unexpected body: %v", rr.Body)
	}
}

func TestAuthEmptyRedirectUri(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{"client_id": []string{"test-client"}, "redirect_uri": []string{""}}
	req.URL.RawQuery = params.Encode()

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
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id":     []string{"test-client"},
		"redirect_uri":  []string{"http://test-client.net/callback"},
		"response_type": []string{""},
		"state":         []string{"test-state"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 302 invalid_request response_type is missing or invalid
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             []string{"invalid_request"},
		"error_description": []string{"response_type is missing or invalid"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthUnknownParam(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id":     []string{"test-client"},
		"redirect_uri":  []string{"http://test-client.net/callback"},
		"unknown-param": []string{"1", "2"},
		"state":         []string{"test-state"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 302 invalid_request response_type is missing or invalid
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             []string{"invalid_request"},
		"error_description": []string{"response_type is missing or invalid"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthDuplicateParams(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id":    []string{"test-client"},
		"redirect_uri": []string{"http://test-client.net/callback"},
		"state":        []string{"1", "2"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 302 invalid_request duplicate parameters found
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             []string{"invalid_request"},
		"error_description": []string{"duplicate parameters found"},
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthNoResponseType(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id":    []string{"test-client"},
		"redirect_uri": []string{"http://test-client.net/callback"},
		"state":        []string{"test-state"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 302 invalid_request duplicate parameters found
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             []string{"invalid_request"},
		"error_description": []string{"response_type is missing or invalid"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthUnknownResponseType(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id":     []string{"test-client"},
		"redirect_uri":  []string{"http://test-client.net/callback"},
		"response_type": []string{"unknown-type"},
		"state":         []string{"test-state"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 302 invalid_request duplicate parameters found
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             []string{"invalid_request"},
		"error_description": []string{"response_type is missing or invalid"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthUnsupportedResponseType(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id":     []string{"test-client"},
		"redirect_uri":  []string{"http://test-client.net/callback"},
		"response_type": []string{"token"},
		"state":         []string{"test-state"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t) // 302 invalid_request duplicate parameters found
	if rr.Code != http.StatusFound {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	location := params["redirect_uri"][0] + "?" + url.Values{
		"error":             []string{"unsupported_response_type"},
		"error_description": []string{"response_type not supported"},
		"state":             params["state"],
	}.Encode()
	if rr.Header().Get("Location") != location {
		t.Errorf("unexpected location: %v", rr.Header().Get("Location"))
	}
}

func TestAuthSuccess(t *testing.T) {
	req := newAuthRequest(t)
	req.Header.Set("Accept", "application/json")
	params := url.Values{
		"client_id":     []string{"test-client"},
		"redirect_uri":  []string{"http://test-client.net/callback"},
		"response_type": []string{"code"},
		"state":         []string{"test-state"}}
	req.URL.RawQuery = params.Encode()

	rr := serveAuthRequest(req, t)
	if rr.Code != http.StatusOK {
		t.Errorf("unexpected status code: %v", rr.Code)
	}
	//t.Errorf("unexpected body: %v", rr.Body)
}
