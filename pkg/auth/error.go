package auth

import (
	"encoding/json"
	"net/url"
)

type Error struct {
	StatusCode    int
	Message       string
	PublicMessage string
}

func (e Error) Error() string {
	return e.Message
}

const (
	ErrInvalidRequest          = "invalid_request"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrAccessDenied            = "access_denied"
	ErrUnsupportedResponseType = "unsupported_response_type"
	ErrInvalidScope            = "invalid_scope"
	ErrServerError             = "server_error"
	ErrTemporarilyUnavailable  = "temporarily_unavailable"
	ErrInternalServerError     = "internal_error"
)

func ErrorURL(source, code, desc, state string) string {
	u, _ := url.Parse(source)
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	// TODO(k15tfu): error_uri
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

const (
	ErrTknInvalidRequest       = "invalid_request"
	ErrTknInvalidClient        = "invalid_client"
	ErrTknInvalidGrant         = "invalid_grant"
	ErrTknUnauthorizedClient   = "unauthorized_client"
	ErrTknUnsupportedGrantType = "unsupported_grant_type"
	ErrTknInvalidScope         = "invalid_scope"
)

func ErrorContent(code, desc string) string {
	e := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
		ErrorURI         string `json:"error_uri,omitempty"`
	}{
		Error:            code,
		ErrorDescription: desc,
	}
	s, _ := json.Marshal(e)
	return string(s)
}
