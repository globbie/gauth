package auth

import "net/url"

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
