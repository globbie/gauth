package auth

import "net/http"

type ProviderInfo struct {
	Name string
	Url  string
	Type string
}

type View interface {
	Login(http.ResponseWriter, []ProviderInfo) error
}
