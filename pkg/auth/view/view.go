package view

import (
	"errors"
	"github.com/golang/gddo/httputil/header"
	"net/http"
)

type ContentType string

type ProviderInfo struct {
	Name string
	Url  string
	Type string
}

type View interface {
	// todo: need to pass auth-request id
	Login(http.ResponseWriter, []ProviderInfo) error
}

type Router struct {
	views map[ContentType]View
}

func NewRouter() Router {
	router := Router {
		views: make(map[ContentType]View),
	}
	return router
}

func (r *Router) RegisterContentType(ct ContentType, v View) error {
	return nil
}

func (r *Router) RegisterProvider(p ProviderInfo) error {
	return nil
}

func (r *Router) NegotiateView(specs []header.AcceptSpec) (View, error) {
	for _, spec := range specs {
		view, ok := r.views[ContentType(spec.Value)]
		if !ok {
			continue
		}
		return view, nil
	}
	// todo: set 406 Not Acceptable
	return nil, errors.New("content-type is not found")
}