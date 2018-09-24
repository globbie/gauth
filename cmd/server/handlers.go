package main

import (
	"fmt"
	//"github.com/globbie/gnode/cmd/server/encryptionSchemes"
	"log"
	"net/http"
)

func logger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL.Path, r.URL.Query(), r.RemoteAddr, r.UserAgent())
		h.ServeHTTP(w, r)
	})
}

func secretHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello, user with valid token!")
	})
}
