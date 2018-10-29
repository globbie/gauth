package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"path/filepath"
	//"github.com/globbie/gnode/cmd/server/encryptionSchemes"
	"log"
	"net/http"
)

const (
	loginTemplate = "login.html"
)

type ProviderInfo struct {
	Name string
	Url  string
}

type frontendHandler struct {
	login *template.Template

	providers []ProviderInfo
}

func NewFrontedHandler(dir string) *frontendHandler {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalf("could not read templates directory '%v', err: %v", dir, err)
	}
	var fileNames []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fileNames = append(fileNames, filepath.Join(dir, file.Name()))
	}
	if len(fileNames) == 0 {
		log.Fatalf("no templates were found in '%v'", dir)
	}
	templates, err := template.ParseFiles(fileNames...)
	if err != nil {
		log.Fatalln("could not parse files, err:", err)
	}

	login := templates.Lookup(loginTemplate)
	if login == nil {
		log.Fatalln("could not find login template")
	}
	return &frontendHandler{
		login: login,
	}
}

func (f *frontendHandler) RegisterProvider(info ProviderInfo) error {
	f.providers = append(f.providers, info)
	return nil
}

func (f *frontendHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Providers []ProviderInfo
	}{
		f.providers,
	}
	f.login.Execute(w, data)
}

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
