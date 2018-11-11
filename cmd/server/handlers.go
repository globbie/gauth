package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"net/http"
)

const (
	indexTemplate = "index.html"
	loginTemplate = "login.html"
	registerTemplate = "register.html"
)

type ProviderInfo struct {
	Name string
	Url  string
}

type view struct {
	ViewConfig

	static   http.Handler

	index     *template.Template
	login     *template.Template
	register  *template.Template
	notFound  *template.Template

	providers []ProviderInfo
}

type ViewConfig struct {
	staticPath    string
	templatesPath string
}

func NewFrontedHandler(c ViewConfig) *view {
	static := http.StripPrefix("/static/", http.FileServer(http.Dir(c.staticPath)))
	v := view{
		ViewConfig: c,
		static: static,
	}
	v.loadTemplates()
	return &v
}

func (v *view) loadTemplates(){
	files, err := ioutil.ReadDir(v.templatesPath)
	if err != nil {
		log.Fatalf("could not read templates c.templatesPathectory '%v', err: %v", v.templatesPath, err)
	}

	var fileNames []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fileNames = append(fileNames, filepath.Join(v.templatesPath, file.Name()))
	}
	if len(fileNames) == 0 {
		log.Fatalf("no templates were found in '%v'", v.templatesPath)
	}
	templates, err := template.ParseFiles(fileNames...)
	if err != nil {
		log.Fatalln("could not parse files, err:", err)
	}

	v.index = templates.Lookup(indexTemplate)
	if v.index == nil {
		log.Fatalln("could not find index template")
	}
	v.login = templates.Lookup(loginTemplate)
	if v.login == nil {
		log.Fatalln("could not find login template")
	}
	v.register = templates.Lookup(registerTemplate)
	if v.register == nil {
		log.Fatalln("could not find register template")
	}
}


func (v *view) RegisterProvider(info ProviderInfo) error {
	v.providers = append(v.providers, info)
	return nil
}

func (v *view) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	paths := strings.Split(r.URL.Path,"/")
	log.Println("path:", r.URL.Path)
	log.Println("view call:", paths, len(paths))

	// fixme: magic number. SplitAfter?
	switch paths[1] {
	case "":
		data := struct {
			Providers []ProviderInfo
		}{
			v.providers,
		}
		v.index.Execute(w, data)
	case "login":
		data := struct {
			Providers []ProviderInfo
		}{
			v.providers,
		}
		v.login.Execute(w, data)
	case "register":
		data := struct {
			Providers []ProviderInfo
		}{
			v.providers,
		}
		v.register.Execute(w, data)
	case "static":
		log.Println("pass through file server")
		v.static.ServeHTTP(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
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
