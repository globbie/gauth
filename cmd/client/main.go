package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

type Config struct {
	Address               string `json:"http"`
	ClientID              string `json:"client-id"`
	ClientSecret          string `json:"client-secret"`
	RedirectURI           string `json:"redirect-uri"`
	AuthorizationEndpoint string `json:"authorization-endpoint"`
	TokenEndpoint         string `json:"token-endpoint"`
	WWWDir                string `json:"www-dir"`
}

const (
	authorizationURL = "/auth"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config-path", "config.json", "path to the config file")
	flag.Parse()

	config := configOpen(configPath)

	oauthConfig := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthorizationEndpoint,
			TokenURL: config.TokenEndpoint,
		},
		RedirectURL: config.RedirectURI,
	}

	router := http.NewServeMux()
	router.Handle(authorizationURL, authHandler(oauthConfig))
	router.Handle("/callback", authCallbackHandler(oauthConfig))
	//router.Handle("/restricted_area", auth("todo"))
	router.Handle("/", templateHandlerNew(filepath.Join(config.WWWDir, "templates"), authorizationURL))
	server := &http.Server{
		Addr:         config.Address,
		Handler:      logger(router),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	go func() {
		<-quit
		log.Println("shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalln("could not gracefully shutdown the server:", server.Addr)
		}
		close(done)
	}()

	log.Println("server is ready to handle requests at:", server.Addr)
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("could not listen on %s, err: %v\n", server.Addr, err)
	}
	<-done
	log.Println("server stopped")
}

func configOpen(configPath string) Config {
	var config Config
	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalln("could not open config file, error:", err)
	}
	if err = json.Unmarshal(configData, &config); err != nil {
		log.Fatalf("could not prase config file '%s', error: %v", configPath, err)
	}
	return config
}

func logger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL.Path, r.URL.Query(), r.RemoteAddr, r.UserAgent())
		h.ServeHTTP(w, r)
	})
}

const (
	indexTemplate = "index.html"
)

type templateHandler struct {
	index            *template.Template
	authorizationURL string
}

func templateHandlerNew(dir string, authorizationURL string) *templateHandler {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalf("could not read template directory '%v', error: %v", dir, err)
	}
	var fileNames []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fileNames = append(fileNames, filepath.Join(dir, file.Name()))
	}
	if len(fileNames) == 0 {
		log.Fatalf("no templates found in '%v'", dir)
	}
	templates, err := template.ParseFiles(fileNames...)
	if err != nil {
		log.Fatalln("could not parse files, error:", err)
	}
	index := templates.Lookup(indexTemplate)
	if index == nil {
		log.Fatalln("could not find one of base templates")
	}
	return &templateHandler{
		index:            index,
		authorizationURL: authorizationURL,
	}
}

func (t *templateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := struct {
		URL template.URL
	}{
		template.URL(t.authorizationURL), // todo: this should be auth url of this service
	}
	t.index.Execute(w, data)
}

func authHandler(config oauth2.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// fixme: state is hardcoded
		url := config.AuthCodeURL("state", oauth2.AccessTypeOnline)
		http.Redirect(w, r, url, http.StatusFound)
	})
}

func authCallbackHandler(config oauth2.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// fixme: state is hardcoded
		state := r.FormValue("state")
		if state != "state" {
			log.Printf("oauth state does not match '%v', got '%v'", "state", state)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		}
		code := r.FormValue("code")
		token, err := config.Exchange(context.TODO(), code)
		if err != nil {
			log.Printf("failed to get token, error: '%v'", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		log.Println("got token:", token)
		_, _ = fmt.Fprintf(w, "%s", token.AccessToken)
	})
}
