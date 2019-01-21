package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"github.com/dgrijalva/jwt-go"
	"github.com/globbie/gauth/pkg/auth"
	"github.com/globbie/gauth/pkg/auth/view"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

var (
	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey
	cfg       Config
)

func init() {
	var configPath string
	flag.StringVar(&configPath, "config-path", "config.json", "path to config file")
	flag.Parse()

	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalln("could not open config file, error:", err)
	}
	err = json.Unmarshal(configData, &cfg)
	if err != nil {
		log.Fatalf("could not parse config file '%s', error: %v", configPath, err)
	}
	signBytes, err := ioutil.ReadFile(cfg.Token.PublicKeyPath)
	if err != nil {
		log.Fatalln("could not open SignKey file:", err)
	}
	SignKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		log.Fatalln(err)
	}
	verifyBytes, err := ioutil.ReadFile(cfg.Token.PrivateKeyPath)
	if err != nil {
		log.Fatalln("could not open VerifyKey file:", err)
	}
	VerifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	storage, err := cfg.Storage.Config.New()
	if err != nil {
		log.Fatalln("could not create storage, error:", err)
	}

	vRouter := view.NewRouter()

	Auth := auth.New(VerifyKey, SignKey, storage, vRouter)
	Auth.URLPrefix = "/auth/" // todo

	for _, cView := range cfg.Views {
		v, err := cView.Config.New(cView.ContentType)
		if err != nil {
			log.Fatalf("could not create view %v, error: %v", cView, err)
		}
		vRouter.RegisterContentType(view.ContentType(cView.ContentType), v)
	}

	for _, p := range cfg.Providers {
		provider, err := p.Config.New(storage, p.ID)
		if err != nil {
			log.Fatalf("could not create provider %v, error: %v", p, err)
		}
		Auth.AddIdentityProvider(p.ID, provider)
	}
	for _, c := range cfg.Clients {
		client := auth.Client{
			ID:           c.ID,
			Secret:       c.Secret,
			RedirectURIs: c.RedirectURIs,
			PKCE:         c.PKCE,
		}
		Auth.AddClient(client)
	}

	router := http.NewServeMux()
	// todo: refactor handlers
	router.Handle("/auth", Auth.AuthorizationHandler()) // oauth2 authorization endpoint
	router.Handle("/auth/", Auth)
	router.Handle("/token", Auth.TokenHandler())                    // oauth2 token endpoint
	router.Handle("/secret", Auth.ResourceHandler(secretHandler())) // oauth2 resource "server"

	//router.Handle("/", staticView)

	server := &http.Server{
		Addr:         cfg.Web.HTTPAddress,
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

	log.Println("server is ready to handle requests at:", cfg.Web.HTTPAddress)

	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("could not listen on %s, err: %v\n", server.Addr, err)
	}

	<-done
	log.Println("server stopped")
}
