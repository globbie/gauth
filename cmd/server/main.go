package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"github.com/dgrijalva/jwt-go"
	"github.com/globbie/gnode/pkg/auth"
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
		log.Fatalln("could not open config file,", err)
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
	for i, p := range cfg.Providers {
		log.Printf("provider[%v]: %v\n", i, p.Type)
	}
	Auth := auth.New(VerifyKey, SignKey, storage)
	Auth.URLPrefix = "/auth/" // todo

	router := http.NewServeMux()
	router.Handle("/auth/", Auth.NewServeMux())
	router.Handle("/secret", Auth.AuthHandler(secretHandler()))

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
