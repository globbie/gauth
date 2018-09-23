package main

import (
	"context"
	"crypto/rsa"
	"flag"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

var (
	listenAddr string
	users      map[string]*Credentials
	VerifyKey  *rsa.PublicKey
	SignKey    *rsa.PrivateKey
)

func init() {
	var verifyKeyPath, signedKeyPath string
	var err error

	flag.StringVar(&listenAddr, "listen-addr", "0.0.0.0:8081", "server listen address")
	flag.StringVar(&verifyKeyPath, "public-key-path", "", "verify key path")
	flag.StringVar(&signedKeyPath, "signed-key-path", "", "signed key path")
	flag.Parse()

	verifyBytes, err := ioutil.ReadFile(verifyKeyPath)
	if err != nil {
		log.Fatalln("could not open VerifyKey file:", err)
	}
	signBytes, err := ioutil.ReadFile(signedKeyPath)
	if err != nil {
		log.Fatalln("could not open SignKey file:", err)
	}
	SignKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		log.Fatalln(err)
	}
	VerifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Fatalln(err)
	}

	users = make(map[string]*Credentials)
}

func main() {
	router := http.NewServeMux()

	router.Handle("/register", registerHandler())
	router.Handle("/login", loginHandler())
	router.Handle("/secret", auth(secretHandler()))

	server := &http.Server{
		Addr:         listenAddr,
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

	log.Println("server is ready to handle request at:", listenAddr)

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("could not listen on %s, err: %v\n", server.Addr, err)
	}

	<-done
	log.Println("server stopped")
}
