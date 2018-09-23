package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

type Token struct {
	Token string `json:"token"`
}

type Credentials struct {
	Email             string
	EncryptedPassword []byte
}

func logger(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL.Path, r.URL.Query(), r.RemoteAddr, r.UserAgent())
		h.ServeHTTP(w, r)
	})
}

func auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
			return VerifyKey, nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		log.Println("welcome:", token.Claims)
		h.ServeHTTP(w, r)
	})
}

func registerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authInfo := &Credentials{}

		email := r.URL.Query().Get("email")
		if email == "" {
			http.Error(w, "email is not set", http.StatusBadRequest)
			return
		}
		password := r.URL.Query().Get("password")
		if password == "" {
			http.Error(w, "password is not set", http.StatusBadRequest)
			return
		}
		encryptedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		authInfo.Email = email
		authInfo.EncryptedPassword = encryptedPassword

		users[email] = authInfo

		signer := jwt.New(jwt.GetSigningMethod("RS256"))
		claims := make(jwt.MapClaims)
		claims["sub"] = email
		claims["exp"] = time.Now().Add(time.Minute * 20).Unix()
		claims["CustomUserInfo"] = struct {
			email string
		}{email}
		signer.Claims = claims

		token, err := signer.SignedString(SignKey)
		if err != nil {
			log.Println("failed to create token", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		response, err := json.Marshal(Token{token})
		if err != nil {
			http.Error(w, "intertal server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	})
}

func loginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
}

func secretHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello, user with valid token!")
	})
}
