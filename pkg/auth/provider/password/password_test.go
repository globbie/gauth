package password

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/globbie/gnode/pkg/auth/ctx"
	"github.com/globbie/gnode/pkg/auth/storage/memory"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func getKeysPair(t *testing.T) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	bytes, err := ioutil.ReadFile("testdata/example.rsa")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(bytes)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err = ioutil.ReadFile("testdata/example.rsa.pub")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestRegister(t *testing.T) {
	storage := memoryStorage.New()
	defer storage.Close()
	privateKey, publicKey := getKeysPair(t)

	provider := NewProvider(nil)

	form := url.Values{
		"login":    {"test@example.com"},
		"password": {"password"},
	}
	req, err := http.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	if err != nil {
		t.Error("could not create register request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := ctx.Ctx{
			W:         w,
			R:         r,
			SignKey:   privateKey,
			VerifyKey: publicKey,
		}
		provider.Register(&c)
	})
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("user register returned %v status code", status)
	}
}
