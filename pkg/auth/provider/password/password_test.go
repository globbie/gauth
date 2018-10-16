package password

import (
	"github.com/globbie/gnode/pkg/auth/ctx"
	//"github.com/globbie/gnode/pkg/auth/storage/knowdy"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRegister(t *testing.T) {
	//storage, err := knowdyStorage.New("")
	//if err != nil {
	//	t.Error("could not create storage:", err)
	//}
	//defer storage.Close()

	provider := NewProvider(nil)

	form := url.Values{
		"login": {"test@example.com"},
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
			W:w,
			R:r,
			SignKey: nil,
			VerifyKey: nil,
		}
		provider.Register(&c)
	})
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("user register returned %v status code", status)
	}
}
