package ctx

import (
	"crypto/rsa"
	"github.com/globbie/gnode/pkg/auth/storage"
	"net/http"
)

type Ctx struct {
	W http.ResponseWriter
	R *http.Request

	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey

	storage   *storage.Storage
}
