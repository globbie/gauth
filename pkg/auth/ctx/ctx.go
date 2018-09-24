package ctx

import (
	"crypto/rsa"
	"net/http"
)

type Ctx struct {
	W http.ResponseWriter
	R *http.Request

	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey
}
