package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"math/rand"
)

type CodeVerifier string

type CodeChallenge struct {
	Challenge string `json:"code-challenge"`
	Method    string `json:"code-challenge-method"`
}

func (c CodeChallenge) String() string {
	return c.Challenge
}

const TransformationPlain = "plain"
const TransformationS256 = "S256"

const CodeVerifierLenMin = 43
const CodeVerifierLenMax = 128

const alphabet = "abcdefghijklmnopqrstuvwxuzABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789-._~"

var ErrMismatchedVerifierAndChallenge = errors.New("auth/pkce: challenge is not a transformed verifier")
var ErrInvalidCodeVerifierLen = errors.New("auth/pkce: invalid code verifier len")
var ErrUnsupportedTransformation = errors.New("auth/pkce: unsupported code verifier transformation method")

// todo(n.rodionov): use masking instead of getting the remainder
// todo(n.rodionov): use cryptographically secure pseudorandom number generator
func NewCodeVerifier(length int) (CodeVerifier, error) {
	if length < CodeVerifierLenMin || length > CodeVerifierLenMax {
		return "", ErrInvalidCodeVerifierLen
	}
	c := make([]byte, length)
	for i := range c {
		c[i] = alphabet[rand.Int63()%int64(len(alphabet))]
	}
	return CodeVerifier(c), nil
}

func NewCodeChallenge(v CodeVerifier, t string) (CodeChallenge, error) {
	var transformedCode string
	switch t {
	case TransformationPlain:
		transformedCode = string(v)
	case TransformationS256:
		h := sha256.New()
		h.Write([]byte(v))
		transformedCode = string(h.Sum(nil))
	default:
		return CodeChallenge{}, ErrUnsupportedTransformation
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(transformedCode))
	return CodeChallenge{string(encoded), t}, nil
}

func NewCodeChallengeFromString(s string, t string) (CodeChallenge, error) {
	switch t {
	case TransformationPlain:
	case TransformationS256:
	default:
		return CodeChallenge{}, ErrUnsupportedTransformation

	}
	return CodeChallenge{s, t}, nil
}

func CompareVerifierAndChallenge(v CodeVerifier, c CodeChallenge) error {
	encoded, err := NewCodeChallenge(v, c.Method)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(encoded.Challenge), []byte(c.Challenge)) == 1 {
		return nil
	}
	return ErrMismatchedVerifierAndChallenge
}
