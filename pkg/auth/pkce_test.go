package auth

import (
	"log"
	"testing"
)

func TestNewCodeVerifier(t *testing.T) {
	// test if it is possible to create code verifier shorter than minimum (43)
	// https://tools.ietf.org/html/rfc7636#section-4.1
	_, err := NewCodeVerifier(42)
	if err != ErrInvalidCodeVerifierLen {
		t.Error("too short code verifier was created")
	}
	// test if it is possible to create code verifier longer than minimum (128)
	// https://tools.ietf.org/html/rfc7636#section-4.1
	_, err = NewCodeVerifier(129)
	if err != ErrInvalidCodeVerifierLen {
		t.Error("too long code verifier was created")
	}
	// test if it is possible to create code verifier with correct len
	_, err = NewCodeVerifier(CodeVerifierLenMin)
	if err != nil {
		t.Error("failed to create code verifier")
	}
	_, err = NewCodeVerifier(CodeVerifierLenMax)
	if err != nil {
		t.Error("failed to create code verifier")
	}
}

func TestNewCodeChallenge(t *testing.T) {
	v, err := NewCodeVerifier(CodeVerifierLenMax)
	if err != nil {
		t.Error("failed to create code verifier")
	}
	// check if not supported case is handled
	transformation := "not supported"
	_, err = NewCodeChallenge(v, transformation)
	if err != ErrUnsupportedTransformation {
		t.Error("code challenge with unsupported transformation method was created")
	}
	// check supported transformation methods
	transformations := []string{TransformationPlain, TransformationS256}
	for i := range transformations {
		_, err := NewCodeChallenge(v, transformations[i])
		if err != nil {
			t.Error("failed to create code challenge")
		}
	}
}

func TestCompareVerifierAndChallenge(t *testing.T) {
	v, err := NewCodeVerifier(CodeVerifierLenMax)
	if err != nil {
		t.Error("could not create new code verifier, error:", err)
	}
	transformations := []string{TransformationPlain, TransformationS256}
	for i := range transformations {
		c, err := NewCodeChallenge(v, transformations[i])
		if err != nil {
			t.Error("could not create new code challenge, error:", err)
		}
		log.Println(c.Challenge)
		err = CompareVerifierAndChallenge(v, c)
		if err != nil {
			t.Error("code verifier and challenge comparison failed, error:", err)
		}
	}
}
