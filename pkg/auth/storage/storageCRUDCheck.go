package storage

import (
	"testing"
)

func CRUDCheckRun(t *testing.T, s Storage) {
	u1 := UserCredentials{
		UID: "u1",
	}
	err := s.UserDelete(u1.UID)
	if err != ErrNotFound {
		t.Errorf("nonexistent user deletion must return '%v', but '%v' was returned", ErrNotFound, err)
	}
	err = s.UserCreate(&u1)
	if err != nil {
		t.Errorf("could not create user, error: '%v'", err)
	}
	err = s.UserCreate(&u1)
	if err != ErrAlreadyExists {
		t.Errorf("created user that already exists")
	}
}
