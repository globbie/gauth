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
	err = s.UserCreate(u1)
	if err != nil {
		t.Errorf("could not create user, error: '%v'", err)
	}
	err = s.UserCreate(u1)
	if err != ErrAlreadyExists {
		t.Errorf("created user that already exists")
	}
	u2, err := s.UserRead(u1.UID)
	if err != nil {
		t.Errorf("could not read existing user, error: '%v'", err)
	}
	if u2.UID != u1.UID {
		t.Errorf("created user is not matching the loaded one")
	}
	// todo: write user update tests
	err = s.UserDelete(u1.UID)
	if err != nil {
		t.Errorf("could not delete user: '%v'", err)
	}
	_, err = s.UserRead(u1.UID)
	if err != ErrNotFound {
		t.Errorf("'%v' expected, but '%v' was returned", ErrNotFound, err)
	}
	err = s.Close()
	if err != nil {
		t.Errorf("could not close storage, error: '%v'", err)
	}
}
