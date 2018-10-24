package storage

import (
	"testing"
)

type testCredentials struct {
	uid string
}

func (c testCredentials) UID() string {
	return c.uid
}

func CRUDCheckRun(t *testing.T, s Storage) {
	providerID := "test"
	err := s.ProviderCreate(providerID)
	if err != nil {
		t.Error("could not register provider, error", err)
	}
	u1 := testCredentials{
		uid: "u1",
	}
	err = s.UserDelete(providerID, u1.UID())
	if err != ErrNotFound {
		t.Errorf("nonexistent user deletion must return '%v', but '%v' was returned", ErrNotFound, err)
	}
	err = s.UserCreate(providerID, u1)
	if err != nil {
		t.Errorf("could not create user, error: '%v'", err)
	}
	err = s.UserCreate(providerID, u1)
	if err != ErrAlreadyExists {
		t.Errorf("created user that already exists")
	}
	u2, err := s.UserRead(providerID, u1.UID())
	if err != nil {
		t.Errorf("could not read existing user, error: '%v'", err)
	}
	if u2.UID() != u1.UID() {
		t.Errorf("created user is not matching the loaded one")
	}
	// todo: write user update tests
	err = s.UserDelete(providerID, u1.UID())
	if err != nil {
		t.Errorf("could not delete user: '%v'", err)
	}
	_, err = s.UserRead(providerID, u1.UID())
	if err != ErrNotFound {
		t.Errorf("'%v' expected, but '%v' was returned", ErrNotFound, err)
	}
	err = s.Close()
	if err != nil {
		t.Errorf("could not close storage, error: '%v'", err)
	}
}
