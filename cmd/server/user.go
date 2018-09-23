package main

import "errors"

// tmp struct before Knowdy be linked
type User struct {
	cred Credentials
}

var users map[string]*User

func createUser(cred Credentials) error {
	_, ok := users[cred.Email]
	if ok {
		return errors.New("user already exists")
	}
	return nil
}
