package main

import (
	"context"

	"github.com/davecgh/go-spew/spew"
	"github.com/volatiletech/authboss/v3"
)

// User struct for authboss
type User struct {
	ID int

	// Non-authboss related field
	Name string
	Role string

	// Auth
	Email    string
	Password string
}

// This pattern is useful in real code to ensure that
// we've got the right interfaces implemented.
var (
	assertUser   = &User{}
	assertStorer = &MemStorer{}

	_ authboss.User         = assertUser
	_ authboss.AuthableUser = assertUser

	_ authboss.CreatingServerStorer    = assertStorer
	_ authboss.RememberingServerStorer = assertStorer
)

// PutPID into user
func (u *User) PutPID(pid string) { u.Email = pid }

// PutPassword into user
func (u *User) PutPassword(password string) { u.Password = password }

// GetPID from user
func (u User) GetPID() string { return u.Email }

// GetPassword from user
func (u User) GetPassword() string { return u.Password }

// MemStorer stores users in memory
type MemStorer struct {
	Users  map[string]User
	Tokens map[string][]string
}

// NewMemStorer constructor
func NewMemStorer() *MemStorer {
	return &MemStorer{
		Users: map[string]User{
			"admin@test.com": {
				ID:       1,
				Name:     "Admin",
				Password: "$2a$10$XtW/BrS5HeYIuOCXYe8DFuInetDMdaarMUJEOg/VA/JAIDgw3l4aG", // pass = 1234
				Email:    "admin@test.com",
				Role:     "admin",
			},
		},
		Tokens: make(map[string][]string),
	}
}

// Save the user
func (m MemStorer) Save(_ context.Context, user authboss.User) error {
	u := user.(*User)
	m.Users[u.Email] = *u
	return nil
}

// Load the user
func (m MemStorer) Load(_ context.Context, key string) (user authboss.User, err error) {

	u, ok := m.Users[key]
	if !ok {
		return nil, authboss.ErrUserNotFound
	}
	return &u, nil
}

// New user creation
func (m MemStorer) New(_ context.Context) authboss.User {
	return &User{Role: "user"}
}

// Create the user
func (m MemStorer) Create(_ context.Context, user authboss.User) error {
	u := user.(*User)

	if _, ok := m.Users[u.Email]; ok {
		return authboss.ErrUserFound
	}

	m.Users[u.Email] = *u
	return nil
}

// AddRememberToken to a user
func (m MemStorer) AddRememberToken(_ context.Context, pid, token string) error {
	m.Tokens[pid] = append(m.Tokens[pid], token)
	spew.Dump(m.Tokens)
	return nil
}

// DelRememberTokens removes all tokens for the given pid
func (m MemStorer) DelRememberTokens(_ context.Context, pid string) error {
	delete(m.Tokens, pid)
	spew.Dump(m.Tokens)
	return nil
}

// UseRememberToken finds the pid-token pair and deletes it.
// If the token could not be found return ErrTokenNotFound
func (m MemStorer) UseRememberToken(_ context.Context, pid, token string) error {
	tokens, ok := m.Tokens[pid]
	if !ok {
		return authboss.ErrTokenNotFound
	}

	for i, tok := range tokens {
		if tok == token {
			tokens[len(tokens)-1] = tokens[i]
			m.Tokens[pid] = tokens[:len(tokens)-1]
			return nil
		}
	}

	return authboss.ErrTokenNotFound
}
