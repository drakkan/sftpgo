package acme

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

type account struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

/** Implementation of the registration.User interface **/

// GetEmail returns the email address for the account.
func (a *account) GetEmail() string {
	return a.Email
}

// GetRegistration returns the server registration.
func (a *account) GetRegistration() *registration.Resource {
	return a.Registration
}

// GetPrivateKey returns the private account key.
func (a *account) GetPrivateKey() crypto.PrivateKey {
	return a.key
}

/** End **/
