// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package acme

import (
	"crypto"

	"github.com/go-acme/lego/v5/acme"
)

type account struct {
	Email        string               `json:"email"`
	Registration *accountRegistration `json:"registration"`
	key          crypto.Signer
}

// accountRegistration is the stored form of the ACME account registration.
// Every SFTPGo version reads this JSON layout, so it must stay stable.
type accountRegistration struct {
	Body acme.Account `json:"body"`
	URI  string       `json:"uri,omitempty"`
}

func newAccountRegistration(reg *acme.ExtendedAccount) *accountRegistration {
	if reg == nil {
		return nil
	}
	return &accountRegistration{
		Body: reg.Account,
		URI:  reg.Location,
	}
}

/** Implementation of the registration.User interface **/

// GetEmail returns the email address for the account.
func (a *account) GetEmail() string {
	return a.Email
}

// GetRegistration returns the server registration.
func (a *account) GetRegistration() *acme.ExtendedAccount {
	if a.Registration == nil {
		return nil
	}
	return &acme.ExtendedAccount{
		Account:  a.Registration.Body,
		Location: a.Registration.URI,
	}
}

// GetPrivateKey returns the private account key.
func (a *account) GetPrivateKey() crypto.Signer {
	return a.key
}

/** End **/
