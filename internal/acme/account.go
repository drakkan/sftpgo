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
