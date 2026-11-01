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

package dataprovider

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/xrogers/gonas/v2/internal/util"
)

const (
	// MaxPasskeys is the maximum number of passkeys for an account
	MaxPasskeys = 20
	// MaxPasskeyNameLength is the maximum length of the name of a passkey
	MaxPasskeyNameLength = 64
)

// Passkey is a WebAuthn credential registered for an account. It holds a public key, so
// unlike the TOTP secret it does not need to be encrypted.
type Passkey struct {
	ID              []byte   `json:"id"`
	Name            string   `json:"name"`
	PublicKey       []byte   `json:"public_key"`
	RPID            string   `json:"rp_id"`
	AttestationType string   `json:"attestation_type,omitempty"`
	Transports      []string `json:"transports,omitempty"`
	AAGUID          []byte   `json:"aaguid,omitempty"`
	SignCount       uint32   `json:"sign_count,omitempty"`
	BackupEligible  bool     `json:"backup_eligible,omitempty"`
	BackupState     bool     `json:"backup_state,omitempty"`
	CreatedAt       int64    `json:"created_at"`
}

func copyPasskeys(passkeys []Passkey) []Passkey {
	if len(passkeys) == 0 {
		return nil
	}
	result := make([]Passkey, 0, len(passkeys))
	for _, p := range passkeys {
		p.ID = slices.Clone(p.ID)
		p.PublicKey = slices.Clone(p.PublicKey)
		p.Transports = slices.Clone(p.Transports)
		p.AAGUID = slices.Clone(p.AAGUID)
		result = append(result, p)
	}
	return result
}

func validatePasskeys(passkeys []Passkey) error {
	if len(passkeys) > MaxPasskeys {
		return util.NewValidationError(fmt.Sprintf("too many passkeys, the maximum is %d", MaxPasskeys))
	}
	for idx, p := range passkeys {
		if len(p.ID) == 0 || len(p.PublicKey) == 0 {
			return util.NewValidationError(fmt.Sprintf("passkey %d is not valid", idx))
		}
		name := strings.TrimSpace(p.Name)
		if name == "" || len(name) > MaxPasskeyNameLength {
			return util.NewValidationError(fmt.Sprintf("passkey %d has an invalid name", idx))
		}
		for _, other := range passkeys[:idx] {
			if bytes.Equal(other.ID, p.ID) {
				return util.NewValidationError(fmt.Sprintf("passkey %q is duplicated", p.Name))
			}
		}
	}
	return nil
}

// HasPasskeys returns true if the user has at least a passkey
func (u *User) HasPasskeys() bool {
	return len(u.Filters.Passkeys) > 0
}

// HasPasskeys returns true if the admin has at least a passkey
func (a *Admin) HasPasskeys() bool {
	return len(a.Filters.Passkeys) > 0
}
