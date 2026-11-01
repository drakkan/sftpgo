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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePasskeys(t *testing.T) {
	valid := Passkey{ID: []byte("a"), Name: "laptop", PublicKey: []byte("key")}
	assert.NoError(t, validatePasskeys([]Passkey{valid}))
	assert.NoError(t, validatePasskeys(nil))

	noKey := valid
	noKey.PublicKey = nil
	assert.Error(t, validatePasskeys([]Passkey{noKey}))
	noName := valid
	noName.Name = "  "
	assert.Error(t, validatePasskeys([]Passkey{noName}))
	longName := valid
	longName.Name = strings.Repeat("a", MaxPasskeyNameLength+1)
	assert.Error(t, validatePasskeys([]Passkey{longName}))
	assert.Error(t, validatePasskeys([]Passkey{valid, valid}))
	assert.Error(t, validatePasskeys(make([]Passkey, MaxPasskeys+1)))
}

func TestCopiesKeepPasskeys(t *testing.T) {
	user := User{}
	user.Filters.Passkeys = []Passkey{{ID: []byte("a"), Name: "laptop", PublicKey: []byte("key")}}
	userCopy := user.getACopy()
	assert.Equal(t, user.Filters.Passkeys, userCopy.Filters.Passkeys)
	userCopy.Filters.Passkeys[0].ID[0] = 'b'
	assert.Equal(t, byte('a'), user.Filters.Passkeys[0].ID[0], "a copy must not share memory")

	admin := Admin{}
	admin.Filters.Passkeys = user.Filters.Passkeys
	adminCopy := admin.getACopy()
	assert.Equal(t, admin.Filters.Passkeys, adminCopy.Filters.Passkeys)
}
