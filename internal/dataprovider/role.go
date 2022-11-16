// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package dataprovider

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

// Role defines an SFTPGo role.
type Role struct {
	// Data provider unique identifier
	ID int64 `json:"id"`
	// Role name
	Name string `json:"name"`
	// optional description
	Description string `json:"description,omitempty"`
	// Creation time as unix timestamp in milliseconds
	CreatedAt int64 `json:"created_at"`
	// last update time as unix timestamp in milliseconds
	UpdatedAt int64 `json:"updated_at"`
	// list of admins associated with this role
	Admins []string `json:"admins,omitempty"`
	// list of usernames associated with this role
	Users []string `json:"users,omitempty"`
}

// RenderAsJSON implements the renderer interface used within plugins
func (r *Role) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		role, err := provider.roleExists(r.Name)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload role before rendering as json: %v", err)
			return nil, err
		}
		return json.Marshal(role)
	}
	return json.Marshal(r)
}

func (r *Role) validate() error {
	if r.Name == "" {
		return util.NewValidationError("name is mandatory")
	}
	if config.NamingRules&1 == 0 && !usernameRegex.MatchString(r.Name) {
		return util.NewValidationError(fmt.Sprintf("name %q is not valid, the following characters are allowed: a-zA-Z0-9-_.~", r.Name))
	}
	return nil
}

func (r *Role) getACopy() Role {
	users := make([]string, len(r.Users))
	copy(users, r.Users)
	admins := make([]string, len(r.Admins))
	copy(admins, r.Admins)

	return Role{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
		Users:       users,
		Admins:      admins,
	}
}

// GetMembersAsString returns a string representation for the role members
func (r *Role) GetMembersAsString() string {
	var sb strings.Builder
	if len(r.Users) > 0 {
		sb.WriteString(fmt.Sprintf("Users: %d. ", len(r.Users)))
	}
	if len(r.Admins) > 0 {
		sb.WriteString(fmt.Sprintf("Admins: %d. ", len(r.Admins)))
	}
	return sb.String()
}
