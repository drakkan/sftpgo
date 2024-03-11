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
	"errors"
	"fmt"
)

// SessionType defines the supported session types
type SessionType int

// Supported session types
const (
	SessionTypeOIDCAuth SessionType = iota + 1
	SessionTypeOIDCToken
	SessionTypeResetCode
	SessionTypeOAuth2Auth
	SessionTypeInvalidToken
	SessionTypeWebTask
)

// Session defines a shared session persisted in the data provider
type Session struct {
	Key       string
	Data      any
	Type      SessionType
	Timestamp int64
}

func (s *Session) validate() error {
	if s.Key == "" {
		return errors.New("unable to save a session with an empty key")
	}
	if s.Type < SessionTypeOIDCAuth || s.Type > SessionTypeWebTask {
		return fmt.Errorf("invalid session type: %v", s.Type)
	}
	return nil
}
