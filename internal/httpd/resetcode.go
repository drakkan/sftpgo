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

package httpd

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	resetCodeLifespan = 10 * time.Minute
	resetCodesMgr     resetCodeManager
)

type resetCodeManager interface {
	Add(code *resetCode) error
	Get(code string) (*resetCode, error)
	Delete(code string) error
	Cleanup()
}

func newResetCodeManager(isShared int) resetCodeManager {
	if isShared == 1 {
		logger.Info(logSender, "", "using provider reset code manager")
		return &dbResetCodeManager{}
	}
	logger.Info(logSender, "", "using memory reset code manager")
	return &memoryResetCodeManager{}
}

type resetCode struct {
	Code      string    `json:"code"`
	Username  string    `json:"username"`
	IsAdmin   bool      `json:"is_admin"`
	ExpiresAt time.Time `json:"expires_at"`
}

func newResetCode(username string, isAdmin bool) *resetCode {
	return &resetCode{
		Code:      util.GenerateUniqueID(),
		Username:  username,
		IsAdmin:   isAdmin,
		ExpiresAt: time.Now().Add(resetCodeLifespan).UTC(),
	}
}

func (c *resetCode) isExpired() bool {
	return c.ExpiresAt.Before(time.Now().UTC())
}

type memoryResetCodeManager struct {
	resetCodes sync.Map
}

func (m *memoryResetCodeManager) Add(code *resetCode) error {
	m.resetCodes.Store(code.Code, code)
	return nil
}

func (m *memoryResetCodeManager) Get(code string) (*resetCode, error) {
	c, ok := m.resetCodes.Load(code)
	if !ok {
		return nil, util.NewRecordNotFoundError("reset code not found")
	}
	return c.(*resetCode), nil
}

func (m *memoryResetCodeManager) Delete(code string) error {
	m.resetCodes.Delete(code)
	return nil
}

func (m *memoryResetCodeManager) Cleanup() {
	m.resetCodes.Range(func(key, value any) bool {
		c, ok := value.(*resetCode)
		if !ok || c.isExpired() {
			m.resetCodes.Delete(key)
		}
		return true
	})
}

type dbResetCodeManager struct{}

func (m *dbResetCodeManager) Add(code *resetCode) error {
	session := dataprovider.Session{
		Key:       code.Code,
		Data:      code,
		Type:      dataprovider.SessionTypeResetCode,
		Timestamp: util.GetTimeAsMsSinceEpoch(code.ExpiresAt),
	}
	return dataprovider.AddSharedSession(session)
}

func (m *dbResetCodeManager) Get(code string) (*resetCode, error) {
	session, err := dataprovider.GetSharedSession(code, dataprovider.SessionTypeResetCode)
	if err != nil {
		return nil, err
	}
	if session.Timestamp < util.GetTimeAsMsSinceEpoch(time.Now()) {
		// expired
		return nil, util.NewRecordNotFoundError("reset code expired")
	}
	return m.decodeData(session.Data)
}

func (m *dbResetCodeManager) decodeData(data any) (*resetCode, error) {
	if val, ok := data.([]byte); ok {
		c := &resetCode{}
		err := json.Unmarshal(val, c)
		return c, err
	}
	logger.Error(logSender, "", "invalid reset code data type %T", data)
	return nil, util.NewRecordNotFoundError("invalid reset code")
}

func (m *dbResetCodeManager) Delete(code string) error {
	return dataprovider.DeleteSharedSession(code, dataprovider.SessionTypeResetCode)
}

func (m *dbResetCodeManager) Cleanup() {
	dataprovider.CleanupSharedSessions(dataprovider.SessionTypeResetCode, time.Now()) //nolint:errcheck
}
