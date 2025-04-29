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
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func newTokenManager(isShared int) tokenManager {
	if isShared == 1 {
		logger.Info(logSender, "", "using provider token manager")
		return &dbTokenManager{}
	}
	logger.Info(logSender, "", "using memory token manager")
	return &memoryTokenManager{}
}

type tokenManager interface {
	Add(token string, expiresAt time.Time)
	Get(token string) bool
	Cleanup()
}

type memoryTokenManager struct {
	invalidatedJWTTokens sync.Map
}

func (m *memoryTokenManager) Add(token string, expiresAt time.Time) {
	m.invalidatedJWTTokens.Store(token, expiresAt)
}

func (m *memoryTokenManager) Get(token string) bool {
	_, ok := m.invalidatedJWTTokens.Load(token)
	return ok
}

func (m *memoryTokenManager) Cleanup() {
	m.invalidatedJWTTokens.Range(func(key, value any) bool {
		exp, ok := value.(time.Time)
		if !ok || exp.Before(time.Now().UTC()) {
			m.invalidatedJWTTokens.Delete(key)
		}
		return true
	})
}

type dbTokenManager struct{}

func (m *dbTokenManager) getKey(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func (m *dbTokenManager) Add(token string, expiresAt time.Time) {
	key := m.getKey(token)
	data := map[string]string{
		"jwt": token,
	}
	session := dataprovider.Session{
		Key:       key,
		Data:      data,
		Type:      dataprovider.SessionTypeInvalidToken,
		Timestamp: util.GetTimeAsMsSinceEpoch(expiresAt),
	}
	dataprovider.AddSharedSession(session) //nolint:errcheck
}

func (m *dbTokenManager) Get(token string) bool {
	key := m.getKey(token)
	_, err := dataprovider.GetSharedSession(key, dataprovider.SessionTypeInvalidToken)
	return err == nil
}

func (m *dbTokenManager) Cleanup() {
	dataprovider.CleanupSharedSessions(dataprovider.SessionTypeInvalidToken, time.Now()) //nolint:errcheck
}
