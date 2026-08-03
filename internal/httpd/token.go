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
	"errors"
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
	Add(id string, expiresAt time.Time) error
	Get(id string) bool
	Cleanup()
}

type memoryTokenManager struct {
	invalidatedJWTTokens sync.Map
}

func (m *memoryTokenManager) Add(id string, expiresAt time.Time) error {
	m.invalidatedJWTTokens.Store(id, expiresAt)
	return nil
}

func (m *memoryTokenManager) Get(id string) bool {
	_, ok := m.invalidatedJWTTokens.Load(id)
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

func (m *dbTokenManager) Add(id string, expiresAt time.Time) error {
	session := dataprovider.Session{
		Key:       id,
		Type:      dataprovider.SessionTypeInvalidToken,
		Timestamp: util.GetTimeAsMsSinceEpoch(expiresAt),
	}
	if err := dataprovider.AddSharedSession(session); err != nil {
		logger.Warn(logSender, "", "unable to add an entry to the invalidation store: %v", err)
		return err
	}
	return nil
}

func (m *dbTokenManager) Get(id string) bool {
	_, err := dataprovider.GetSharedSession(id, dataprovider.SessionTypeInvalidToken)
	if err == nil {
		return true
	}
	if errors.Is(err, util.ErrNotFound) {
		return false
	}
	// a provider error is treated as invalidated (fail closed)
	logger.Warn(logSender, "", "unable to check the invalidation store: %v", err)
	return true
}

func (m *dbTokenManager) Cleanup() {
	dataprovider.CleanupSharedSessions(dataprovider.SessionTypeInvalidToken, time.Now()) //nolint:errcheck
}
