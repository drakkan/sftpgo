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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	resetCodeLifespan   = 10 * time.Minute
	resetCodeSendWindow = 60 * time.Second
	resetCodesMgr       resetCodeManager
	codeSendMarkersMgr  codeSendMarkerManager
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
	rc := c.(*resetCode)
	if rc.isExpired() {
		m.resetCodes.Delete(code)
		return nil, util.NewRecordNotFoundError("reset code expired")
	}
	return rc, nil
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
	_ = dataprovider.CleanupSharedSessions(dataprovider.SessionTypeResetCode, time.Now())
}

// codeSendMarkerManager tracks, per account, that a code email was recently
// sent, so further emails within the send window can be suppressed.
type codeSendMarkerManager interface {
	// Has reports whether an unexpired marker exists. It is not atomic: use
	// it only to skip work early
	Has(key string) bool
	// Mark atomically adds a marker for the given key, unless a not expired one
	// already exists, in this case dataprovider.ErrDuplicatedKey is returned
	Mark(key string, expiresAt time.Time) error
	Clear(key string)
	Cleanup()
}

func newCodeSendMarkerManager(isShared int) codeSendMarkerManager {
	if isShared == 1 {
		return &dbCodeSendMarkerManager{}
	}
	return &memoryCodeSendMarkerManager{
		markers: make(map[string]time.Time),
	}
}

type memoryCodeSendMarkerManager struct {
	mu      sync.Mutex
	markers map[string]time.Time
}

func (m *memoryCodeSendMarkerManager) Has(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt, ok := m.markers[key]
	return ok && !expiresAt.Before(time.Now().UTC())
}

func (m *memoryCodeSendMarkerManager) Mark(key string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if current, ok := m.markers[key]; ok && !current.Before(time.Now().UTC()) {
		return dataprovider.ErrDuplicatedKey
	}
	m.markers[key] = expiresAt
	return nil
}

func (m *memoryCodeSendMarkerManager) Clear(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.markers, key)
}

func (m *memoryCodeSendMarkerManager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	for key, expiresAt := range m.markers {
		if expiresAt.Before(now) {
			delete(m.markers, key)
		}
	}
}

type dbCodeSendMarkerManager struct{}

func (m *dbCodeSendMarkerManager) Has(key string) bool {
	session, err := dataprovider.GetSharedSession(key, dataprovider.SessionTypeCodeSendMarker)
	if err != nil {
		return false
	}
	return session.Timestamp >= util.GetTimeAsMsSinceEpoch(time.Now())
}

func (m *dbCodeSendMarkerManager) Mark(key string, expiresAt time.Time) error {
	session := dataprovider.Session{
		Key:       key,
		Data:      "",
		Type:      dataprovider.SessionTypeCodeSendMarker,
		Timestamp: util.GetTimeAsMsSinceEpoch(expiresAt),
	}
	return dataprovider.AddUniqueSharedSession(session)
}

func (m *dbCodeSendMarkerManager) Clear(key string) {
	_ = dataprovider.DeleteSharedSession(key, dataprovider.SessionTypeCodeSendMarker)
}

func (m *dbCodeSendMarkerManager) Cleanup() {
	_ = dataprovider.CleanupSharedSessions(dataprovider.SessionTypeCodeSendMarker, time.Now())
}

func codeSendMarkerKey(isAdmin bool, username string) string {
	digest := sha256.Sum256(fmt.Appendf(nil, "%t:%s", isAdmin, strings.ToLower(username)))
	return hex.EncodeToString(digest[:])
}

func hasRecentCodeSend(isAdmin bool, username string) bool {
	if resetCodeSendWindow <= 0 {
		return false
	}
	return codeSendMarkersMgr.Has(codeSendMarkerKey(isAdmin, username))
}

func markCodeSent(isAdmin bool, username string) error {
	if resetCodeSendWindow <= 0 {
		return nil
	}
	expiresAt := time.Now().Add(resetCodeSendWindow).UTC()
	return codeSendMarkersMgr.Mark(codeSendMarkerKey(isAdmin, username), expiresAt)
}

func clearCodeSent(isAdmin bool, username string) {
	codeSendMarkersMgr.Clear(codeSendMarkerKey(isAdmin, username))
}

func sendCodeEmailInBackground(c *resetCode, reqID string, recipients []string, subject, body string) bool {
	if hasRecentCodeSend(c.IsAdmin, c.Username) {
		logger.Debug(logSender, reqID, "a code email was recently sent to %+v, new email suppressed", recipients)
		return false
	}
	if err := markCodeSent(c.IsAdmin, c.Username); err != nil {
		if errors.Is(err, dataprovider.ErrDuplicatedKey) {
			logger.Debug(logSender, reqID, "a code email was recently sent to %+v, new email suppressed", recipients)
		} else {
			logger.Warn(logSender, reqID, "unable to track the code email to send to %+v, email not sent: %v",
				recipients, err)
		}
		return false
	}
	if err := resetCodesMgr.Add(c); err != nil {
		logger.Warn(logSender, reqID, "unable to store the code to send to %+v: %v", recipients, err)
		clearCodeSent(c.IsAdmin, c.Username)
		return false
	}
	go func() {
		startTime := time.Now()
		if err := smtp.SendEmail(recipients, nil, subject, body, smtp.EmailContentTypeTextHTML); err != nil {
			logger.Warn(logSender, reqID, "unable to send code email to %+v: %v, elapsed: %s", recipients, err,
				time.Since(startTime))
			if err := resetCodesMgr.Delete(c.Code); err != nil {
				logger.Warn(logSender, reqID, "unable to remove the code of a failed email delivery: %v", err)
			}
			clearCodeSent(c.IsAdmin, c.Username)
			return
		}
		logger.Debug(logSender, reqID, "code email sent to %+v, elapsed: %s", recipients, time.Since(startTime))
	}()
	return true
}
