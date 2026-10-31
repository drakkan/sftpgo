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
	"errors"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	oidcMgr oidcManager
)

func newOIDCManager(isShared int) oidcManager {
	if isShared == 1 {
		logger.Info(logSender, "", "using provider OIDC manager")
		return &dbOIDCManager{}
	}
	logger.Info(logSender, "", "using memory OIDC manager")
	return &memoryOIDCManager{
		tokens: make(map[string]oidcToken),
	}
}

type oidcManager interface {
	addToken(token oidcToken)
	getToken(cookie string) (oidcToken, error)
	removeToken(cookie string)
	updateTokenUsage(token oidcToken)
	cleanup()
}

type memoryOIDCManager struct {
	tokenMutex sync.RWMutex
	tokens     map[string]oidcToken
}

func (o *memoryOIDCManager) addToken(token oidcToken) {
	o.tokenMutex.Lock()
	token.UsedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	o.tokens[token.Cookie] = token
	o.tokenMutex.Unlock()
}

func (o *memoryOIDCManager) getToken(cookie string) (oidcToken, error) {
	o.tokenMutex.RLock()
	defer o.tokenMutex.RUnlock()

	token, ok := o.tokens[cookie]
	if !ok {
		return oidcToken{}, errors.New("oidc: no token found for the specified session")
	}
	diff := util.GetTimeAsMsSinceEpoch(time.Now()) - token.UsedAt
	if diff > tokenDeleteInterval {
		return oidcToken{}, errors.New("oidc: token is too old")
	}
	return token, nil
}

func (o *memoryOIDCManager) removeToken(cookie string) {
	o.tokenMutex.Lock()
	defer o.tokenMutex.Unlock()

	delete(o.tokens, cookie)
}

func (o *memoryOIDCManager) updateTokenUsage(token oidcToken) {
	diff := util.GetTimeAsMsSinceEpoch(time.Now()) - token.UsedAt
	if diff > tokenUpdateInterval {
		o.addToken(token)
	}
}

func (o *memoryOIDCManager) cleanup() {
	o.cleanupTokens()
}

func (o *memoryOIDCManager) cleanupTokens() {
	o.tokenMutex.Lock()
	defer o.tokenMutex.Unlock()

	for k, token := range o.tokens {
		diff := util.GetTimeAsMsSinceEpoch(time.Now()) - token.UsedAt
		// remove tokens unused from more than tokenDeleteInterval
		if diff > tokenDeleteInterval {
			delete(o.tokens, k)
		}
	}
}

type dbOIDCManager struct{}

func (o *dbOIDCManager) addToken(token oidcToken) {
	token.UsedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	session := dataprovider.Session{
		Key:       token.Cookie,
		Data:      token,
		Type:      dataprovider.SessionTypeOIDCToken,
		Timestamp: token.UsedAt + tokenDeleteInterval,
	}
	_ = dataprovider.AddSharedSession(session)
}

func (o *dbOIDCManager) removeToken(cookie string) {
	_ = dataprovider.DeleteSharedSession(cookie, dataprovider.SessionTypeOIDCToken)
}

func (o *dbOIDCManager) updateTokenUsage(token oidcToken) {
	diff := util.GetTimeAsMsSinceEpoch(time.Now()) - token.UsedAt
	if diff > tokenUpdateInterval {
		o.addToken(token)
	}
}

func (o *dbOIDCManager) getToken(cookie string) (oidcToken, error) {
	session, err := dataprovider.GetSharedSession(cookie, dataprovider.SessionTypeOIDCToken)
	if err != nil {
		return oidcToken{}, errors.New("oidc: unable to get the token for the specified session")
	}
	if session.Timestamp < util.GetTimeAsMsSinceEpoch(time.Now()) {
		// expired
		return oidcToken{}, errors.New("oidc: token is too old")
	}
	return o.decodeTokenData(session.Data)
}

func (o *dbOIDCManager) decodeTokenData(data any) (oidcToken, error) {
	if val, ok := data.([]byte); ok {
		token := oidcToken{}
		err := json.Unmarshal(val, &token)
		return token, err
	}
	logger.Error(logSender, "", "invalid oidc token data type %T", data)
	return oidcToken{}, errors.New("oidc: invalid token data")
}

func (o *dbOIDCManager) cleanup() {
	_ = dataprovider.CleanupSharedSessions(dataprovider.SessionTypeOIDCToken, time.Now())
}
