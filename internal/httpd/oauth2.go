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
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	oauth2Mgr oauth2Manager
)

func newOAuth2Manager(isShared int) oauth2Manager {
	if isShared == 1 {
		logger.Info(logSender, "", "using provider OAuth2 manager")
		return &dbOAuth2Manager{}
	}
	logger.Info(logSender, "", "using memory OAuth2 manager")
	return &memoryOAuth2Manager{
		pendingAuths: make(map[string]oauth2PendingAuth),
	}
}

type oauth2PendingAuth struct {
	State        string      `json:"state"`
	Provider     int         `json:"provider"`
	ClientID     string      `json:"client_id"`
	ClientSecret *kms.Secret `json:"client_secret"`
	RedirectURL  string      `json:"redirect_url"`
	IssuedAt     int64       `json:"issued_at"`
}

func newOAuth2PendingAuth(provider int, redirectURL, clientID string, clientSecret *kms.Secret) oauth2PendingAuth {
	return oauth2PendingAuth{
		State:        util.GenerateOpaqueString(),
		Provider:     provider,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		IssuedAt:     util.GetTimeAsMsSinceEpoch(time.Now()),
	}
}

type oauth2Manager interface {
	addPendingAuth(pendingAuth oauth2PendingAuth)
	removePendingAuth(state string)
	getPendingAuth(state string) (oauth2PendingAuth, error)
	cleanup()
}

type memoryOAuth2Manager struct {
	mu           sync.RWMutex
	pendingAuths map[string]oauth2PendingAuth
}

func (o *memoryOAuth2Manager) addPendingAuth(pendingAuth oauth2PendingAuth) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.pendingAuths[pendingAuth.State] = pendingAuth
}

func (o *memoryOAuth2Manager) removePendingAuth(state string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	delete(o.pendingAuths, state)
}

func (o *memoryOAuth2Manager) getPendingAuth(state string) (oauth2PendingAuth, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	authReq, ok := o.pendingAuths[state]
	if !ok {
		return oauth2PendingAuth{}, errors.New("oauth2: no auth request found for the specified state")
	}
	diff := util.GetTimeAsMsSinceEpoch(time.Now()) - authReq.IssuedAt
	if diff > authStateValidity {
		return oauth2PendingAuth{}, errors.New("oauth2: auth request is too old")
	}
	return authReq, nil
}

func (o *memoryOAuth2Manager) cleanup() {
	o.mu.Lock()
	defer o.mu.Unlock()

	for k, auth := range o.pendingAuths {
		diff := util.GetTimeAsMsSinceEpoch(time.Now()) - auth.IssuedAt
		// remove old pending auth requests
		if diff < 0 || diff > authStateValidity {
			delete(o.pendingAuths, k)
		}
	}
}

type dbOAuth2Manager struct{}

func (o *dbOAuth2Manager) addPendingAuth(pendingAuth oauth2PendingAuth) {
	if err := pendingAuth.ClientSecret.Encrypt(); err != nil {
		logger.Error(logSender, "", "unable to encrypt oauth2 secret: %v", err)
		return
	}
	session := dataprovider.Session{
		Key:       pendingAuth.State,
		Data:      pendingAuth,
		Type:      dataprovider.SessionTypeOAuth2Auth,
		Timestamp: pendingAuth.IssuedAt + authStateValidity,
	}
	dataprovider.AddSharedSession(session) //nolint:errcheck
}

func (o *dbOAuth2Manager) removePendingAuth(state string) {
	dataprovider.DeleteSharedSession(state, dataprovider.SessionTypeOAuth2Auth) //nolint:errcheck
}

func (o *dbOAuth2Manager) getPendingAuth(state string) (oauth2PendingAuth, error) {
	session, err := dataprovider.GetSharedSession(state, dataprovider.SessionTypeOAuth2Auth)
	if err != nil {
		return oauth2PendingAuth{}, errors.New("oauth2: unable to get the auth request for the specified state")
	}
	if session.Timestamp < util.GetTimeAsMsSinceEpoch(time.Now()) {
		// expired
		return oauth2PendingAuth{}, errors.New("oauth2: auth request is too old")
	}
	return o.decodePendingAuthData(session.Data)
}

func (o *dbOAuth2Manager) decodePendingAuthData(data any) (oauth2PendingAuth, error) {
	if val, ok := data.([]byte); ok {
		authReq := oauth2PendingAuth{}
		err := json.Unmarshal(val, &authReq)
		if err != nil {
			return authReq, err
		}
		err = authReq.ClientSecret.TryDecrypt()
		return authReq, err
	}
	logger.Error(logSender, "", "invalid oauth2 auth request data type %T", data)
	return oauth2PendingAuth{}, errors.New("oauth2: invalid auth request data")
}

func (o *dbOAuth2Manager) cleanup() {
	dataprovider.CleanupSharedSessions(dataprovider.SessionTypeOAuth2Auth, time.Now()) //nolint:errcheck
}
