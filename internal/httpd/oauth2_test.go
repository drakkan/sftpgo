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
	"testing"
	"time"

	"github.com/rs/xid"
	sdkkms "github.com/sftpgo/sdk/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func TestMemoryOAuth2Manager(t *testing.T) {
	mgr := newOAuth2Manager(0)
	m, ok := mgr.(*memoryOAuth2Manager)
	require.True(t, ok)
	require.Len(t, m.pendingAuths, 0)
	_, err := m.getPendingAuth(xid.New().String())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no auth request found")
	auth := newOAuth2PendingAuth(1, "https://...", "cid", kms.NewPlainSecret("mysecret"))
	m.addPendingAuth(auth)
	require.Len(t, m.pendingAuths, 1)
	a, err := m.getPendingAuth(auth.State)
	assert.NoError(t, err)
	assert.Equal(t, auth.State, a.State)
	assert.Equal(t, sdkkms.SecretStatusPlain, a.ClientSecret.GetStatus())
	m.removePendingAuth(auth.State)
	_, err = m.getPendingAuth(auth.State)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no auth request found")
	require.Len(t, m.pendingAuths, 0)
	state := xid.New().String()
	auth = oauth2PendingAuth{
		State:    state,
		Provider: 1,
		IssuedAt: util.GetTimeAsMsSinceEpoch(time.Now()),
	}
	m.addPendingAuth(auth)
	auth = oauth2PendingAuth{
		State:    xid.New().String(),
		Provider: 1,
		IssuedAt: util.GetTimeAsMsSinceEpoch(time.Now().Add(-10 * time.Minute)),
	}
	m.addPendingAuth(auth)
	require.Len(t, m.pendingAuths, 2)
	_, err = m.getPendingAuth(auth.State)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth request is too old")
	m.cleanup()
	require.Len(t, m.pendingAuths, 1)
	m.removePendingAuth(state)
	require.Len(t, m.pendingAuths, 0)
}

func TestDbOAuth2Manager(t *testing.T) {
	if !isSharedProviderSupported() {
		t.Skip("this test it is not available with this provider")
	}
	mgr := newOAuth2Manager(1)
	m, ok := mgr.(*dbOAuth2Manager)
	require.True(t, ok)
	_, err := m.getPendingAuth(xid.New().String())
	require.Error(t, err)
	auth := newOAuth2PendingAuth(1, "https://...", "client_id", kms.NewPlainSecret("my db secret"))
	m.addPendingAuth(auth)
	a, err := m.getPendingAuth(auth.State)
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusPlain, a.ClientSecret.GetStatus())
	session, err := dataprovider.GetSharedSession(auth.State, dataprovider.SessionTypeOAuth2Auth)
	assert.NoError(t, err)
	authReq := oauth2PendingAuth{}
	err = json.Unmarshal(session.Data.([]byte), &authReq)
	assert.NoError(t, err)
	assert.Equal(t, sdkkms.SecretStatusSecretBox, authReq.ClientSecret.GetStatus())
	m.cleanup()
	_, err = m.getPendingAuth(auth.State)
	assert.NoError(t, err)
	m.removePendingAuth(auth.State)
	_, err = m.getPendingAuth(auth.State)
	assert.Error(t, err)
	auth = oauth2PendingAuth{
		State:        xid.New().String(),
		Provider:     1,
		IssuedAt:     util.GetTimeAsMsSinceEpoch(time.Now().Add(-10 * time.Minute)),
		ClientSecret: kms.NewPlainSecret("db secret"),
	}
	m.addPendingAuth(auth)
	_, err = m.getPendingAuth(auth.State)
	assert.Error(t, err)
	_, err = dataprovider.GetSharedSession(auth.State, dataprovider.SessionTypeOAuth2Auth)
	assert.NoError(t, err)
	m.cleanup()
	_, err = dataprovider.GetSharedSession(auth.State, dataprovider.SessionTypeOAuth2Auth)
	assert.Error(t, err)
	_, err = m.decodePendingAuthData("not a byte array")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid auth request data")
	_, err = m.decodePendingAuthData([]byte("{not a json"))
	require.Error(t, err)
	// adding a request with a non plain secret will fail
	auth = oauth2PendingAuth{
		State:        xid.New().String(),
		Provider:     1,
		IssuedAt:     util.GetTimeAsMsSinceEpoch(time.Now().Add(-10 * time.Minute)),
		ClientSecret: kms.NewPlainSecret("db secret"),
	}
	auth.ClientSecret.SetStatus(sdkkms.SecretStatusSecretBox)
	m.addPendingAuth(auth)
	_, err = dataprovider.GetSharedSession(auth.State, dataprovider.SessionTypeOAuth2Auth)
	assert.Error(t, err)
	asJSON, err := json.Marshal(auth)
	assert.NoError(t, err)
	_, err = m.decodePendingAuthData(asJSON)
	assert.Error(t, err)
}
