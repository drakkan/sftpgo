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

package httpd_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpdtest"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const userAPIKeysPath = "/api/v2/user/apikeys"

func addSelfServiceUser(t *testing.T, username string) dataprovider.User {
	u := getTestUser()
	u.Username = username
	u.HomeDir = filepath.Join(homeBasePath, username)
	u.Filters.AllowAPIKeyAuth = true
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	require.NoError(t, err)
	user.Password = u.Password
	t.Cleanup(func() {
		_, err := httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		assert.NoError(t, os.RemoveAll(user.GetHomeDir()))
	})
	return user
}

func userTokenFor(t *testing.T, user dataprovider.User) string {
	token, err := getJWTAPIUserTokenFromTestServer(user.Username, user.Password)
	require.NoError(t, err)
	return token
}

func postUserAPIKey(t *testing.T, token string, body map[string]any) *httptest.ResponseRecorder {
	asJSON, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, userAPIKeysPath, bytes.NewBuffer(asJSON))
	require.NoError(t, err)
	setBearerForReq(req, token)
	return executeRequest(req)
}

func createUserAPIKey(t *testing.T, token, name string) (string, string) {
	rr := postUserAPIKey(t, token, map[string]any{"name": name})
	checkResponseCode(t, http.StatusCreated, rr)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	key := resp["key"]
	keyID, _, ok := strings.Cut(key, ".")
	require.True(t, ok)
	return key, keyID
}

func listUserDirsWithKey(t *testing.T, key string) *httptest.ResponseRecorder {
	req, err := http.NewRequest(http.MethodGet, userDirsPath, nil)
	require.NoError(t, err)
	setAPIKeyForReq(req, key, "")
	return executeRequest(req)
}

func deleteUserAPIKeyAs(t *testing.T, keyID, token, key string) *httptest.ResponseRecorder {
	req, err := http.NewRequest(http.MethodDelete, userAPIKeysPath+"/"+keyID, nil)
	require.NoError(t, err)
	if token != "" {
		setBearerForReq(req, token)
	} else {
		setAPIKeyForReq(req, key, "")
	}
	return executeRequest(req)
}

func TestUserAPIKeyCreate(t *testing.T) {
	user := addSelfServiceUser(t, "selfservice_create")
	token := userTokenFor(t, user)

	// A forged body cannot change the owner or the scope, or pick the credentials.
	expiresAt := util.GetTimeAsMsSinceEpoch(time.Now().Add(time.Hour))
	rr := postUserAPIKey(t, token, map[string]any{
		"name":        "phone",
		"description": "my phone",
		"expires_at":  expiresAt,
		"scope":       dataprovider.APIKeyScopeAdmin,
		"admin":       defaultTokenAuthUser,
		"user":        "someone_else",
		"id":          "chosen_id",
		"key":         "chosen_secret",
	})
	checkResponseCode(t, http.StatusCreated, rr)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	key := resp["key"]
	keyID, secret, ok := strings.Cut(key, ".")
	require.True(t, ok)
	assert.NotEqual(t, "chosen_id", keyID)
	assert.NotEqual(t, "chosen_secret", secret)
	assert.Equal(t, keyID, rr.Header().Get("X-Object-ID"))
	assert.Equal(t, userAPIKeysPath+"/"+keyID, rr.Header().Get("Location"))

	stored, _, err := httpdtest.GetAPIKeyByID(keyID, http.StatusOK)
	require.NoError(t, err)
	assert.Equal(t, dataprovider.APIKeyScopeUser, stored.Scope)
	assert.Equal(t, user.Username, stored.User)
	assert.Empty(t, stored.Admin)
	assert.Equal(t, expiresAt, stored.ExpiresAt)
	assert.Equal(t, "my phone", stored.Description)

	// The key works for this user and for nothing else.
	checkResponseCode(t, http.StatusOK, listUserDirsWithKey(t, key))
	req, err := http.NewRequest(http.MethodGet, versionPath, nil)
	require.NoError(t, err)
	setAPIKeyForReq(req, key, "")
	checkResponseCode(t, http.StatusForbidden, executeRequest(req))

	// A key cannot extend its own life by creating another one.
	req, err = http.NewRequest(http.MethodPost, userAPIKeysPath, bytes.NewBufferString(`{"name":"chained"}`))
	require.NoError(t, err)
	setAPIKeyForReq(req, key, "")
	checkResponseCode(t, http.StatusForbidden, executeRequest(req))

	// Bad requests.
	checkResponseCode(t, http.StatusBadRequest, postUserAPIKey(t, token, map[string]any{"name": ""}))
	checkResponseCode(t, http.StatusBadRequest, postUserAPIKey(t, token, map[string]any{
		"name":       "expired",
		"expires_at": util.GetTimeAsMsSinceEpoch(time.Now().Add(-time.Minute)),
	}))
	checkResponseCode(t, http.StatusBadRequest, postUserAPIKey(t, token, map[string]any{
		"name":       "negative",
		"expires_at": -1,
	}))

	// No token, no key.
	req, err = http.NewRequest(http.MethodPost, userAPIKeysPath, bytes.NewBufferString(`{"name":"anonymous"}`))
	require.NoError(t, err)
	checkResponseCode(t, http.StatusUnauthorized, executeRequest(req))

	_, err = httpdtest.RemoveAPIKey(stored, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserAPIKeyAdminControls(t *testing.T) {
	user := addSelfServiceUser(t, "selfservice_controls")
	token := userTokenFor(t, user)
	_, keyID := createUserAPIKey(t, token, "before_the_restriction")
	stored, _, err := httpdtest.GetAPIKeyByID(keyID, http.StatusOK)
	require.NoError(t, err)

	// The existing per user switch turns off self-service keys.
	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled}
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	require.NoError(t, err)
	user.Password = defaultPassword
	token = userTokenFor(t, user)
	checkResponseCode(t, http.StatusForbidden, postUserAPIKey(t, token, map[string]any{"name": "blocked"}))
	checkResponseCode(t, http.StatusForbidden, deleteUserAPIKeyAs(t, keyID, token, ""))

	// A key is useless without API key authentication, so it is refused rather than created.
	user.Filters.WebClient = nil
	user.Filters.AllowAPIKeyAuth = false
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	require.NoError(t, err)
	user.Password = defaultPassword
	token = userTokenFor(t, user)
	rr := postUserAPIKey(t, token, map[string]any{"name": "disabled"})
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "disabled for this user")

	_, err = httpdtest.RemoveAPIKey(stored, http.StatusOK)
	assert.NoError(t, err)
}

func TestUserAPIKeyDelete(t *testing.T) {
	user := addSelfServiceUser(t, "selfservice_delete")
	other := addSelfServiceUser(t, "selfservice_delete_other")
	token := userTokenFor(t, user)
	otherToken := userTokenFor(t, other)

	phoneKey, phoneID := createUserAPIKey(t, token, "phone")
	tabletKey, tabletID := createUserAPIKey(t, token, "tablet")

	// Keys of others look like keys that do not exist.
	unknown := deleteUserAPIKeyAs(t, "no_such_key", token, "")
	checkResponseCode(t, http.StatusNotFound, unknown)
	foreign := deleteUserAPIKeyAs(t, phoneID, otherToken, "")
	checkResponseCode(t, http.StatusNotFound, foreign)
	assert.Equal(t, unknown.Body.String(), foreign.Body.String())
	_, otherKeyID := createUserAPIKey(t, otherToken, "other")
	checkResponseCode(t, http.StatusNotFound, deleteUserAPIKeyAs(t, otherKeyID, "", phoneKey))

	adminKey, _, err := httpdtest.AddAPIKey(dataprovider.APIKey{
		Name:  "admin_scope",
		Scope: dataprovider.APIKeyScopeAdmin,
	}, http.StatusCreated)
	require.NoError(t, err)
	anyUserKey, _, err := httpdtest.AddAPIKey(dataprovider.APIKey{
		Name:  "any_user",
		Scope: dataprovider.APIKeyScopeUser,
	}, http.StatusCreated)
	require.NoError(t, err)
	checkResponseCode(t, http.StatusNotFound, deleteUserAPIKeyAs(t, adminKey.KeyID, token, ""))
	checkResponseCode(t, http.StatusNotFound, deleteUserAPIKeyAs(t, anyUserKey.KeyID, token, ""))

	// A key revokes itself, but not the key of another device.
	checkResponseCode(t, http.StatusForbidden, deleteUserAPIKeyAs(t, tabletID, "", phoneKey))
	checkResponseCode(t, http.StatusOK, listUserDirsWithKey(t, tabletKey))
	checkResponseCode(t, http.StatusOK, deleteUserAPIKeyAs(t, phoneID, "", phoneKey))
	assert.NotEqual(t, http.StatusOK, listUserDirsWithKey(t, phoneKey).Code)

	// A login can revoke any key of the user, for example after losing a phone.
	checkResponseCode(t, http.StatusOK, deleteUserAPIKeyAs(t, tabletID, token, ""))
	assert.NotEqual(t, http.StatusOK, listUserDirsWithKey(t, tabletKey).Code)

	for _, id := range []string{adminKey.KeyID, anyUserKey.KeyID, otherKeyID} {
		_, err = httpdtest.RemoveAPIKey(dataprovider.APIKey{KeyID: id}, http.StatusOK)
		assert.NoError(t, err)
	}
}
