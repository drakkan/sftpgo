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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/httpdtest"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

const (
	userAPIKeysPath      = "/api/v2/user/apikeys"
	userWebSessionPath   = "/api/v2/user/websession"
	webClientAPIKeysPath = "/web/client/api-keys"
)

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

func createWebSessionKey(t *testing.T, token, name string) (string, string) {
	rr := postUserAPIKey(t, token, map[string]any{"name": name, "web_session": true})
	checkResponseCode(t, http.StatusCreated, rr)
	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	keyID, _, ok := strings.Cut(resp["key"], ".")
	require.True(t, ok)
	return resp["key"], keyID
}

func openWebSession(t *testing.T, key string) *httptest.ResponseRecorder {
	req, err := http.NewRequest(http.MethodPost, userWebSessionPath, nil)
	require.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setAPIKeyForReq(req, key, "")
	return executeRequest(req)
}

func webSessionCookie(t *testing.T, key string) string {
	rr := openWebSession(t, key)
	checkResponseCode(t, http.StatusOK, rr)
	cookie, err := getCookieFromResponse(rr)
	require.NoError(t, err)
	return cookie
}

func webClientRequest(t *testing.T, method, path, cookie string) *httptest.ResponseRecorder {
	req, err := http.NewRequest(method, path, nil)
	require.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	return executeRequest(req)
}

func webClientFormRequest(t *testing.T, method, path, cookie string) *httptest.ResponseRecorder {
	csrfToken, err := getCSRFTokenFromInternalPageMock(webClientProfilePath, cookie)
	require.NoError(t, err)
	form := make(url.Values)
	form.Set(csrfFormToken, csrfToken)
	req, err := http.NewRequest(method, path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-TOKEN", csrfToken)
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

func TestWebSessionOnlyWithMarkedKeys(t *testing.T) {
	user := addSelfServiceUser(t, "websession_marked")
	token := userTokenFor(t, user)

	plainKey, plainID := createUserAPIKey(t, token, "plain")
	sessionKey, sessionID := createWebSessionKey(t, token, "session")

	stored, _, err := httpdtest.GetAPIKeyByID(sessionID, http.StatusOK)
	require.NoError(t, err)
	assert.Equal(t, dataprovider.APIKeyScopeUserWebSession, stored.Scope)
	assert.Equal(t, user.Username, stored.User)

	// A marked key is still a user key.
	checkResponseCode(t, http.StatusOK, listUserDirsWithKey(t, sessionKey))
	req, err := http.NewRequest(http.MethodGet, versionPath, nil)
	require.NoError(t, err)
	setAPIKeyForReq(req, sessionKey, "")
	checkResponseCode(t, http.StatusForbidden, executeRequest(req))

	// A key cannot extend its own life, marked or not.
	req, err = http.NewRequest(http.MethodPost, userAPIKeysPath, bytes.NewBufferString(`{"name":"chained"}`))
	require.NoError(t, err)
	setAPIKeyForReq(req, sessionKey, "")
	checkResponseCode(t, http.StatusForbidden, executeRequest(req))

	// Ordinary keys and logins are refused, and neither gets a cookie.
	rr := openWebSession(t, plainKey)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Empty(t, rr.Header().Get("Set-Cookie"))
	req, err = http.NewRequest(http.MethodPost, userWebSessionPath, nil)
	require.NoError(t, err)
	setBearerForReq(req, token)
	rr = executeRequest(req)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Empty(t, rr.Header().Get("Set-Cookie"))
	req, err = http.NewRequest(http.MethodPost, userWebSessionPath, nil)
	require.NoError(t, err)
	checkResponseCode(t, http.StatusUnauthorized, executeRequest(req))
	checkResponseCode(t, http.StatusUnauthorized, openWebSession(t, sessionID+".wrong_secret"))

	// The cookie opens the WebClient, and only that.
	rr = openWebSession(t, sessionKey)
	checkResponseCode(t, http.StatusOK, rr)
	setCookie := rr.Header().Get("Set-Cookie")
	assert.Contains(t, setCookie, "HttpOnly")
	assert.Contains(t, setCookie, "SameSite=Strict")
	assert.Contains(t, setCookie, "Path=/web/client")
	cookie, err := getCookieFromResponse(rr)
	require.NoError(t, err)
	checkResponseCode(t, http.StatusOK, webClientRequest(t, http.MethodGet, webClientFilesPath, cookie))
	req, err = http.NewRequest(http.MethodGet, userDirsPath, nil)
	require.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setBearerForReq(req, cookie)
	checkResponseCode(t, http.StatusUnauthorized, executeRequest(req))
	req, err = http.NewRequest(http.MethodGet, webUsersPath, nil)
	require.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	checkResponseCode(t, http.StatusFound, executeRequest(req))

	// The owner must be fixed: a key valid for anyone would open a session for anyone.
	_, _, err = httpdtest.AddAPIKey(dataprovider.APIKey{
		Name:  "any_user_session",
		Scope: dataprovider.APIKeyScopeUserWebSession,
	}, http.StatusBadRequest)
	assert.NoError(t, err)

	// An ordinary key that names a user in the request gets no session either.
	wildcard, _, err := httpdtest.AddAPIKey(dataprovider.APIKey{
		Name:  "any_user",
		Scope: dataprovider.APIKeyScopeUser,
	}, http.StatusCreated)
	require.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, userWebSessionPath, nil)
	require.NoError(t, err)
	req.RemoteAddr = defaultRemoteAddr
	setAPIKeyForReq(req, wildcard.Key, user.Username)
	checkResponseCode(t, http.StatusForbidden, executeRequest(req))

	for _, id := range []string{plainID, sessionID, wildcard.KeyID} {
		_, err = httpdtest.RemoveAPIKey(dataprovider.APIKey{KeyID: id}, http.StatusOK)
		assert.NoError(t, err)
	}
}

func TestWebSessionCannotChangeTheAccount(t *testing.T) {
	user := addSelfServiceUser(t, "websession_account")
	key, keyID := createWebSessionKey(t, userTokenFor(t, user), "session")
	cookie := webSessionCookie(t, key)

	loginCookie, err := getJWTWebClientTokenFromTestServer(user.Username, user.Password)
	require.NoError(t, err)

	guarded := []struct{ method, path string }{
		{http.MethodPost, webClientProfilePath},
		{http.MethodGet, webChangeClientPwdPath},
		{http.MethodPost, webChangeClientPwdPath},
		{http.MethodGet, webClientMFAPath},
		{http.MethodPost, "/web/client/totp/generate"},
		{http.MethodPost, "/web/client/totp/validate"},
		{http.MethodPost, webClientTOTPSavePath},
		{http.MethodGet, "/web/client/recoverycodes"},
		{http.MethodPost, "/web/client/recoverycodes"},
	}
	// A valid CSRF token rules out the CSRF check, and the HTML page rules out the
	// handlers, which answer 403 in JSON when the account has no second factor.
	refusedByGuard := func(rr *httptest.ResponseRecorder) bool {
		return rr.Code == http.StatusForbidden && strings.Contains(strings.ToLower(rr.Body.String()), "<!doctype html>")
	}
	for _, route := range guarded {
		assert.True(t, refusedByGuard(webClientFormRequest(t, route.method, route.path, cookie)),
			"%s %s", route.method, route.path)
		assert.False(t, refusedByGuard(webClientFormRequest(t, route.method, route.path, loginCookie)),
			"%s %s", route.method, route.path)
	}
	checkResponseCode(t, http.StatusOK, webClientRequest(t, http.MethodGet, webClientProfilePath, cookie))

	_, err = httpdtest.RemoveAPIKey(dataprovider.APIKey{KeyID: keyID}, http.StatusOK)
	assert.NoError(t, err)
}

func TestWebSessionEndsWithTheKey(t *testing.T) {
	user := addSelfServiceUser(t, "websession_revoke")
	token := userTokenFor(t, user)

	// Revocation works on the next request, without waiting for the cookie to expire.
	key, keyID := createWebSessionKey(t, token, "phone")
	cookie := webSessionCookie(t, key)
	checkResponseCode(t, http.StatusOK, webClientRequest(t, http.MethodGet, webClientFilesPath, cookie))
	checkResponseCode(t, http.StatusOK, deleteUserAPIKeyAs(t, keyID, token, ""))
	rr := webClientRequest(t, http.MethodGet, webClientFilesPath, cookie)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Contains(t, rr.Header().Get("Location"), webClientLoginPath)
	assert.NotEqual(t, http.StatusOK, openWebSession(t, key).Code)

	// So does expiration.
	key, keyID = createWebSessionKey(t, token, "expiring")
	cookie = webSessionCookie(t, key)
	stored, _, err := httpdtest.GetAPIKeyByID(keyID, http.StatusOK)
	require.NoError(t, err)
	stored.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-time.Minute))
	_, _, err = httpdtest.UpdateAPIKey(stored, http.StatusOK)
	require.NoError(t, err)
	checkResponseCode(t, http.StatusFound, webClientRequest(t, http.MethodGet, webClientFilesPath, cookie))
	assert.NotEqual(t, http.StatusOK, openWebSession(t, key).Code)

	// Downgrading the key closes the sessions it opened.
	key, keyID = createWebSessionKey(t, token, "downgraded")
	cookie = webSessionCookie(t, key)
	stored, _, err = httpdtest.GetAPIKeyByID(keyID, http.StatusOK)
	require.NoError(t, err)
	stored.Scope = dataprovider.APIKeyScopeUser
	_, _, err = httpdtest.UpdateAPIKey(stored, http.StatusOK)
	require.NoError(t, err)
	checkResponseCode(t, http.StatusFound, webClientRequest(t, http.MethodGet, webClientFilesPath, cookie))
	checkResponseCode(t, http.StatusForbidden, openWebSession(t, key))
	_, err = httpdtest.RemoveAPIKey(dataprovider.APIKey{KeyID: keyID}, http.StatusOK)
	assert.NoError(t, err)

	// A disabled account gets no session.
	key, keyID = createWebSessionKey(t, token, "disabled_user")
	user.Status = 0
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, openWebSession(t, key).Code)
	user.Status = 1
	user, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	require.NoError(t, err)
	checkResponseCode(t, http.StatusOK, openWebSession(t, key))

	// Turning off API key authentication stops new sessions.
	user.Filters.AllowAPIKeyAuth = false
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, openWebSession(t, key).Code)
	_, err = httpdtest.RemoveAPIKey(dataprovider.APIKey{KeyID: keyID}, http.StatusOK)
	assert.NoError(t, err)
}

func TestWebSessionAndSecondFactor(t *testing.T) {
	user := addSelfServiceUser(t, "websession_2fa")
	token := userTokenFor(t, user)
	key, keyID := createWebSessionKey(t, token, "session")

	// The key replaces the second factor: this is what the marked scope is for.
	configName, totpKey, _, err := mfa.GenerateTOTPSecret(mfa.GetAvailableTOTPConfigNames()[0], user.Username)
	require.NoError(t, err)
	dbUser, err := dataprovider.UserExists(user.Username, "")
	require.NoError(t, err)
	dbUser.Password = user.Password
	dbUser.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled:    true,
		ConfigName: configName,
		Secret:     kms.NewPlainSecret(totpKey.Secret()),
		Protocols:  []string{common.ProtocolHTTP},
	}
	require.NoError(t, dataprovider.UpdateUser(&dbUser, "", "", ""))

	loginCookie, err := getJWTWebClientTokenFromTestServer(user.Username, user.Password)
	require.NoError(t, err)
	rr := webClientRequest(t, http.MethodGet, webClientFilesPath, loginCookie)
	checkResponseCode(t, http.StatusFound, rr)
	assert.Equal(t, webClientTwoFactorPath, rr.Header().Get("Location"))

	cookie := webSessionCookie(t, key)
	checkResponseCode(t, http.StatusOK, webClientRequest(t, http.MethodGet, webClientFilesPath, cookie))

	// Pages closed to key sessions must be sent to a real login, or the user is stuck.
	dbUser, err = dataprovider.UserExists(user.Username, "")
	require.NoError(t, err)
	dbUser.Filters.RequirePasswordChange = true
	require.NoError(t, dataprovider.UpdateUser(&dbUser, "", "", ""))
	rr = openWebSession(t, key)
	checkResponseCode(t, http.StatusForbidden, rr)
	assert.Contains(t, rr.Body.String(), "Login with the password required")
	assert.Empty(t, rr.Header().Get("Set-Cookie"))

	_, err = httpdtest.RemoveAPIKey(dataprovider.APIKey{KeyID: keyID}, http.StatusOK)
	assert.NoError(t, err)
}

func TestWebAdminKeepsWebSessionScope(t *testing.T) {
	user := addSelfServiceUser(t, "websession_webadmin")
	key, keyID := createWebSessionKey(t, userTokenFor(t, user), "session")
	adminCookie, err := getJWTWebTokenFromTestServer(defaultTokenAuthUser, defaultTokenAuthPass)
	require.NoError(t, err)

	// The page must show the real scope, or saving it would look like a change.
	rr := webClientRequest(t, http.MethodGet, webAPIKeyPath+"/"+keyID, adminCookie)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Regexp(t, `value="3"\s+selected`, rr.Body.String())

	// A disabled select is not submitted, so the form has no scope.
	csrfToken, err := getCSRFTokenFromInternalPageMock(webAPIKeyPath, adminCookie)
	require.NoError(t, err)
	form := url.Values{
		"name":        {"session"},
		"description": {"edited"},
		"user":        {user.Username},
		csrfFormToken: {csrfToken},
	}
	req, err := http.NewRequest(http.MethodPost, webAPIKeyPath+"/"+keyID, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setJWTCookieForReq(req, adminCookie)
	checkResponseCode(t, http.StatusSeeOther, executeRequest(req))

	stored, _, err := httpdtest.GetAPIKeyByID(keyID, http.StatusOK)
	require.NoError(t, err)
	assert.Equal(t, "edited", stored.Description)
	assert.Equal(t, dataprovider.APIKeyScopeUserWebSession, stored.Scope)
	checkResponseCode(t, http.StatusOK, openWebSession(t, key))

	_, err = httpdtest.RemoveAPIKey(stored, http.StatusOK)
	assert.NoError(t, err)
}

func webClientKeyRequest(t *testing.T, method, path, cookie, csrfToken string, body map[string]any) *httptest.ResponseRecorder {
	asJSON, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, path, bytes.NewBuffer(asJSON))
	require.NoError(t, err)
	setJWTCookieForReq(req, cookie)
	setCSRFHeaderForReq(req, csrfToken)
	return executeRequest(req)
}

func TestWebClientAPIKeys(t *testing.T) {
	user := addSelfServiceUser(t, "webclient_keys")
	other := addSelfServiceUser(t, "webclient_keys_other")
	_, otherKeyID := createUserAPIKey(t, userTokenFor(t, other), "not yours")

	cookie, err := getJWTWebClientTokenFromTestServer(user.Username, user.Password)
	require.NoError(t, err)
	csrfToken, err := getCSRFTokenFromInternalPageMock(webClientProfilePath, cookie)
	require.NoError(t, err)

	rr := webClientRequest(t, http.MethodGet, webClientAPIKeysPath, cookie)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Contains(t, rr.Body.String(), `id="add-key"`)

	body := map[string]any{"name": "from the web", "web_session": true}
	// A form token is what stops another site from creating a key with the user's cookie.
	checkResponseCode(t, http.StatusForbidden, webClientKeyRequest(t, http.MethodPost, webClientAPIKeysPath, cookie, "", body))

	rr = webClientKeyRequest(t, http.MethodPost, webClientAPIKeysPath, cookie, csrfToken, body)
	checkResponseCode(t, http.StatusCreated, rr)
	var created map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	keyID, _, ok := strings.Cut(created["key"], ".")
	require.True(t, ok)
	checkResponseCode(t, http.StatusOK, listUserDirsWithKey(t, created["key"]))
	checkResponseCode(t, http.StatusOK, openWebSession(t, created["key"]))

	rr = webClientRequest(t, http.MethodGet, webClientAPIKeysPath+"/json", cookie)
	checkResponseCode(t, http.StatusOK, rr)
	var keys []dataprovider.APIKey
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &keys))
	require.Len(t, keys, 1, "only the user's own keys")
	assert.Equal(t, keyID, keys[0].KeyID)
	assert.Equal(t, dataprovider.APIKeyScopeUserWebSession, keys[0].Scope)
	assert.Empty(t, keys[0].Key, "the stored hash stays on the server")

	checkResponseCode(t, http.StatusNotFound, webClientKeyRequest(t, http.MethodDelete,
		webClientAPIKeysPath+"/"+otherKeyID, cookie, csrfToken, nil))
	checkResponseCode(t, http.StatusForbidden, webClientKeyRequest(t, http.MethodDelete,
		webClientAPIKeysPath+"/"+keyID, cookie, "", nil))
	checkResponseCode(t, http.StatusOK, webClientKeyRequest(t, http.MethodDelete,
		webClientAPIKeysPath+"/"+keyID, cookie, csrfToken, nil))
	assert.NotEqual(t, http.StatusOK, listUserDirsWithKey(t, created["key"]).Code)
}

func TestWebClientAPIKeysAreClosedToKeySessions(t *testing.T) {
	user := addSelfServiceUser(t, "webclient_keys_session")
	token := userTokenFor(t, user)
	key, keyID := createWebSessionKey(t, token, "session")
	_, otherID := createUserAPIKey(t, token, "other")
	cookie := webSessionCookie(t, key)
	// A real form token, so that only the session check can refuse these requests.
	page := webClientRequest(t, http.MethodGet, webClientFilesPath, cookie)
	checkResponseCode(t, http.StatusOK, page)
	match := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindStringSubmatch(page.Body.String())
	require.Len(t, match, 2)
	csrfToken := match[1]

	// A stolen key must not be able to create the next one, or revoke the owner's.
	checkResponseCode(t, http.StatusForbidden, webClientRequest(t, http.MethodGet, webClientAPIKeysPath, cookie))
	checkResponseCode(t, http.StatusForbidden, webClientRequest(t, http.MethodGet, webClientAPIKeysPath+"/json", cookie))
	checkResponseCode(t, http.StatusForbidden, webClientFormRequest(t, http.MethodPost, webClientAPIKeysPath, cookie))
	checkResponseCode(t, http.StatusForbidden, webClientKeyRequest(t, http.MethodDelete,
		webClientAPIKeysPath+"/"+otherID, cookie, csrfToken, nil))

	rr := webClientRequest(t, http.MethodGet, webClientFilesPath, cookie)
	checkResponseCode(t, http.StatusOK, rr)
	assert.NotContains(t, rr.Body.String(), webClientAPIKeysPath, "the page must not offer them either")

	checkResponseCode(t, http.StatusOK, deleteUserAPIKeyAs(t, keyID, token, ""))
	checkResponseCode(t, http.StatusOK, deleteUserAPIKeyAs(t, otherID, token, ""))
}

func TestWebClientAPIKeysPermission(t *testing.T) {
	user := addSelfServiceUser(t, "webclient_keys_denied")
	user.Filters.WebClient = []string{sdk.WebClientAPIKeyAuthChangeDisabled}
	_, _, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	require.NoError(t, err)

	cookie, err := getJWTWebClientTokenFromTestServer(user.Username, user.Password)
	require.NoError(t, err)
	checkResponseCode(t, http.StatusForbidden, webClientRequest(t, http.MethodGet, webClientAPIKeysPath, cookie))
	checkResponseCode(t, http.StatusForbidden, webClientFormRequest(t, http.MethodPost, webClientAPIKeysPath, cookie))
	rr := webClientRequest(t, http.MethodGet, webClientFilesPath, cookie)
	checkResponseCode(t, http.StatusOK, rr)
	assert.NotContains(t, rr.Body.String(), webClientAPIKeysPath)
}

func TestWebClientDirPermissionsHeader(t *testing.T) {
	user := addSelfServiceUser(t, "webclient_dir_perms")
	user.Permissions["/readonly"] = []string{dataprovider.PermListItems, dataprovider.PermDownload}
	_, _, err := httpdtest.UpdateUser(user, http.StatusOK, "")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(user.GetHomeDir(), "readonly"), os.ModePerm))

	cookie, err := getJWTWebClientTokenFromTestServer(user.Username, user.Password)
	require.NoError(t, err)
	rr := webClientRequest(t, http.MethodGet, webClientDirsPath+"?path=%2F", cookie)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, "add,mkdir,rename,delete,download,copy", rr.Header().Get("X-SFTPGO-DIR-PERMISSIONS"))
	rr = webClientRequest(t, http.MethodGet, webClientDirsPath+"?path=%2Freadonly", cookie)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, "download", rr.Header().Get("X-SFTPGO-DIR-PERMISSIONS"))
}

// The WebClient was rewritten so that it no longer depends on the proprietary theme in
// static/assets, which only WebAdmin may use. This keeps it that way.
func TestWebClientStaysFreeOfTheTheme(t *testing.T) {
	forbidden := []string{"/assets/", "ki-duotone", "ki-outline", "data-kt", "keenthemes", "bootstrap", "KTThemeMode",
		"jquery", "{{template \"base\"", "{{template \"baselogin\""}
	for _, root := range []string{filepath.Join("..", "..", "templates", "webclient"), filepath.Join("..", "..", "static", "webclient")} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			extension := filepath.Ext(path)
			if entry.IsDir() || (extension != ".html" && extension != ".js" && extension != ".css") {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, text := range forbidden {
				assert.NotContains(t, strings.ToLower(string(content)), strings.ToLower(text), path)
			}
			return nil
		})
		require.NoError(t, err)
	}
	user := addSelfServiceUser(t, "webclient_theme")
	cookie, err := getJWTWebClientTokenFromTestServer(user.Username, user.Password)
	require.NoError(t, err)
	for _, page := range []string{webClientLoginPath, webClientFilesPath, webClientSharesPath, webClientProfilePath, webClientMFAPath} {
		assert.NotContains(t, webClientRequest(t, http.MethodGet, page, cookie).Body.String(), "/static/assets/", page)
	}
}
