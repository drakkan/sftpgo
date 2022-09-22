// Copyright (C) 2019-2022  Nicola Murino
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package httpd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	oidcMockAddr = "127.0.0.1:11111"
)

type mockTokenSource struct {
	token *oauth2.Token
	err   error
}

func (t *mockTokenSource) Token() (*oauth2.Token, error) {
	return t.token, t.err
}

type mockOAuth2Config struct {
	tokenSource *mockTokenSource
	authCodeURL string
	token       *oauth2.Token
	err         error
}

func (c *mockOAuth2Config) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return c.authCodeURL
}

func (c *mockOAuth2Config) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return c.token, c.err
}

func (c *mockOAuth2Config) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	return c.tokenSource
}

type mockOIDCVerifier struct {
	token *oidc.IDToken
	err   error
}

func (v *mockOIDCVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return v.token, v.err
}

// hack because the field is unexported
func setIDTokenClaims(idToken *oidc.IDToken, claims []byte) {
	pointerVal := reflect.ValueOf(idToken)
	val := reflect.Indirect(pointerVal)
	member := val.FieldByName("claims")
	ptr := unsafe.Pointer(member.UnsafeAddr())
	realPtr := (*[]byte)(ptr)
	*realPtr = claims
}

func TestOIDCInitialization(t *testing.T) {
	config := OIDC{}
	err := config.initialize()
	assert.NoError(t, err)
	config = OIDC{
		ClientID:        "sftpgo-client",
		ClientSecret:    "jRsmE0SWnuZjP7djBqNq0mrf8QN77j2c",
		ConfigURL:       fmt.Sprintf("http://%v/", oidcMockAddr),
		RedirectBaseURL: "http://127.0.0.1:8081/",
		UsernameField:   "preferred_username",
		RoleField:       "sftpgo_role",
	}
	err = config.initialize()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "oidc: required scope \"openid\" is not set")
	}
	config.Scopes = []string{oidc.ScopeOpenID}
	err = config.initialize()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "oidc: unable to initialize provider")
	}
	config.ConfigURL = fmt.Sprintf("http://%v/auth/realms/sftpgo", oidcMockAddr)
	err = config.initialize()
	assert.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8081"+webOIDCRedirectPath, config.getRedirectURL())
}

func TestOIDCLoginLogout(t *testing.T) {
	oidcMgr, ok := oidcMgr.(*memoryOIDCManager)
	require.True(t, ok)
	server := getTestOIDCServer()
	err := server.binding.OIDC.initialize()
	assert.NoError(t, err)
	server.initializeRouter()

	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, webOIDCRedirectPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Authentication state did not match")

	expiredAuthReq := oidcPendingAuth{
		State:    xid.New().String(),
		Nonce:    xid.New().String(),
		Audience: tokenAudienceWebClient,
		IssuedAt: util.GetTimeAsMsSinceEpoch(time.Now().Add(-10 * time.Minute)),
	}
	oidcMgr.addPendingAuth(expiredAuthReq)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+expiredAuthReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Authentication state did not match")
	oidcMgr.removePendingAuth(expiredAuthReq.State)

	server.binding.OIDC.oauth2Config = &mockOAuth2Config{
		tokenSource: &mockTokenSource{},
		authCodeURL: webOIDCRedirectPath,
		err:         common.ErrGenericFailure,
	}
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err: common.ErrGenericFailure,
	}

	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webAdminOIDCLoginPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webOIDCRedirectPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 1)
	var state string
	for k := range oidcMgr.pendingAuths {
		state = k
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+state, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webAdminLoginPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	// now the same for the web client
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientOIDCLoginPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webOIDCRedirectPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 1)
	for k := range oidcMgr.pendingAuths {
		state = k
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+state, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientLoginPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	// now return an OAuth2 token without the id_token
	server.binding.OIDC.oauth2Config = &mockOAuth2Config{
		tokenSource: &mockTokenSource{},
		authCodeURL: webOIDCRedirectPath,
		token: &oauth2.Token{
			AccessToken: "123",
			Expiry:      time.Now().Add(5 * time.Minute),
		},
		err: nil,
	}
	authReq := newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	// now fail to verify the id token
	token := &oauth2.Token{
		AccessToken: "123",
		Expiry:      time.Now().Add(5 * time.Minute),
	}
	token = token.WithExtra(map[string]any{
		"id_token": "id_token_val",
	})
	server.binding.OIDC.oauth2Config = &mockOAuth2Config{
		tokenSource: &mockTokenSource{},
		authCodeURL: webOIDCRedirectPath,
		token:       token,
		err:         nil,
	}
	authReq = newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	// id token nonce does not match
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: &oidc.IDToken{},
	}
	authReq = newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	// null id token claims
	authReq = newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err: nil,
		token: &oidc.IDToken{
			Nonce: authReq.Nonce,
		},
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	// invalid id token claims (no username)
	authReq = newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	idToken := &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"aud": "my_client_id"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	// invalid audience
	authReq = newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	idToken = &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"test","sftpgo_role":"admin"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	// invalid audience
	authReq = newOIDCPendingAuth(tokenAudienceWebAdmin)
	oidcMgr.addPendingAuth(authReq)
	idToken = &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"test"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	// mapped user not found
	authReq = newOIDCPendingAuth(tokenAudienceWebAdmin)
	oidcMgr.addPendingAuth(authReq)
	idToken = &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"test","sftpgo_role":"admin"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	// admin login ok
	authReq = newOIDCPendingAuth(tokenAudienceWebAdmin)
	oidcMgr.addPendingAuth(authReq)
	idToken = &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"admin","sftpgo_role":"admin","sid":"sid123"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webUsersPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	require.Len(t, oidcMgr.tokens, 1)
	// admin profile is not available
	var tokenCookie string
	for k := range oidcMgr.tokens {
		tokenCookie = k
	}
	oidcToken, err := oidcMgr.getToken(tokenCookie)
	assert.NoError(t, err)
	assert.Equal(t, "sid123", oidcToken.SessionID)
	assert.True(t, oidcToken.isAdmin())
	assert.False(t, oidcToken.isExpired())
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webAdminProfilePath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	// the admin can access the allowed pages
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webUsersPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	// try with an invalid cookie
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webUsersPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, xid.New().String()))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))
	// Web Client is not available with an admin token
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	// logout the admin user
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webLogoutPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	require.Len(t, oidcMgr.tokens, 0)
	// now login and logout a user
	username := "test_oidc_user"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Password: "pwd",
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
		Filters: dataprovider.UserFilters{
			BaseUserFilters: sdk.BaseUserFilters{
				WebClient: []string{sdk.WebClientSharesDisabled},
			},
		},
	}
	err = dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)

	authReq = newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	idToken = &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"test_oidc_user"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientFilesPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	require.Len(t, oidcMgr.tokens, 1)
	// user profile is not available
	for k := range oidcMgr.tokens {
		tokenCookie = k
	}
	oidcToken, err = oidcMgr.getToken(tokenCookie)
	assert.NoError(t, err)
	assert.Empty(t, oidcToken.SessionID)
	assert.False(t, oidcToken.isAdmin())
	assert.False(t, oidcToken.isExpired())
	if assert.Len(t, oidcToken.Permissions, 1) {
		assert.Equal(t, sdk.WebClientSharesDisabled, oidcToken.Permissions[0])
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientProfilePath, nil)
	assert.NoError(t, err)
	r.RequestURI = webClientProfilePath
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	// the user can access the allowed pages
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusOK, rr.Code)
	// try with an invalid cookie
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, xid.New().String()))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	// Web Admin is not available with a client cookie
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webUsersPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))
	// logout the user
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientLogoutPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	require.Len(t, oidcMgr.tokens, 0)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
}

func TestOIDCRefreshToken(t *testing.T) {
	oidcMgr, ok := oidcMgr.(*memoryOIDCManager)
	require.True(t, ok)
	r, err := http.NewRequest(http.MethodGet, webUsersPath, nil)
	assert.NoError(t, err)
	token := oidcToken{
		Cookie:      xid.New().String(),
		AccessToken: xid.New().String(),
		TokenType:   "Bearer",
		ExpiresAt:   util.GetTimeAsMsSinceEpoch(time.Now().Add(-1 * time.Minute)),
		Nonce:       xid.New().String(),
		Role:        adminRoleFieldValue,
		Username:    defaultAdminUsername,
	}
	config := mockOAuth2Config{
		tokenSource: &mockTokenSource{
			err: common.ErrGenericFailure,
		},
	}
	verifier := mockOIDCVerifier{
		err: common.ErrGenericFailure,
	}
	err = token.refresh(&config, &verifier, r)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "refresh token not set")
	}
	token.RefreshToken = xid.New().String()
	err = token.refresh(&config, &verifier, r)
	assert.ErrorIs(t, err, common.ErrGenericFailure)

	newToken := &oauth2.Token{
		AccessToken:  xid.New().String(),
		RefreshToken: xid.New().String(),
		Expiry:       time.Now().Add(5 * time.Minute),
	}
	config = mockOAuth2Config{
		tokenSource: &mockTokenSource{
			token: newToken,
		},
	}
	verifier = mockOIDCVerifier{
		token: &oidc.IDToken{},
	}
	err = token.refresh(&config, &verifier, r)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "the refreshed token has no id token")
	}
	newToken = newToken.WithExtra(map[string]any{
		"id_token": "id_token_val",
	})
	newToken.Expiry = time.Time{}
	config = mockOAuth2Config{
		tokenSource: &mockTokenSource{
			token: newToken,
		},
	}
	verifier = mockOIDCVerifier{
		err: common.ErrGenericFailure,
	}
	err = token.refresh(&config, &verifier, r)
	assert.ErrorIs(t, err, common.ErrGenericFailure)

	newToken = newToken.WithExtra(map[string]any{
		"id_token": "id_token_val",
	})
	newToken.Expiry = time.Now().Add(5 * time.Minute)
	config = mockOAuth2Config{
		tokenSource: &mockTokenSource{
			token: newToken,
		},
	}
	verifier = mockOIDCVerifier{
		token: &oidc.IDToken{},
	}
	err = token.refresh(&config, &verifier, r)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "the refreshed token nonce mismatch")
	}
	verifier = mockOIDCVerifier{
		token: &oidc.IDToken{
			Nonce: token.Nonce,
		},
	}
	err = token.refresh(&config, &verifier, r)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "oidc: claims not set")
	}
	idToken := &oidc.IDToken{
		Nonce: token.Nonce,
	}
	setIDTokenClaims(idToken, []byte(`{"sid":"id_token_sid"}`))
	verifier = mockOIDCVerifier{
		token: idToken,
	}
	err = token.refresh(&config, &verifier, r)
	assert.NoError(t, err)
	assert.Len(t, token.Permissions, 1)
	token.Role = nil
	// user does not exist
	err = token.refresh(&config, &verifier, r)
	assert.Error(t, err)
	require.Len(t, oidcMgr.tokens, 1)
	oidcMgr.removeToken(token.Cookie)
	require.Len(t, oidcMgr.tokens, 0)
}

func TestOIDCRefreshUser(t *testing.T) {
	token := oidcToken{
		Cookie:      xid.New().String(),
		AccessToken: xid.New().String(),
		TokenType:   "Bearer",
		ExpiresAt:   util.GetTimeAsMsSinceEpoch(time.Now().Add(1 * time.Minute)),
		Nonce:       xid.New().String(),
		Role:        adminRoleFieldValue,
		Username:    "missing username",
	}
	r, err := http.NewRequest(http.MethodGet, webUsersPath, nil)
	assert.NoError(t, err)
	err = token.refreshUser(r)
	assert.Error(t, err)
	admin := dataprovider.Admin{
		Username:    "test_oidc_admin_refresh",
		Password:    "p",
		Permissions: []string{dataprovider.PermAdminAny},
		Status:      0,
		Filters: dataprovider.AdminFilters{
			Preferences: dataprovider.AdminPreferences{
				HideUserPageSections: 1 + 2 + 4,
			},
		},
	}
	err = dataprovider.AddAdmin(&admin, "", "")
	assert.NoError(t, err)

	token.Username = admin.Username
	err = token.refreshUser(r)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is disabled")
	}

	admin.Status = 1
	err = dataprovider.UpdateAdmin(&admin, "", "")
	assert.NoError(t, err)
	err = token.refreshUser(r)
	assert.NoError(t, err)
	assert.Equal(t, admin.Permissions, token.Permissions)
	assert.Equal(t, admin.Filters.Preferences.HideUserPageSections, token.HideUserPageSections)

	err = dataprovider.DeleteAdmin(admin.Username, "", "")
	assert.NoError(t, err)

	username := "test_oidc_user_refresh_token"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Password: "p",
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   0,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
		Filters: dataprovider.UserFilters{
			BaseUserFilters: sdk.BaseUserFilters{
				DeniedProtocols: []string{common.ProtocolHTTP},
				WebClient:       []string{sdk.WebClientSharesDisabled, sdk.WebClientWriteDisabled},
			},
		},
	}
	err = dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)

	r, err = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	assert.NoError(t, err)
	token.Role = nil
	token.Username = username
	assert.False(t, token.isAdmin())
	err = token.refreshUser(r)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is disabled")
	}
	user, err = dataprovider.UserExists(username)
	assert.NoError(t, err)
	user.Status = 1
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	err = token.refreshUser(r)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "protocol HTTP is not allowed")
	}

	user.Filters.DeniedProtocols = []string{common.ProtocolFTP}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	err = token.refreshUser(r)
	assert.NoError(t, err)
	assert.Equal(t, user.Filters.WebClient, token.Permissions)

	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
}

func TestValidateOIDCToken(t *testing.T) {
	oidcMgr, ok := oidcMgr.(*memoryOIDCManager)
	require.True(t, ok)
	server := getTestOIDCServer()
	err := server.binding.OIDC.initialize()
	assert.NoError(t, err)
	server.initializeRouter()

	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, webClientLogoutPath, nil)
	assert.NoError(t, err)
	_, err = server.validateOIDCToken(rr, r, false)
	assert.ErrorIs(t, err, errInvalidToken)
	// expired token and refresh error
	server.binding.OIDC.oauth2Config = &mockOAuth2Config{
		tokenSource: &mockTokenSource{
			err: common.ErrGenericFailure,
		},
	}
	token := oidcToken{
		Cookie:      xid.New().String(),
		AccessToken: xid.New().String(),
		ExpiresAt:   util.GetTimeAsMsSinceEpoch(time.Now().Add(-2 * time.Minute)),
	}
	oidcMgr.addToken(token)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientLogoutPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, token.Cookie))
	_, err = server.validateOIDCToken(rr, r, false)
	assert.ErrorIs(t, err, errInvalidToken)
	oidcMgr.removeToken(token.Cookie)
	assert.Len(t, oidcMgr.tokens, 0)

	server.tokenAuth = jwtauth.New("PS256", util.GenerateRandomBytes(32), nil)
	token = oidcToken{
		Cookie:      xid.New().String(),
		AccessToken: xid.New().String(),
	}
	oidcMgr.addToken(token)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientLogoutPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, token.Cookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	oidcMgr.removeToken(token.Cookie)
	assert.Len(t, oidcMgr.tokens, 0)

	token = oidcToken{
		Cookie:      xid.New().String(),
		AccessToken: xid.New().String(),
		Role:        "admin",
	}
	oidcMgr.addToken(token)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webLogoutPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, token.Cookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))
	oidcMgr.removeToken(token.Cookie)
	assert.Len(t, oidcMgr.tokens, 0)
}

func TestSkipOIDCAuth(t *testing.T) {
	server := getTestOIDCServer()
	err := server.binding.OIDC.initialize()
	assert.NoError(t, err)
	server.initializeRouter()
	jwtTokenClaims := jwtTokenClaims{
		Username: "user",
	}
	_, tokenString, err := jwtTokenClaims.createToken(server.tokenAuth, tokenAudienceWebClient, "")
	assert.NoError(t, err)
	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, webClientLogoutPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", jwtCookieKey, tokenString))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
}

func TestOIDCLogoutErrors(t *testing.T) {
	server := getTestOIDCServer()
	assert.Empty(t, server.binding.OIDC.providerLogoutURL)
	server.logoutFromOIDCOP("")
	server.binding.OIDC.providerLogoutURL = "http://foo\x7f.com/"
	server.doOIDCFromLogout("")
	server.binding.OIDC.providerLogoutURL = "http://127.0.0.1:11234"
	server.doOIDCFromLogout("")
}

func TestOIDCToken(t *testing.T) {
	admin := dataprovider.Admin{
		Username:    "test_oidc_admin",
		Password:    "p",
		Permissions: []string{dataprovider.PermAdminAny},
		Status:      0,
	}
	err := dataprovider.AddAdmin(&admin, "", "")
	assert.NoError(t, err)

	token := oidcToken{
		Username: admin.Username,
		Role:     "admin",
	}
	req, err := http.NewRequest(http.MethodGet, webUsersPath, nil)
	assert.NoError(t, err)
	err = token.getUser(req)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is disabled")
	}
	err = dataprovider.DeleteAdmin(admin.Username, "", "")
	assert.NoError(t, err)

	username := "test_oidc_user"
	token.Username = username
	token.Role = ""
	err = token.getUser(req)
	if assert.Error(t, err) {
		_, ok := err.(*util.RecordNotFoundError)
		assert.True(t, ok)
	}

	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Password: "p",
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   0,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
		Filters: dataprovider.UserFilters{
			BaseUserFilters: sdk.BaseUserFilters{
				DeniedProtocols: []string{common.ProtocolHTTP},
			},
		},
	}
	err = dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)
	err = token.getUser(req)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "is disabled")
	}
	user, err = dataprovider.UserExists(username)
	assert.NoError(t, err)
	user.Status = 1
	user.Password = "np"
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)

	err = token.getUser(req)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "protocol HTTP is not allowed")
	}

	user.Filters.DeniedProtocols = nil
	user.FsConfig.Provider = sdk.SFTPFilesystemProvider
	user.FsConfig.SFTPConfig = vfs.SFTPFsConfig{
		BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
			Endpoint: "127.0.0.1:8022",
			Username: username,
		},
		Password: kms.NewPlainSecret("np"),
	}
	err = dataprovider.UpdateUser(&user, "", "")
	assert.NoError(t, err)
	err = token.getUser(req)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "SFTP loop")
	}

	common.Config.PostConnectHook = fmt.Sprintf("http://%v/404", oidcMockAddr)

	err = token.getUser(req)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "access denied by post connect hook")
	}

	common.Config.PostConnectHook = ""

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
}

func TestOIDCImplicitRoles(t *testing.T) {
	oidcMgr, ok := oidcMgr.(*memoryOIDCManager)
	require.True(t, ok)

	server := getTestOIDCServer()
	server.binding.OIDC.ImplicitRoles = true
	err := server.binding.OIDC.initialize()
	assert.NoError(t, err)
	server.initializeRouter()

	authReq := newOIDCPendingAuth(tokenAudienceWebAdmin)
	oidcMgr.addPendingAuth(authReq)
	token := &oauth2.Token{
		AccessToken: "1234",
		Expiry:      time.Now().Add(5 * time.Minute),
	}
	token = token.WithExtra(map[string]any{
		"id_token": "id_token_val",
	})
	server.binding.OIDC.oauth2Config = &mockOAuth2Config{
		tokenSource: &mockTokenSource{},
		authCodeURL: webOIDCRedirectPath,
		token:       token,
	}
	idToken := &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"admin","sid":"sid456"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webUsersPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	require.Len(t, oidcMgr.tokens, 1)
	var tokenCookie string
	for k := range oidcMgr.tokens {
		tokenCookie = k
	}
	// Web Client is not available with an admin token
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientFilesPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	// logout the admin user
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webLogoutPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webAdminLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	require.Len(t, oidcMgr.tokens, 0)
	// now login and logout a user
	username := "test_oidc_implicit_user"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Password: "pwd",
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
		Filters: dataprovider.UserFilters{
			BaseUserFilters: sdk.BaseUserFilters{
				WebClient: []string{sdk.WebClientSharesDisabled},
			},
		},
	}
	err = dataprovider.AddUser(&user, "", "")
	assert.NoError(t, err)

	authReq = newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	idToken = &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"test_oidc_implicit_user"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientFilesPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	require.Len(t, oidcMgr.tokens, 1)
	for k := range oidcMgr.tokens {
		tokenCookie = k
	}

	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webClientLogoutPath, nil)
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	require.Len(t, oidcMgr.pendingAuths, 0)
	require.Len(t, oidcMgr.tokens, 0)

	err = os.RemoveAll(user.GetHomeDir())
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
}

func TestMemoryOIDCManager(t *testing.T) {
	oidcMgr, ok := oidcMgr.(*memoryOIDCManager)
	require.True(t, ok)
	require.Len(t, oidcMgr.pendingAuths, 0)
	authReq := newOIDCPendingAuth(tokenAudienceWebAdmin)
	oidcMgr.addPendingAuth(authReq)
	require.Len(t, oidcMgr.pendingAuths, 1)
	_, err := oidcMgr.getPendingAuth(authReq.State)
	assert.NoError(t, err)
	oidcMgr.removePendingAuth(authReq.State)
	require.Len(t, oidcMgr.pendingAuths, 0)
	authReq.IssuedAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-61 * time.Second))
	oidcMgr.addPendingAuth(authReq)
	require.Len(t, oidcMgr.pendingAuths, 1)
	_, err = oidcMgr.getPendingAuth(authReq.State)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "too old")
	}
	oidcMgr.cleanup()
	require.Len(t, oidcMgr.pendingAuths, 0)

	token := oidcToken{
		AccessToken: xid.New().String(),
		Nonce:       xid.New().String(),
		SessionID:   xid.New().String(),
		Cookie:      xid.New().String(),
		Username:    xid.New().String(),
		Role:        "admin",
		Permissions: []string{dataprovider.PermAdminAny},
	}
	require.Len(t, oidcMgr.tokens, 0)
	oidcMgr.addToken(token)
	require.Len(t, oidcMgr.tokens, 1)
	_, err = oidcMgr.getToken(xid.New().String())
	assert.Error(t, err)
	storedToken, err := oidcMgr.getToken(token.Cookie)
	assert.NoError(t, err)
	token.UsedAt = 0 // ensure we don't modify the stored token
	assert.Greater(t, storedToken.UsedAt, int64(0))
	token.UsedAt = storedToken.UsedAt
	assert.Equal(t, token, storedToken)
	// the usage will not be updated, it is recent
	oidcMgr.updateTokenUsage(storedToken)
	storedToken, err = oidcMgr.getToken(token.Cookie)
	assert.NoError(t, err)
	assert.Equal(t, token, storedToken)
	usedAt := util.GetTimeAsMsSinceEpoch(time.Now().Add(-5 * time.Minute))
	storedToken.UsedAt = usedAt
	oidcMgr.tokens[token.Cookie] = storedToken
	storedToken, err = oidcMgr.getToken(token.Cookie)
	assert.NoError(t, err)
	assert.Equal(t, usedAt, storedToken.UsedAt)
	token.UsedAt = storedToken.UsedAt
	assert.Equal(t, token, storedToken)
	oidcMgr.updateTokenUsage(storedToken)
	storedToken, err = oidcMgr.getToken(token.Cookie)
	assert.NoError(t, err)
	assert.Greater(t, storedToken.UsedAt, usedAt)
	token.UsedAt = storedToken.UsedAt
	assert.Equal(t, token, storedToken)
	storedToken.UsedAt = util.GetTimeAsMsSinceEpoch(time.Now()) - tokenDeleteInterval - 1
	oidcMgr.tokens[token.Cookie] = storedToken
	storedToken, err = oidcMgr.getToken(token.Cookie)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "token is too old")
	}
	oidcMgr.removeToken(xid.New().String())
	require.Len(t, oidcMgr.tokens, 1)
	oidcMgr.removeToken(token.Cookie)
	require.Len(t, oidcMgr.tokens, 0)
	oidcMgr.addToken(token)
	usedAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-6 * time.Hour))
	token.UsedAt = usedAt
	oidcMgr.tokens[token.Cookie] = token
	newToken := oidcToken{
		Cookie: xid.New().String(),
	}
	oidcMgr.addToken(newToken)
	oidcMgr.cleanup()
	require.Len(t, oidcMgr.tokens, 1)
	_, err = oidcMgr.getToken(token.Cookie)
	assert.Error(t, err)
	_, err = oidcMgr.getToken(newToken.Cookie)
	assert.NoError(t, err)
	oidcMgr.removeToken(newToken.Cookie)
	require.Len(t, oidcMgr.tokens, 0)
}

func TestOIDCPreLoginHook(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	oidcMgr, ok := oidcMgr.(*memoryOIDCManager)
	require.True(t, ok)
	username := "test_oidc_user_prelogin"
	u := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			HomeDir:  filepath.Join(os.TempDir(), username),
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
	}
	preLoginPath := filepath.Join(os.TempDir(), "prelogin.sh")
	providerConf := dataprovider.GetProviderConfig()
	err := dataprovider.Close()
	assert.NoError(t, err)
	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(u, false), os.ModePerm)
	assert.NoError(t, err)
	newProviderConf := providerConf
	newProviderConf.PreLoginHook = preLoginPath
	err = dataprovider.Initialize(newProviderConf, configDir, true)
	assert.NoError(t, err)
	server := getTestOIDCServer()
	server.binding.OIDC.CustomFields = []string{"field1", "field2"}
	err = server.binding.OIDC.initialize()
	assert.NoError(t, err)
	server.initializeRouter()

	_, err = dataprovider.UserExists(username)
	_, ok = err.(*util.RecordNotFoundError)
	assert.True(t, ok)
	// now login with OIDC
	authReq := newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	token := &oauth2.Token{
		AccessToken: "1234",
		Expiry:      time.Now().Add(5 * time.Minute),
	}
	token = token.WithExtra(map[string]any{
		"id_token": "id_token_val",
	})
	server.binding.OIDC.oauth2Config = &mockOAuth2Config{
		tokenSource: &mockTokenSource{},
		authCodeURL: webOIDCRedirectPath,
		token:       token,
	}
	idToken := &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"`+username+`"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientFilesPath, rr.Header().Get("Location"))
	_, err = dataprovider.UserExists(username)
	assert.NoError(t, err)

	err = dataprovider.DeleteUser(username, "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(u.HomeDir)
	assert.NoError(t, err)

	err = os.WriteFile(preLoginPath, getPreLoginScriptContent(u, true), os.ModePerm)
	assert.NoError(t, err)

	authReq = newOIDCPendingAuth(tokenAudienceWebClient)
	oidcMgr.addPendingAuth(authReq)
	idToken = &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"`+username+`","field1":"value1","field2":"value2","field3":"value3"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webClientLoginPath, rr.Header().Get("Location"))
	_, err = dataprovider.UserExists(username)
	_, ok = err.(*util.RecordNotFoundError)
	assert.True(t, ok)
	if assert.Len(t, oidcMgr.tokens, 1) {
		for k := range oidcMgr.tokens {
			oidcMgr.removeToken(k)
		}
	}
	require.Len(t, oidcMgr.pendingAuths, 0)
	require.Len(t, oidcMgr.tokens, 0)

	err = dataprovider.Close()
	assert.NoError(t, err)
	err = dataprovider.Initialize(providerConf, configDir, true)
	assert.NoError(t, err)
	err = os.Remove(preLoginPath)
	assert.NoError(t, err)
}

func TestOIDCIsAdmin(t *testing.T) {
	type test struct {
		input any
		want  bool
	}

	emptySlice := make([]any, 0)

	tests := []test{
		{input: "admin", want: true},
		{input: append(emptySlice, "admin"), want: true},
		{input: append(emptySlice, "user", "admin"), want: true},
		{input: "user", want: false},
		{input: emptySlice, want: false},
		{input: append(emptySlice, 1), want: false},
		{input: 1, want: false},
		{input: nil, want: false},
		{input: map[string]string{"admin": "admin"}, want: false},
	}
	for _, tc := range tests {
		token := oidcToken{
			Role: tc.input,
		}
		assert.Equal(t, tc.want, token.isAdmin(), "%v should return %t", tc.input, tc.want)
	}
}

func TestParseAdminRole(t *testing.T) {
	claims := make(map[string]any)
	rawClaims := []byte(`{
		"sub": "35666371",
		"email": "example@example.com",
		"preferred_username": "Sally",
		"name": "Sally Tyler",
		"updated_at": "2018-04-13T22:08:45Z",
		"given_name": "Sally",
		"family_name": "Tyler",
		"params": {
		  "sftpgo_role": "admin",
		  "subparams": {
			"sftpgo_role": "admin",
			"inner": {
				"sftpgo_role": ["user","admin"]
			}
		  }
		},
		"at_hash": "lPLhxI2wjEndc-WfyroDZA",
		"rt_hash": "mCmxPtA04N-55AxlEUbq-A",
		"aud": "78d1d040-20c9-0136-5146-067351775fae92920",
		"exp": 1523664997,
		"iat": 1523657797
	  }`)
	err := json.Unmarshal(rawClaims, &claims)
	assert.NoError(t, err)

	type test struct {
		input string
		want  bool
	}

	tests := []test{
		{input: "sftpgo_role", want: false},
		{input: "params.sftpgo_role", want: true},
		{input: "params.subparams.sftpgo_role", want: true},
		{input: "params.subparams.inner.sftpgo_role", want: true},
		{input: "email", want: false},
		{input: "missing", want: false},
		{input: "params.email", want: false},
		{input: "missing.sftpgo_role", want: false},
		{input: "params", want: false},
		{input: "params.subparams.inner.sftpgo_role.missing", want: false},
	}

	for _, tc := range tests {
		token := oidcToken{}
		token.getRoleFromField(claims, tc.input)
		assert.Equal(t, tc.want, token.isAdmin(), "%q should return %t", tc.input, tc.want)
	}
}

func TestOIDCWithLoginFormsDisabled(t *testing.T) {
	oidcMgr, ok := oidcMgr.(*memoryOIDCManager)
	require.True(t, ok)

	server := getTestOIDCServer()
	server.binding.OIDC.ImplicitRoles = true
	server.binding.EnabledLoginMethods = 3
	server.binding.EnableWebAdmin = true
	server.binding.EnableWebClient = true
	err := server.binding.OIDC.initialize()
	assert.NoError(t, err)
	server.initializeRouter()
	// login with an admin user
	authReq := newOIDCPendingAuth(tokenAudienceWebAdmin)
	oidcMgr.addPendingAuth(authReq)
	token := &oauth2.Token{
		AccessToken: "1234",
		Expiry:      time.Now().Add(5 * time.Minute),
	}
	token = token.WithExtra(map[string]any{
		"id_token": "id_token_val",
	})
	server.binding.OIDC.oauth2Config = &mockOAuth2Config{
		tokenSource: &mockTokenSource{},
		authCodeURL: webOIDCRedirectPath,
		token:       token,
	}
	idToken := &oidc.IDToken{
		Nonce:  authReq.Nonce,
		Expiry: time.Now().Add(5 * time.Minute),
	}
	setIDTokenClaims(idToken, []byte(`{"preferred_username":"admin","sid":"sid456"}`))
	server.binding.OIDC.verifier = &mockOIDCVerifier{
		err:   nil,
		token: idToken,
	}
	rr := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, webOIDCRedirectPath+"?state="+authReq.State, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, webUsersPath, rr.Header().Get("Location"))
	var tokenCookie string
	for k := range oidcMgr.tokens {
		tokenCookie = k
	}
	// we should be able to create admins without setting a password
	if csrfTokenAuth == nil {
		csrfTokenAuth = jwtauth.New(jwa.HS256.String(), util.GenerateRandomBytes(32), nil)
	}
	adminUsername := "testAdmin"
	form := make(url.Values)
	form.Set(csrfFormToken, createCSRFToken(""))
	form.Set("username", adminUsername)
	form.Set("password", "")
	form.Set("status", "1")
	form.Set("permissions", "*")
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminPath, bytes.NewBuffer([]byte(form.Encode())))
	assert.NoError(t, err)
	r.Header.Set("Cookie", fmt.Sprintf("%v=%v", oidcCookieKey, tokenCookie))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusSeeOther, rr.Code)
	_, err = dataprovider.AdminExists(adminUsername)
	assert.NoError(t, err)
	err = dataprovider.DeleteAdmin(adminUsername, "", "")
	assert.NoError(t, err)
	// login and password related routes are disabled
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminLoginPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webAdminTwoFactorPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webClientLoginPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	rr = httptest.NewRecorder()
	r, err = http.NewRequest(http.MethodPost, webClientForgotPwdPath, nil)
	assert.NoError(t, err)
	server.router.ServeHTTP(rr, r)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestDbOIDCManager(t *testing.T) {
	if !isSharedProviderSupported() {
		t.Skip("this test it is not available with this provider")
	}
	mgr := newOIDCManager(1)
	pendingAuth := newOIDCPendingAuth(tokenAudienceWebAdmin)
	mgr.addPendingAuth(pendingAuth)
	authReq, err := mgr.getPendingAuth(pendingAuth.State)
	assert.NoError(t, err)
	assert.Equal(t, pendingAuth, authReq)
	pendingAuth.IssuedAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-24 * time.Hour))
	mgr.addPendingAuth(pendingAuth)
	_, err = mgr.getPendingAuth(pendingAuth.State)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "auth request is too old")
	}
	mgr.removePendingAuth(pendingAuth.State)
	_, err = mgr.getPendingAuth(pendingAuth.State)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to get the auth request for the specified state")
	}
	mgr.addPendingAuth(pendingAuth)
	_, err = mgr.getPendingAuth(pendingAuth.State)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "auth request is too old")
	}
	mgr.cleanup()
	_, err = mgr.getPendingAuth(pendingAuth.State)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to get the auth request for the specified state")
	}

	token := oidcToken{
		Cookie:       xid.New().String(),
		AccessToken:  xid.New().String(),
		TokenType:    "Bearer",
		RefreshToken: xid.New().String(),
		ExpiresAt:    util.GetTimeAsMsSinceEpoch(time.Now().Add(-2 * time.Minute)),
		SessionID:    xid.New().String(),
		IDToken:      xid.New().String(),
		Nonce:        xid.New().String(),
		Username:     xid.New().String(),
		Permissions:  []string{dataprovider.PermAdminAny},
		Role:         "admin",
	}
	mgr.addToken(token)
	tokenGet, err := mgr.getToken(token.Cookie)
	assert.NoError(t, err)
	assert.Greater(t, tokenGet.UsedAt, int64(0))
	token.UsedAt = tokenGet.UsedAt
	assert.Equal(t, token, tokenGet)
	time.Sleep(100 * time.Millisecond)
	mgr.updateTokenUsage(token)
	// no change
	tokenGet, err = mgr.getToken(token.Cookie)
	assert.NoError(t, err)
	assert.Equal(t, token.UsedAt, tokenGet.UsedAt)
	tokenGet.UsedAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-24 * time.Hour))
	tokenGet.RefreshToken = xid.New().String()
	mgr.updateTokenUsage(tokenGet)
	tokenGet, err = mgr.getToken(token.Cookie)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenGet.RefreshToken)
	assert.NotEqual(t, token.RefreshToken, tokenGet.RefreshToken)
	assert.Greater(t, tokenGet.UsedAt, token.UsedAt)
	mgr.removeToken(token.Cookie)
	tokenGet, err = mgr.getToken(token.Cookie)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to get the token for the specified session")
	}
	// add an expired token
	token.UsedAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(-24 * time.Hour))
	session := dataprovider.Session{
		Key:       token.Cookie,
		Data:      token,
		Type:      dataprovider.SessionTypeOIDCToken,
		Timestamp: token.UsedAt + tokenDeleteInterval,
	}
	err = dataprovider.AddSharedSession(session)
	assert.NoError(t, err)
	_, err = mgr.getToken(token.Cookie)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "token is too old")
	}
	mgr.cleanup()
	_, err = mgr.getToken(token.Cookie)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to get the token for the specified session")
	}
	// adding a session without a key should fail
	session.Key = ""
	err = dataprovider.AddSharedSession(session)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "unable to save a session with an empty key")
	}
	session.Key = xid.New().String()
	session.Type = 1000
	err = dataprovider.AddSharedSession(session)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid session type")
	}

	dbMgr, ok := mgr.(*dbOIDCManager)
	if assert.True(t, ok) {
		_, err = dbMgr.decodePendingAuthData(2)
		assert.Error(t, err)
		_, err = dbMgr.decodeTokenData(true)
		assert.Error(t, err)
	}
}

func getTestOIDCServer() *httpdServer {
	return &httpdServer{
		binding: Binding{
			OIDC: OIDC{
				ClientID:        "sftpgo-client",
				ClientSecret:    "jRsmE0SWnuZjP7djBqNq0mrf8QN77j2c",
				ConfigURL:       fmt.Sprintf("http://%v/auth/realms/sftpgo", oidcMockAddr),
				RedirectBaseURL: "http://127.0.0.1:8081/",
				UsernameField:   "preferred_username",
				RoleField:       "sftpgo_role",
				ImplicitRoles:   false,
				Scopes:          []string{oidc.ScopeOpenID, "profile", "email"},
				CustomFields:    nil,
				Debug:           true,
			},
		},
		enableWebAdmin:  true,
		enableWebClient: true,
	}
}

func getPreLoginScriptContent(user dataprovider.User, nonJSONResponse bool) []byte {
	content := []byte("#!/bin/sh\n\n")
	if nonJSONResponse {
		content = append(content, []byte("echo 'text response'\n")...)
		return content
	}
	if len(user.Username) > 0 {
		u, _ := json.Marshal(user)
		content = append(content, []byte(fmt.Sprintf("echo '%v'\n", string(u)))...)
	}
	return content
}
