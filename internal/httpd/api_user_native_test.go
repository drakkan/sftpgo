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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xrogers/gonas/v2/internal/common"
	"github.com/xrogers/gonas/v2/internal/dataprovider"
	"github.com/xrogers/gonas/v2/internal/httpdtest"
)

const (
	nativeHost            = "files.example.com"
	nativeOrigin          = "http://" + nativeHost
	userTokenPasskeyPath  = "/api/v2/user/token/passkey"
	userTokenRefreshPath  = "/api/v2/user/token/refresh"
	userPasskeysPath      = "/api/v2/user/passkeys"
	userSearchPath        = "/api/v2/user/search"
	userThumbnailPath     = "/api/v2/user/thumbnail"
	webClientPasskeyLogin = "/web/client/login/passkey"
)

// nativeAuthenticator is a key held the way the Android app holds its own: it builds the messages
// of a WebAuthn authenticator itself.
type nativeAuthenticator struct {
	key *ecdsa.PrivateKey
	id  []byte
}

func newNativeAuthenticator(t *testing.T) *nativeAuthenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := make([]byte, 32)
	_, err = rand.Read(id)
	require.NoError(t, err)
	return &nativeAuthenticator{key: key, id: id}
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func clientDataJSON(t *testing.T, kind, challenge string) []byte {
	data, err := json.Marshal(map[string]any{
		"type": kind, "challenge": challenge, "origin": nativeOrigin, "crossOrigin": false,
	})
	require.NoError(t, err)
	return data
}

func (a *nativeAuthenticator) registration(t *testing.T, challenge string) json.RawMessage {
	public, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: a.key.X.FillBytes(make([]byte, 32)),
		YCoord: a.key.Y.FillBytes(make([]byte, 32)),
	})
	require.NoError(t, err)
	rpHash := sha256.Sum256([]byte(nativeHost))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, 0x45, 0, 0, 0, 0) // user present and verified, attested data
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, 0, byte(len(a.id)))
	authData = append(authData, a.id...)
	authData = append(authData, public...)
	attestation, err := webauthncbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{}, "authData": authData,
	})
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{
		"id": b64(a.id), "rawId": b64(a.id), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientDataJSON(t, "webauthn.create", challenge)),
			"attestationObject": b64(attestation),
		},
	})
	require.NoError(t, err)
	return body
}

func (a *nativeAuthenticator) assertion(t *testing.T, challenge, username string) json.RawMessage {
	clientData := clientDataJSON(t, "webauthn.get", challenge)
	rpHash := sha256.Sum256([]byte(nativeHost))
	authData := append(append([]byte{}, rpHash[:]...), 0x05, 0, 0, 0, 0)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{
		"id": b64(a.id), "rawId": b64(a.id), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        b64([]byte(username)),
		},
	})
	require.NoError(t, err)
	return body
}

func nativeRequest(t *testing.T, method, target, token string, body any) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, target, reader)
	require.NoError(t, err)
	req.Host = nativeHost
	if token != "" {
		setBearerForReq(req, token)
	}
	return executeRequest(req)
}

type nativeOptions struct {
	Token   string `json:"token"`
	Options struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
	} `json:"options"`
}

// decodeNative replaces target with the body, as decoding into a slice of maps would merge.
func decodeNative[T any](t *testing.T, rr *httptest.ResponseRecorder, target *T) {
	var zero T
	*target = zero
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), target), rr.Body.String())
}

func registerNativePasskey(t *testing.T, token string, authenticator *nativeAuthenticator) {
	rr := nativeRequest(t, http.MethodPost, userPasskeysPath+"/begin", token, nil)
	checkResponseCode(t, http.StatusOK, rr)
	var begin nativeOptions
	decodeNative(t, rr, &begin)
	assert.Equal(t, nativeHost, begin.Options.RP.ID)
	rr = nativeRequest(t, http.MethodPost, userPasskeysPath+"/finish", token, map[string]any{
		"token":      begin.Token,
		"name":       "Phone",
		"credential": authenticator.registration(t, begin.Options.Challenge),
	})
	checkResponseCode(t, http.StatusOK, rr)
}

func nativePasskeyToken(t *testing.T, authenticator *nativeAuthenticator, username string) *httptest.ResponseRecorder {
	rr := nativeRequest(t, http.MethodGet, userTokenPasskeyPath, "", nil)
	checkResponseCode(t, http.StatusOK, rr)
	var options nativeOptions
	decodeNative(t, rr, &options)
	return nativeRequest(t, http.MethodPost, userTokenPasskeyPath, "", map[string]any{
		"token":      options.Token,
		"credential": authenticator.assertion(t, options.Options.Challenge, username),
	})
}

func TestNativePasskeySignIn(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		assert.NoError(t, os.RemoveAll(user.GetHomeDir()))
	})
	authenticator := newNativeAuthenticator(t)

	rr := nativePasskeyToken(t, authenticator, defaultUsername)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	require.NoError(t, err)
	registerNativePasskey(t, token, authenticator)

	rr = nativeRequest(t, http.MethodGet, userPasskeysPath, token, nil)
	checkResponseCode(t, http.StatusOK, rr)
	var passkeys []map[string]any
	decodeNative(t, rr, &passkeys)
	require.Len(t, passkeys, 1)
	assert.Equal(t, "Phone", passkeys[0]["name"])
	assert.Equal(t, b64(authenticator.id), passkeys[0]["id"])

	rr = nativePasskeyToken(t, authenticator, defaultUsername)
	checkResponseCode(t, http.StatusOK, rr)
	var response map[string]any
	decodeNative(t, rr, &response)
	passkeyToken, ok := response["access_token"].(string)
	require.True(t, ok)
	rr = nativeRequest(t, http.MethodGet, userDirsPath, passkeyToken, nil)
	checkResponseCode(t, http.StatusOK, rr)

	// A challenge is single use.
	rr = nativeRequest(t, http.MethodGet, userTokenPasskeyPath, "", nil)
	var options nativeOptions
	decodeNative(t, rr, &options)
	assertion := authenticator.assertion(t, options.Options.Challenge, defaultUsername)
	body := map[string]any{"token": options.Token, "credential": assertion}
	checkResponseCode(t, http.StatusOK, nativeRequest(t, http.MethodPost, userTokenPasskeyPath, "", body))
	checkResponseCode(t, http.StatusUnauthorized, nativeRequest(t, http.MethodPost, userTokenPasskeyPath, "", body))

	// A challenge of the login page is not one of the API.
	rr = nativeRequest(t, http.MethodGet, webClientPasskeyLogin, "", nil)
	checkResponseCode(t, http.StatusOK, rr)
	decodeNative(t, rr, &options)
	rr = nativeRequest(t, http.MethodPost, userTokenPasskeyPath, "", map[string]any{
		"token":      options.Token,
		"credential": authenticator.assertion(t, options.Options.Challenge, defaultUsername),
	})
	checkResponseCode(t, http.StatusUnauthorized, rr)

	// Another key, not registered, is refused.
	rr = nativePasskeyToken(t, newNativeAuthenticator(t), defaultUsername)
	checkResponseCode(t, http.StatusUnauthorized, rr)

	rr = nativeRequest(t, http.MethodDelete, userPasskeysPath+"/"+b64(authenticator.id), token, nil)
	checkResponseCode(t, http.StatusOK, rr)
	rr = nativePasskeyToken(t, authenticator, defaultUsername)
	checkResponseCode(t, http.StatusUnauthorized, rr)
}

func TestNativePasskeyAsRequiredSecondFactor(t *testing.T) {
	u := getTestUser()
	u.Filters.TwoFactorAuthProtocols = []string{common.ProtocolHTTP}
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		assert.NoError(t, os.RemoveAll(user.GetHomeDir()))
	})
	authenticator := newNativeAuthenticator(t)

	// With 2FA required and not set up, a password token can only set it up.
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	require.NoError(t, err)
	checkResponseCode(t, http.StatusForbidden, nativeRequest(t, http.MethodGet, userDirsPath, token, nil))
	registerNativePasskey(t, token, authenticator)

	// The passkey is now the second factor: the password alone is not enough, as on the web.
	_, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	assert.Error(t, err)

	rr := nativePasskeyToken(t, authenticator, defaultUsername)
	checkResponseCode(t, http.StatusOK, rr)
	var response map[string]any
	decodeNative(t, rr, &response)
	passkeyToken, ok := response["access_token"].(string)
	require.True(t, ok)
	checkResponseCode(t, http.StatusOK, nativeRequest(t, http.MethodGet, userDirsPath, passkeyToken, nil))

	// The last passkey can't be removed while it is the required second factor.
	rr = nativeRequest(t, http.MethodDelete, userPasskeysPath+"/"+b64(authenticator.id), passkeyToken, nil)
	checkResponseCode(t, http.StatusBadRequest, rr)
}

func TestNativePasskeysNeedAccountTokens(t *testing.T) {
	u := getTestUser()
	u.Filters.AllowAPIKeyAuth = true
	user, _, err := httpdtest.AddUser(u, http.StatusCreated)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		assert.NoError(t, os.RemoveAll(user.GetHomeDir()))
	})
	key, _, err := httpdtest.AddAPIKey(dataprovider.APIKey{
		Name: "native", Scope: dataprovider.APIKeyScopeUser, User: defaultUsername,
	}, http.StatusCreated)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := httpdtest.RemoveAPIKey(key, http.StatusOK)
		assert.NoError(t, err)
	})
	req, err := http.NewRequest(http.MethodPost, userPasskeysPath+"/begin", nil)
	require.NoError(t, err)
	req.Host = nativeHost
	setAPIKeyForReq(req, key.Key, "")
	checkResponseCode(t, http.StatusForbidden, executeRequest(req))
}

func TestNativeSearchAndThumbnails(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		assert.NoError(t, os.RemoveAll(user.GetHomeDir()))
	})
	dir := filepath.Join(user.GetHomeDir(), "photos", "2026")
	require.NoError(t, os.MkdirAll(dir, os.ModePerm))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Report.txt"), []byte("report"), 0o600))
	img := image.NewRGBA(image.Rect(0, 0, 40, 30))
	img.Set(1, 1, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beach.png"), buf.Bytes(), 0o600))

	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	require.NoError(t, err)

	rr := nativeRequest(t, http.MethodGet, userSearchPath+"?q=report", token, nil)
	checkResponseCode(t, http.StatusOK, rr)
	var results []map[string]any
	decodeNative(t, rr, &results)
	require.Len(t, results, 1)
	assert.Equal(t, "Report.txt", results[0]["name"])
	assert.Equal(t, "/photos/2026", results[0]["path"])
	assert.EqualValues(t, 6, results[0]["size"])
	assert.Empty(t, rr.Header().Get("X-GONAS-Search-Truncated"))

	rr = nativeRequest(t, http.MethodGet, userSearchPath+"?q=2026&path=/photos", token, nil)
	checkResponseCode(t, http.StatusOK, rr)
	decodeNative(t, rr, &results)
	require.Len(t, results, 1, "folders match too")
	assert.Equal(t, "/photos", results[0]["path"])
	assert.NotContains(t, results[0], "size")

	rr = nativeRequest(t, http.MethodGet, userSearchPath+"?q=", token, nil)
	checkResponseCode(t, http.StatusOK, rr)
	assert.JSONEq(t, "[]", rr.Body.String())

	rr = nativeRequest(t, http.MethodGet, userThumbnailPath+"?path=/photos/2026/beach.png", token, nil)
	checkResponseCode(t, http.StatusOK, rr)
	assert.Equal(t, "image/jpeg", rr.Header().Get("Content-Type"))
	rr = nativeRequest(t, http.MethodGet, userThumbnailPath+"?path=/photos/2026/Report.txt", token, nil)
	checkResponseCode(t, http.StatusNotFound, rr)

	// Without the permission to list, there is nothing to search.
	user.Permissions["/photos"] = []string{dataprovider.PermDownload}
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	require.NoError(t, err)
	token, err = getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	require.NoError(t, err)
	rr = nativeRequest(t, http.MethodGet, userSearchPath+"?q=report", token, nil)
	checkResponseCode(t, http.StatusOK, rr)
	decodeNative(t, rr, &results)
	assert.Empty(t, results)
}

func TestNativeTokenRefresh(t *testing.T) {
	user, _, err := httpdtest.AddUser(getTestUser(), http.StatusCreated)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := httpdtest.RemoveUser(user, http.StatusOK)
		assert.NoError(t, err)
		assert.NoError(t, os.RemoveAll(user.GetHomeDir()))
	})
	token, err := getJWTAPIUserTokenFromTestServer(defaultUsername, defaultPassword)
	require.NoError(t, err)
	rr := nativeRequest(t, http.MethodGet, userTokenRefreshPath, token, nil)
	checkResponseCode(t, http.StatusOK, rr)
	var response map[string]any
	decodeNative(t, rr, &response)
	refreshed, ok := response["access_token"].(string)
	require.True(t, ok)
	checkResponseCode(t, http.StatusOK, nativeRequest(t, http.MethodGet, userDirsPath, refreshed, nil))

	// A changed password ends the session, as it changes the signature of the account.
	user.Password = defaultPassword + "_new"
	_, _, err = httpdtest.UpdateUser(user, http.StatusOK, "")
	require.NoError(t, err)
	checkResponseCode(t, http.StatusUnauthorized, nativeRequest(t, http.MethodGet, userTokenRefreshPath, refreshed, nil))
}
