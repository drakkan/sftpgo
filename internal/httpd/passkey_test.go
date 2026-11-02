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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xrogers/gonas/v2/internal/common"
	"github.com/xrogers/gonas/v2/internal/dataprovider"
	"github.com/xrogers/gonas/v2/internal/jwt"
	"github.com/xrogers/gonas/v2/internal/util"
)

func setPasskeysConfig(t *testing.T, config PasskeysConfig) {
	previous := passkeysConfig
	passkeysConfig = config
	t.Cleanup(func() { passkeysConfig = previous })
}

func newPasskeyTestSigner(t *testing.T) *jwt.Signer {
	signer, err := jwt.NewSigner(jose.HS256, util.GenerateRandomBytes(32))
	require.NoError(t, err)
	return signer
}

func TestPasskeyTokenIsSingleUse(t *testing.T) {
	signer := newPasskeyTestSigner(t)
	session := &webauthn.SessionData{Challenge: "challenge", RelyingPartyID: "files.example.com"}
	token, err := createPasskeyToken(signer, tokenAudiencePasskeyLogin, session, "192.0.2.1")
	require.NoError(t, err)

	decoded, err := consumePasskeyToken(signer, token, tokenAudiencePasskeyLogin, "192.0.2.1")
	require.NoError(t, err)
	assert.Equal(t, session.Challenge, decoded.Challenge)
	assert.Equal(t, session.RelyingPartyID, decoded.RelyingPartyID)

	_, err = consumePasskeyToken(signer, token, tokenAudiencePasskeyLogin, "192.0.2.1")
	assert.ErrorIs(t, err, errPasskeyInvalid)
}

func TestPasskeyTokenIsBoundToItsUse(t *testing.T) {
	signer := newPasskeyTestSigner(t)
	session := &webauthn.SessionData{Challenge: "challenge"}
	token, err := createPasskeyToken(signer, tokenAudiencePasskeyRegister, session, "192.0.2.1")
	require.NoError(t, err)

	_, err = consumePasskeyToken(signer, token, tokenAudiencePasskeyLogin, "192.0.2.1")
	assert.ErrorIs(t, err, errPasskeyInvalid, "a challenge for another step")
	_, err = consumePasskeyToken(signer, token, tokenAudiencePasskeyRegister, "192.0.2.2")
	assert.ErrorIs(t, err, errPasskeyInvalid, "a challenge from another address")
	_, err = consumePasskeyToken(newPasskeyTestSigner(t), token, tokenAudiencePasskeyRegister, "192.0.2.1")
	assert.ErrorIs(t, err, errPasskeyInvalid, "a challenge signed by another key")
	_, err = consumePasskeyToken(signer, "", tokenAudiencePasskeyRegister, "192.0.2.1")
	assert.ErrorIs(t, err, errPasskeyInvalid)
}

func TestPasskeyTokenExpires(t *testing.T) {
	signer := newPasskeyTestSigner(t)
	claims := jwt.NewClaims(tokenAudiencePasskeyLogin, "192.0.2.1", -time.Minute)
	claims.ID = "expired"
	token, err := signer.Sign(claims)
	require.NoError(t, err)
	_, err = consumePasskeyToken(signer, token, tokenAudiencePasskeyLogin, "192.0.2.1")
	assert.ErrorIs(t, err, errPasskeyInvalid)
}

func TestPasskeyAsSecondFactor(t *testing.T) {
	user := dataprovider.User{}
	user.Filters.TwoFactorAuthProtocols = []string{common.ProtocolHTTP}
	admin := dataprovider.Admin{}
	admin.Filters.RequireTwoFactor = true

	setPasskeysConfig(t, PasskeysConfig{Enabled: true})
	assert.True(t, userMustSetSecondFactor(&user))
	assert.True(t, adminMustSetSecondFactor(&admin))

	passkeys := []dataprovider.Passkey{{ID: []byte("id")}}
	user.Filters.Passkeys = passkeys
	admin.Filters.Passkeys = passkeys
	// Off: a passkey replaces the password, not the requirement.
	assert.True(t, userMustSetSecondFactor(&user))
	assert.True(t, adminMustSetSecondFactor(&admin))
	assert.False(t, userMustUseSecondFactor(&user))
	assert.False(t, adminMustUseSecondFactor(&admin))
	assert.False(t, userHasPasskeyTwoFactor(&user))

	setPasskeysConfig(t, PasskeysConfig{Enabled: true, SkipTwoFactor: true})
	assert.False(t, userMustSetSecondFactor(&user))
	assert.False(t, adminMustSetSecondFactor(&admin))
	// The requirement is met, so the password alone must not be enough.
	assert.True(t, userMustUseSecondFactor(&user))
	assert.True(t, adminMustUseSecondFactor(&admin))
	assert.True(t, userHasPasskeyTwoFactor(&user))

	// A passkey cannot be used over SSH, so TOTP is still needed there.
	user.Filters.TwoFactorAuthProtocols = []string{common.ProtocolHTTP, common.ProtocolSSH}
	assert.True(t, userMustSetSecondFactor(&user))

	// Without a requirement a passkey does not take the password away.
	user.Filters.TwoFactorAuthProtocols = nil
	admin.Filters.RequireTwoFactor = false
	assert.False(t, userMustUseSecondFactor(&user))
	assert.False(t, adminMustUseSecondFactor(&admin))

	// Turned off, nothing is left of the option.
	setPasskeysConfig(t, PasskeysConfig{SkipTwoFactor: true})
	assert.False(t, passkeysSatisfyTwoFactor())
}

func TestPasskeyTOTPStaysRequired(t *testing.T) {
	setPasskeysConfig(t, PasskeysConfig{Enabled: true, SkipTwoFactor: true})
	user := dataprovider.User{}
	user.Filters.TOTPConfig.Enabled = true
	user.Filters.TOTPConfig.Protocols = []string{common.ProtocolHTTP}
	assert.True(t, userMustUseSecondFactor(&user), "a password login with TOTP still needs the code")
	user.Filters.TOTPConfig.Protocols = []string{common.ProtocolSSH}
	assert.False(t, userMustUseSecondFactor(&user))
}

func TestPasskeyAccountOnlyUsesItsDomain(t *testing.T) {
	account := &passkeyAccount{
		username: "user",
		rpID:     "files.example.com",
		passkeys: []dataprovider.Passkey{
			{ID: []byte("here"), PublicKey: []byte("key"), RPID: "files.example.com", SignCount: 3, BackupEligible: true},
			{ID: []byte("there"), PublicKey: []byte("key"), RPID: "other.example.com"},
		},
	}
	credentials := account.WebAuthnCredentials()
	require.Len(t, credentials, 1)
	assert.Equal(t, []byte("here"), credentials[0].ID)
	assert.Equal(t, uint32(3), credentials[0].Authenticator.SignCount)
	assert.True(t, credentials[0].Flags.BackupEligible)
	assert.True(t, credentials[0].Flags.UserVerified)
	assert.Len(t, account.exclusions(), 1)
	assert.Equal(t, []byte("user"), account.WebAuthnID())
}

func TestPasskeyProviderFollowsTheRequest(t *testing.T) {
	setPasskeysConfig(t, PasskeysConfig{Enabled: true})
	server := &httpdServer{binding: Binding{}}
	r := httptest.NewRequest(http.MethodGet, "https://files.example.com:8443/web/client/login", nil)
	provider, err := server.newPasskeyProvider(r)
	require.NoError(t, err)
	assert.Equal(t, "files.example.com", provider.Config.RPID)
	assert.Equal(t, []string{"https://files.example.com:8443"}, provider.Config.RPOrigins)

	setPasskeysConfig(t, PasskeysConfig{
		Enabled: true, RPID: "example.com", Origins: []string{"https://a.example.com", "https://b.example.com"},
	})
	provider, err = server.newPasskeyProvider(r)
	require.NoError(t, err)
	assert.Equal(t, "example.com", provider.Config.RPID)
	assert.Len(t, provider.Config.RPOrigins, 2)
}

func TestUpdatePasskeySignCount(t *testing.T) {
	passkeys := []dataprovider.Passkey{{ID: []byte("a"), SignCount: 1}, {ID: []byte("b"), SignCount: 1}}
	used := &webauthn.Credential{ID: []byte("b"), Authenticator: webauthn.Authenticator{SignCount: 2}}
	assert.True(t, updatePasskeySignCount(passkeys, used))
	assert.Equal(t, uint32(1), passkeys[0].SignCount)
	assert.Equal(t, uint32(2), passkeys[1].SignCount)
	assert.False(t, updatePasskeySignCount(passkeys, used), "nothing to store")
}

// softPasskey is a passkey held in memory: it signs what a real authenticator would, so that a
// test can choose the origin that a client reports.
type softPasskey struct {
	key     *ecdsa.PrivateKey
	account *passkeyAccount
}

func newSoftPasskey(t *testing.T, rpID string) *softPasskey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: key.X.FillBytes(make([]byte, 32)),
		YCoord: key.Y.FillBytes(make([]byte, 32)),
	})
	require.NoError(t, err)
	return &softPasskey{key: key, account: &passkeyAccount{
		username: "user",
		rpID:     rpID,
		passkeys: []dataprovider.Passkey{{ID: []byte("credential"), PublicKey: public, RPID: rpID}},
	}}
}

func (p *softPasskey) sign(t *testing.T, rpID, origin, challenge string) *protocol.ParsedCredentialAssertionData {
	encode := base64.RawURLEncoding.EncodeToString
	clientData, err := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": challenge, "origin": origin})
	require.NoError(t, err)
	rpHash := sha256.Sum256([]byte(rpID))
	// user present and verified, then a counter of zero
	authData := append(append([]byte{}, rpHash[:]...), 0x05, 0, 0, 0, 0)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{
		"id": encode([]byte("credential")), "rawId": encode([]byte("credential")), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    encode(clientData),
			"authenticatorData": encode(authData),
			"signature":         encode(signature),
			"userHandle":        encode([]byte("user")),
		},
	})
	require.NoError(t, err)
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	require.NoError(t, err)
	return parsed
}

func TestPasskeyAndroidOrigin(t *testing.T) {
	const fingerprint = "94:F0:25:2E:4A:57:F8:F6:C1:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66"
	digest, err := parseCertFingerprint(fingerprint)
	require.NoError(t, err)
	appOrigin := "android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(digest)
	appOriginSHA256 := "android:apk-key-hash-sha256:" + base64.RawURLEncoding.EncodeToString(digest)
	const webOrigin = "https://files.example.com"
	const rpID = "files.example.com"

	verify := func(origin string) error {
		server := &httpdServer{binding: Binding{}}
		r := httptest.NewRequest(http.MethodGet, webOrigin+"/web/client/login", nil)
		r.TLS = nil
		provider, err := server.newPasskeyProvider(r)
		require.NoError(t, err)
		passkey := newSoftPasskey(t, rpID)
		const challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		session := webauthn.SessionData{
			Challenge:        challenge,
			RelyingPartyID:   rpID,
			UserID:           passkey.account.WebAuthnID(),
			UserVerification: protocol.VerificationRequired,
			Expires:          time.Now().Add(time.Minute),
		}
		_, err = provider.ValidateLogin(passkey.account, session, passkey.sign(t, rpID, origin, challenge))
		return err
	}

	setPasskeysConfig(t, PasskeysConfig{Enabled: true, Origins: []string{webOrigin}})
	assert.NoError(t, verify(webOrigin))
	assert.Error(t, verify(appOrigin), "an app must not be accepted unless it is configured")

	setPasskeysConfig(t, PasskeysConfig{
		Enabled: true, Origins: []string{webOrigin}, AndroidCertFingerprints: []string{fingerprint},
	})
	assert.NoError(t, verify(appOrigin))
	assert.NoError(t, verify(appOriginSHA256))
	assert.NoError(t, verify(webOrigin), "a WebView may report the web origin")
	assert.Error(t, verify("android:apk-key-hash:"+strings.Repeat("A", 43)), "an app signed by another key")
	assert.Error(t, verify("https://evil.example.com"))

	// Any other form a device may report can be allowed without a code change.
	const other = "android:apk-key-hash:c29tZXRoaW5nLWVsc2U"
	setPasskeysConfig(t, PasskeysConfig{Enabled: true, Origins: []string{webOrigin, other}})
	assert.NoError(t, verify(other))
	assert.NoError(t, verify(webOrigin))
}

func TestAssetLinks(t *testing.T) {
	setPasskeysConfig(t, PasskeysConfig{Enabled: true, AndroidPackageName: "com.example.app"})
	request := httptest.NewRequest(http.MethodGet, assetLinksPath, nil)
	recorder := httptest.NewRecorder()
	handleAssetLinks(recorder, request)
	assert.Equal(t, http.StatusNotFound, recorder.Code, "nothing to publish without a certificate")

	setPasskeysConfig(t, PasskeysConfig{
		Enabled:            true,
		AndroidPackageName: "com.example.app",
		AndroidCertFingerprints: []string{
			strings.Repeat("ab", 32),
			"not a fingerprint",
		},
	})
	recorder = httptest.NewRecorder()
	handleAssetLinks(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Header().Get("Content-Type"), "application/json")
	var links []assetLink
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &links))
	require.Len(t, links, 1)
	assert.Contains(t, links[0].Relation, "delegate_permission/common.get_login_creds")
	assert.Equal(t, "android_app", links[0].Target.Namespace)
	assert.Equal(t, "com.example.app", links[0].Target.PackageName)
	require.Len(t, links[0].Target.Fingerprints, 1, "an invalid fingerprint is left out")
	assert.Equal(t, strings.TrimSuffix(strings.Repeat("AB:", 32), ":"), links[0].Target.Fingerprints[0])
}

func TestPasskeyNeedsRecentLogin(t *testing.T) {
	now := time.Now()
	claims := &jwt.Claims{AuthAt: now.Add(-time.Minute).Unix()}
	assert.True(t, loginIsRecent(claims, now))
	claims.AuthAt = now.Add(-passkeyRecentLogin - time.Second).Unix()
	assert.False(t, loginIsRecent(claims, now), "an old sign in")
	claims.AuthAt = 0
	assert.False(t, loginIsRecent(claims, now), "a session from before this check, or with no sign in")
}

func TestRefreshKeepsLoginTime(t *testing.T) {
	signer := newPasskeyTestSigner(t)
	claims := &jwt.Claims{Username: "user", AuthAt: 1234}
	first, err := signer.SignWithParams(claims, tokenAudienceWebClient, "192.0.2.1", time.Hour)
	require.NoError(t, err)
	decoded, err := jwt.VerifyToken(signer, first)
	require.NoError(t, err)
	second, err := signer.SignWithParams(decoded, tokenAudienceWebClient, "192.0.2.1", time.Hour)
	require.NoError(t, err)
	refreshed, err := jwt.VerifyToken(signer, second)
	require.NoError(t, err)
	assert.Equal(t, int64(1234), refreshed.AuthAt, "a refresh is not a new sign in")
}
