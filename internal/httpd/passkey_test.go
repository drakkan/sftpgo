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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
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
