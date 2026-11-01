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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/xid"

	"github.com/xrogers/gonas/v2/internal/common"
	"github.com/xrogers/gonas/v2/internal/dataprovider"
	"github.com/xrogers/gonas/v2/internal/jwt"
	"github.com/xrogers/gonas/v2/internal/kms"
	"github.com/xrogers/gonas/v2/internal/logger"
	"github.com/xrogers/gonas/v2/internal/util"
)

const (
	passkeyChallengeLifetime = 5 * time.Minute
	// The user handle is the username, and WebAuthn limits it to 64 bytes.
	passkeyMaxUserHandle = 64
	passkeyTokenField    = "passkey_token"
	passkeyCredential    = "credential"

	tokenAudiencePasskeyLogin     tokenAudience = "PasskeyLogin"
	tokenAudiencePasskeyTwoFactor tokenAudience = "PasskeyTwoFactor"
	tokenAudiencePasskeyRegister  tokenAudience = "PasskeyRegister"

	i18nErrorPasskeyFailed   = "passkey.err_failed"
	i18nErrorPasskeySave     = "passkey.err_save"
	i18nErrorPasskeyLimit    = "passkey.err_limit"
	i18nErrorPasskeyName     = "passkey.err_name"
	i18nErrorPasskeyUsername = "passkey.err_username"
	i18nErrorPasskeyRequired = "passkey.err_required"
)

var (
	passkeysConfig     PasskeysConfig
	errPasskeyInvalid  = errors.New("invalid passkey")
	errPasskeyDisabled = errors.New("passkeys are not usable for this account")
)

// PasskeysConfig defines the configuration for signing in to the web interfaces with passkeys
type PasskeysConfig struct {
	// Enabled allows users and admins to register and use passkeys
	Enabled bool `json:"enabled" mapstructure:"enabled"`
	// RPID is the domain passkeys are bound to. Empty means the host name of each request,
	// and passkeys then work only from the host name they were registered on.
	RPID string `json:"rp_id" mapstructure:"rp_id"`
	// Origins allowed to use passkeys, for example "https://files.example.com". Empty means
	// the origin of each request. It is needed if a passkey must work on several origins.
	Origins []string `json:"origins" mapstructure:"origins"`
	// SkipTwoFactor makes a passkey satisfy two-factor authentication. Signing in with one
	// then needs no authentication code, and it can be used in place of the code after a
	// password. If false, a passkey only replaces the password.
	SkipTwoFactor bool `json:"skip_two_factor" mapstructure:"skip_two_factor"`
}

// passkeysSatisfyTwoFactor returns true if a passkey counts as a second factor
func passkeysSatisfyTwoFactor() bool {
	return passkeysConfig.Enabled && passkeysConfig.SkipTwoFactor
}

// userMustUseSecondFactor returns true if a password alone is not enough to sign in to the
// WebClient. An account that has a passkey, but that is not required to use a second factor
// and has no TOTP, keeps being able to sign in with its password.
func userMustUseSecondFactor(user *dataprovider.User) bool {
	if user.Filters.TOTPConfig.Enabled && slices.Contains(user.Filters.TOTPConfig.Protocols, common.ProtocolHTTP) {
		return true
	}
	return passkeysSatisfyTwoFactor() && user.HasPasskeys() &&
		slices.Contains(user.Filters.TwoFactorAuthProtocols, common.ProtocolHTTP)
}

// userMustSetSecondFactor is User.MustSetSecondFactor for the web interface, where a passkey
// can stand in for TOTP. The other protocols cannot use a passkey and still require TOTP.
func userMustSetSecondFactor(user *dataprovider.User) bool {
	if !user.MustSetSecondFactor() {
		return false
	}
	if !passkeysSatisfyTwoFactor() || !user.HasPasskeys() {
		return true
	}
	for _, protocol := range user.Filters.TwoFactorAuthProtocols {
		if protocol != common.ProtocolHTTP && user.MustSetSecondFactorForProtocol(protocol) {
			return true
		}
	}
	return false
}

func adminMustUseSecondFactor(admin *dataprovider.Admin) bool {
	return admin.Filters.TOTPConfig.Enabled ||
		(passkeysSatisfyTwoFactor() && admin.HasPasskeys() && admin.Filters.RequireTwoFactor)
}

func adminMustSetSecondFactor(admin *dataprovider.Admin) bool {
	if !admin.Filters.RequireTwoFactor || admin.Filters.TOTPConfig.Enabled {
		return false
	}
	return !passkeysSatisfyTwoFactor() || !admin.HasPasskeys()
}

// userHasPasskeyTwoFactor returns true if a passkey or a recovery code can complete the sign in
func userHasPasskeyTwoFactor(user *dataprovider.User) bool {
	return passkeysSatisfyTwoFactor() && user.HasPasskeys()
}

func adminHasPasskeyTwoFactor(admin *dataprovider.Admin) bool {
	return passkeysSatisfyTwoFactor() && admin.HasPasskeys()
}

// passkeyAccount adapts a user or an admin to what the WebAuthn library expects.
type passkeyAccount struct {
	username string
	rpID     string
	passkeys []dataprovider.Passkey
}

func (a *passkeyAccount) WebAuthnID() []byte {
	return []byte(a.username)
}

func (a *passkeyAccount) WebAuthnName() string {
	return a.username
}

func (a *passkeyAccount) WebAuthnDisplayName() string {
	return a.username
}

func (a *passkeyAccount) WebAuthnCredentials() []webauthn.Credential {
	credentials := make([]webauthn.Credential, 0, len(a.passkeys))
	for _, p := range a.passkeys {
		if p.RPID != a.rpID {
			continue
		}
		transports := make([]protocol.AuthenticatorTransport, 0, len(p.Transports))
		for _, t := range p.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		credentials = append(credentials, webauthn.Credential{
			ID:              p.ID,
			PublicKey:       p.PublicKey,
			AttestationType: p.AttestationType,
			Transport:       transports,
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: p.BackupEligible,
				BackupState:    p.BackupState,
			},
			Authenticator: webauthn.Authenticator{AAGUID: p.AAGUID, SignCount: p.SignCount},
		})
	}
	return credentials
}

func (a *passkeyAccount) exclusions() []protocol.CredentialDescriptor {
	credentials := a.WebAuthnCredentials()
	result := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, c := range credentials {
		result = append(result, c.Descriptor())
	}
	return result
}

// newPasskeyProvider builds the verifier for this request. What the browser signs names the real
// origin, and a passkey is only offered on the domain it belongs to, so deriving these from the
// Host header cannot make a passkey work somewhere else.
func (s *httpdServer) newPasskeyProvider(r *http.Request) (*webauthn.WebAuthn, error) {
	rpID := passkeysConfig.RPID
	if rpID == "" {
		rpID = r.Host
		if host, _, err := net.SplitHostPort(r.Host); err == nil {
			rpID = host
		}
	}
	origins := passkeysConfig.Origins
	if len(origins) == 0 {
		scheme := "http"
		if isTLS(r) {
			scheme = "https"
		}
		origins = []string{fmt.Sprintf("%s://%s", scheme, r.Host)}
	}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: s.binding.webClientBranding().ShortName,
		RPOrigins:     origins,
	})
}

func createPasskeyToken(csrfTokenAuth *jwt.Signer, audience string, session *webauthn.SessionData, ip string) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	claims := jwt.NewClaims(audience, ip, passkeyChallengeLifetime)
	claims.ID = xid.New().String()
	claims.Subject = base64.RawURLEncoding.EncodeToString(data)
	return csrfTokenAuth.Sign(claims)
}

// consumePasskeyToken returns the challenge held in a token and invalidates the token: a
// challenge is signed so that no state is kept for visitors who are not signed in, and a replay
// would otherwise be possible until it expires.
func consumePasskeyToken(csrfTokenAuth *jwt.Signer, tokenString, audience, ip string) (webauthn.SessionData, error) {
	var session webauthn.SessionData
	token, err := jwt.VerifyToken(csrfTokenAuth, tokenString)
	if err != nil || token == nil || token.ID == "" || token.Expiry == nil {
		return session, errPasskeyInvalid
	}
	if !token.Audience.Contains(audience) {
		return session, errPasskeyInvalid
	}
	if err := validateIPForToken(token, ip); err != nil {
		return session, errPasskeyInvalid
	}
	if invalidatedJWTTokens.Get(token.ID) {
		return session, errPasskeyInvalid
	}
	if err := invalidatedJWTTokens.Add(token.ID, token.Expiry.Time()); err != nil {
		return session, err
	}
	data, err := base64.RawURLEncoding.DecodeString(token.Subject)
	if err != nil {
		return session, errPasskeyInvalid
	}
	if err := json.Unmarshal(data, &session); err != nil {
		return session, errPasskeyInvalid
	}
	return session, nil
}

type passkeyOptions struct {
	Token   string `json:"token"`
	Options any    `json:"options"`
}

func (s *httpdServer) sendPasskeyOptions(
	w http.ResponseWriter, r *http.Request, audience string, options any, session *webauthn.SessionData,
) {
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	token, err := createPasskeyToken(s.csrfTokenAuth, audience, session, ipAddr)
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	render.JSON(w, r, passkeyOptions{Token: token, Options: options})
}

func (s *httpdServer) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	provider, err := s.newPasskeyProvider(r)
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	assertion, session, err := provider.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusInternalServerError)
		return
	}
	s.sendPasskeyOptions(w, r, tokenAudiencePasskeyLogin, assertion.Response, session)
}

// validateDiscoverableLogin checks a passkey sign in from the login page. The account comes from
// the passkey itself: lookup returns the credentials of the account named by the user handle.
func (s *httpdServer) validateDiscoverableLogin(
	r *http.Request, ipAddr string, lookup func(username string) (*passkeyAccount, error),
) (*webauthn.Credential, error) {
	session, err := consumePasskeyToken(s.csrfTokenAuth, r.Form.Get(passkeyTokenField), tokenAudiencePasskeyLogin, ipAddr)
	if err != nil {
		return nil, err
	}
	provider, err := s.newPasskeyProvider(r)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(r.Form.Get(passkeyCredential)))
	if err != nil {
		return nil, errPasskeyInvalid
	}
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		account, err := lookup(string(userHandle))
		if err != nil {
			return nil, err
		}
		account.rpID = provider.Config.RPID
		return account, nil
	}
	_, credential, err := provider.ValidatePasskeyLogin(handler, session, parsed)
	if err != nil {
		return nil, err
	}
	if credential.Authenticator.CloneWarning {
		return nil, errPasskeyInvalid
	}
	return credential, nil
}

// validateAccountPasskey checks a passkey used as the second factor of a known account.
func (s *httpdServer) validateAccountPasskey(
	r *http.Request, ipAddr string, account *passkeyAccount,
) (*webauthn.Credential, error) {
	session, err := consumePasskeyToken(s.csrfTokenAuth, r.Form.Get(passkeyTokenField), tokenAudiencePasskeyTwoFactor, ipAddr)
	if err != nil {
		return nil, err
	}
	provider, err := s.newPasskeyProvider(r)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(r.Form.Get(passkeyCredential)))
	if err != nil {
		return nil, errPasskeyInvalid
	}
	account.rpID = provider.Config.RPID
	credential, err := provider.ValidateLogin(account, session, parsed)
	if err != nil {
		return nil, err
	}
	if credential.Authenticator.CloneWarning {
		return nil, errPasskeyInvalid
	}
	return credential, nil
}

// updatePasskeySignCount records a counter that moved, and reports if there was a change. Only
// security keys use the counter, as synced passkeys always report zero.
func updatePasskeySignCount(passkeys []dataprovider.Passkey, credential *webauthn.Credential) bool {
	for idx := range passkeys {
		if bytes.Equal(passkeys[idx].ID, credential.ID) && passkeys[idx].SignCount != credential.Authenticator.SignCount {
			passkeys[idx].SignCount = credential.Authenticator.SignCount
			return true
		}
	}
	return false
}

func (s *httpdServer) handleWebClientPasskeyLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	failed := &dataprovider.User{}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		updateLoginMetrics(failed, dataprovider.LoginMethodPasskey, ipAddr, err, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, common.ProtocolHTTP); err != nil {
		updateLoginMetrics(failed, dataprovider.LoginMethodPasskey, ipAddr, err, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nError403Message))
		return
	}
	var user, userMerged dataprovider.User
	credential, err := s.validateDiscoverableLogin(r, ipAddr, func(username string) (*passkeyAccount, error) {
		var err error
		user, userMerged, err = dataprovider.GetUserVariants(username, "")
		if err != nil {
			return nil, err
		}
		failed.Username = user.Username
		if !userMerged.CanManageMFA() {
			return nil, errPasskeyDisabled
		}
		return &passkeyAccount{username: user.Username, passkeys: user.Filters.Passkeys}, nil
	})
	if err != nil {
		logger.Debug(logSender, "", "passkey login failed: %v", err)
		updateLoginMetrics(failed, dataprovider.LoginMethodPasskey, ipAddr, dataprovider.ErrInvalidCredentials, r)
		s.renderClientLoginPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolHTTP, xid.New().String())
	if err := checkHTTPClientUser(&userMerged, r, connectionID, true, false); err != nil {
		updateLoginMetrics(&userMerged, dataprovider.LoginMethodPasskey, ipAddr, err, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nError403Message))
		return
	}
	defer userMerged.CloseFs()
	if err := userMerged.CheckFsRoot(connectionID); err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&userMerged, dataprovider.LoginMethodPasskey, ipAddr, common.ErrInternalFailure, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nErrorFsGeneric))
		return
	}
	if updatePasskeySignCount(user.Filters.Passkeys, credential) {
		if err := dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr, user.Role); err != nil {
			logger.Warn(logSender, connectionID, "unable to update the passkey counter: %v", err)
		}
	}
	s.loginUser(w, r, &userMerged, connectionID, ipAddr, dataprovider.LoginMethodPasskey,
		passkeysSatisfyTwoFactor(), s.renderClientLoginPage)
}

func (s *httpdServer) handleWebAdminPasskeyLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderAdminLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderAdminLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	var admin dataprovider.Admin
	credential, err := s.validateDiscoverableLogin(r, ipAddr, func(username string) (*passkeyAccount, error) {
		var err error
		admin, err = dataprovider.AdminExists(username)
		if err != nil {
			return nil, err
		}
		if !admin.CanManageMFA() {
			return nil, errPasskeyDisabled
		}
		return &passkeyAccount{username: admin.Username, passkeys: admin.Filters.Passkeys}, nil
	})
	if err == nil {
		err = admin.CanLogin(ipAddr)
	}
	if err != nil {
		logger.Debug(logSender, "", "admin passkey login failed: %v", err)
		_ = handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials)
		s.renderAdminLoginPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if updatePasskeySignCount(admin.Filters.Passkeys, credential) {
		if err := dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, ipAddr, admin.Role); err != nil {
			logger.Warn(logSender, "", "unable to update the passkey counter: %v", err)
		}
	}
	s.loginAdmin(w, r, &admin, passkeysSatisfyTwoFactor(), s.renderAdminLoginPage, ipAddr)
}

func (s *httpdServer) sendTwoFactorOptions(w http.ResponseWriter, r *http.Request, account *passkeyAccount) {
	provider, err := s.newPasskeyProvider(r)
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	account.rpID = provider.Config.RPID
	assertion, session, err := provider.BeginLogin(account, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	s.sendPasskeyOptions(w, r, tokenAudiencePasskeyTwoFactor, assertion.Response, session)
}

func (s *httpdServer) handleWebClientPasskeyTwoFactorOptions(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	user, err := dataprovider.UserExists(claims.Username, "")
	if err != nil || !userHasPasskeyTwoFactor(&user) {
		sendAPIResponse(w, r, errPasskeyDisabled, i18nErrorPasskeyFailed, http.StatusForbidden)
		return
	}
	s.sendTwoFactorOptions(w, r, &passkeyAccount{username: user.Username, passkeys: user.Filters.Passkeys})
}

func (s *httpdServer) handleWebAdminPasskeyTwoFactorOptions(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil || !adminHasPasskeyTwoFactor(&admin) {
		sendAPIResponse(w, r, errPasskeyDisabled, i18nErrorPasskeyFailed, http.StatusForbidden)
		return
	}
	s.sendTwoFactorOptions(w, r, &passkeyAccount{username: admin.Username, passkeys: admin.Filters.Passkeys})
}

func (s *httpdServer) handleWebClientPasskeyTwoFactorPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	user, userMerged, err := dataprovider.GetUserVariants(claims.Username, "")
	if err != nil || !userHasPasskeyTwoFactor(&user) {
		s.renderClientTwoFactorPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	account := &passkeyAccount{username: user.Username, passkeys: user.Filters.Passkeys}
	credential, err := s.validateAccountPasskey(r, ipAddr, account)
	if err != nil {
		logger.Debug(logSender, "", "passkey second factor failed: %v", err)
		updateLoginMetrics(&user, dataprovider.LoginMethodPasskey, ipAddr, dataprovider.ErrInvalidCredentials, r)
		s.renderClientTwoFactorPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if updatePasskeySignCount(user.Filters.Passkeys, credential) {
		if err := dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr, user.Role); err != nil {
			logger.Warn(logSender, "", "unable to update the passkey counter: %v", err)
		}
	}
	connectionID := fmt.Sprintf("%v_%v", getProtocolFromRequest(r), xid.New().String())
	s.loginUser(w, r, &userMerged, connectionID, ipAddr, dataprovider.LoginMethodPasskey, true,
		s.renderClientTwoFactorPage)
}

func (s *httpdServer) handleWebAdminPasskeyTwoFactorPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil || !adminHasPasskeyTwoFactor(&admin) {
		s.renderTwoFactorPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	account := &passkeyAccount{username: admin.Username, passkeys: admin.Filters.Passkeys}
	credential, err := s.validateAccountPasskey(r, ipAddr, account)
	if err != nil {
		logger.Debug(logSender, "", "admin passkey second factor failed: %v", err)
		_ = handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials)
		s.renderTwoFactorPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if updatePasskeySignCount(admin.Filters.Passkeys, credential) {
		if err := dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, ipAddr, admin.Role); err != nil {
			logger.Warn(logSender, "", "unable to update the passkey counter: %v", err)
		}
	}
	s.loginAdmin(w, r, &admin, true, s.renderTwoFactorPage, ipAddr)
}

// loadPasskeyOwner reads the account of a signed in user or admin, and returns the function that
// stores the changes to its passkeys, with the recovery codes they may need.
func loadPasskeyOwner(claims *jwt.Claims, ipAddr string) (*passkeyAccount, func(p []dataprovider.Passkey) error, error) {
	if hasUserAudience(claims) {
		user, err := dataprovider.UserExists(claims.Username, "")
		if err != nil {
			return nil, nil, err
		}
		save := func(passkeys []dataprovider.Passkey) error {
			user.Filters.Passkeys = passkeys
			if passkeysSatisfyTwoFactor() && len(passkeys) > 0 && user.CountUnusedRecoveryCodes() < 5 {
				user.Filters.RecoveryCodes = newRecoveryCodes()
			}
			return dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr, user.Role)
		}
		return &passkeyAccount{username: user.Username, passkeys: user.Filters.Passkeys}, save, nil
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil {
		return nil, nil, err
	}
	save := func(passkeys []dataprovider.Passkey) error {
		admin.Filters.Passkeys = passkeys
		if passkeysSatisfyTwoFactor() && len(passkeys) > 0 && admin.CountUnusedRecoveryCodes() < 5 {
			admin.Filters.RecoveryCodes = newRecoveryCodes()
		}
		return dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, ipAddr, admin.Role)
	}
	return &passkeyAccount{username: admin.Username, passkeys: admin.Filters.Passkeys}, save, nil
}

func newRecoveryCodes() []dataprovider.RecoveryCode {
	codes := make([]dataprovider.RecoveryCode, 0, 12)
	for range 12 {
		codes = append(codes, dataprovider.RecoveryCode{Secret: kms.NewPlainSecret(getNewRecoveryCode())})
	}
	return codes
}

// requiredSecondFactorLost returns true if removing the last passkey would leave an account
// without the second factor it must have.
func requiredSecondFactorLost(claims *jwt.Claims) bool {
	if !passkeysSatisfyTwoFactor() {
		return false
	}
	if hasUserAudience(claims) {
		user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
		return err != nil || (slices.Contains(user.Filters.TwoFactorAuthProtocols, common.ProtocolHTTP) &&
			user.MustSetSecondFactorForProtocol(common.ProtocolHTTP))
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	return err != nil || (admin.Filters.RequireTwoFactor && !admin.Filters.TOTPConfig.Enabled)
}

func (s *httpdServer) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	account, _, err := loadPasskeyOwner(claims, ipAddr)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	if len(account.username) > passkeyMaxUserHandle {
		sendAPIResponse(w, r, nil, i18nErrorPasskeyUsername, http.StatusBadRequest)
		return
	}
	if len(account.passkeys) >= dataprovider.MaxPasskeys {
		sendAPIResponse(w, r, nil, i18nErrorPasskeyLimit, http.StatusBadRequest)
		return
	}
	provider, err := s.newPasskeyProvider(r)
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	account.rpID = provider.Config.RPID
	residentKey := true
	creation, session, err := provider.BeginRegistration(account,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: &residentKey,
			UserVerification:   protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(account.exclusions()),
	)
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusInternalServerError)
		return
	}
	s.sendPasskeyOptions(w, r, tokenAudiencePasskeyRegister, creation.Response, session)
}

type passkeyRegistration struct {
	Token      string          `json:"token"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func (s *httpdServer) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	var request passkeyRegistration
	if err := render.DecodeJSON(r.Body, &request); err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	session, err := consumePasskeyToken(s.csrfTokenAuth, request.Token, tokenAudiencePasskeyRegister, ipAddr)
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	account, save, err := loadPasskeyOwner(claims, ipAddr)
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	name := strings.TrimSpace(request.Name)
	if name == "" || len(name) > dataprovider.MaxPasskeyNameLength ||
		slices.ContainsFunc(account.passkeys, func(p dataprovider.Passkey) bool { return p.Name == name }) {
		sendAPIResponse(w, r, nil, i18nErrorPasskeyName, http.StatusBadRequest)
		return
	}
	if len(account.passkeys) >= dataprovider.MaxPasskeys {
		sendAPIResponse(w, r, nil, i18nErrorPasskeyLimit, http.StatusBadRequest)
		return
	}
	provider, err := s.newPasskeyProvider(r)
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	account.rpID = provider.Config.RPID
	parsed, err := protocol.ParseCredentialCreationResponseBytes(request.Credential)
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	credential, err := provider.CreateCredential(account, session, parsed)
	if err != nil {
		logger.Debug(logSender, "", "unable to register a passkey for %q: %v", claims.Username, err)
		sendAPIResponse(w, r, err, i18nErrorPasskeyFailed, http.StatusBadRequest)
		return
	}
	transports := make([]string, 0, len(credential.Transport))
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}
	passkeys := append(account.passkeys, dataprovider.Passkey{
		ID:              credential.ID,
		Name:            name,
		PublicKey:       credential.PublicKey,
		RPID:            provider.Config.RPID,
		AttestationType: credential.AttestationType,
		Transports:      transports,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		CreatedAt:       util.GetTimeAsMsSinceEpoch(time.Now()),
	})
	if err := save(passkeys); err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeySave, getRespStatus(err))
		return
	}
	if claims.MustSetTwoFactorAuth && passkeysSatisfyTwoFactor() {
		// The session still carries the requirement, so it must end, as after saving TOTP.
		baseURL := webBasePath
		if hasUserAudience(claims) {
			baseURL = webBaseClientPath
		}
		defer removeCookie(w, r, baseURL)
	}
	sendAPIResponse(w, r, nil, "Passkey added", http.StatusOK)
}

func (s *httpdServer) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, i18nErrorPasskeySave, http.StatusBadRequest)
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(getURLParam(r, "id"))
	if err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeySave, http.StatusBadRequest)
		return
	}
	account, save, err := loadPasskeyOwner(claims, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	passkeys := slices.DeleteFunc(slices.Clone(account.passkeys), func(p dataprovider.Passkey) bool {
		return bytes.Equal(p.ID, id)
	})
	if len(passkeys) == len(account.passkeys) {
		sendAPIResponse(w, r, nil, i18nErrorPasskeySave, http.StatusNotFound)
		return
	}
	if len(passkeys) == 0 && requiredSecondFactorLost(claims) {
		sendAPIResponse(w, r, nil, i18nErrorPasskeyRequired, http.StatusBadRequest)
		return
	}
	if err := save(passkeys); err != nil {
		sendAPIResponse(w, r, err, i18nErrorPasskeySave, getRespStatus(err))
		return
	}
	sendAPIResponse(w, r, nil, "Passkey removed", http.StatusOK)
}

// passkeyEntry is what the 2FA page shows for a passkey.
type passkeyEntry struct {
	ID        string
	Name      string
	CreatedAt int64
}

// passkeyPageData holds the fields of the 2FA page for passkeys.
type passkeyPageData struct {
	PasskeysEnabled bool
	PasskeysURL     string
	Passkeys        []passkeyEntry
	PasskeyIs2FA    bool
	ShowRecovery    bool
}

func newPasskeyPageData(url string, passkeys []dataprovider.Passkey) passkeyPageData {
	data := passkeyPageData{
		PasskeysEnabled: passkeysConfig.Enabled,
		PasskeysURL:     url,
		PasskeyIs2FA:    passkeysConfig.SkipTwoFactor,
		ShowRecovery:    passkeysSatisfyTwoFactor() && len(passkeys) > 0,
	}
	for _, p := range passkeys {
		data.Passkeys = append(data.Passkeys, passkeyEntry{
			ID:        base64.RawURLEncoding.EncodeToString(p.ID),
			Name:      p.Name,
			CreatedAt: p.CreatedAt,
		})
	}
	return data
}

func (s *httpdServer) registerPasskeyLoginRoutes(login, twoFactor string, partial string, isAdmin bool) {
	options := s.handlePasskeyLoginOptions
	twoFactorOptions, twoFactorPost := s.handleWebClientPasskeyTwoFactorOptions, s.handleWebClientPasskeyTwoFactorPost
	loginPost := s.handleWebClientPasskeyLoginPost
	if isAdmin {
		twoFactorOptions, twoFactorPost = s.handleWebAdminPasskeyTwoFactorOptions, s.handleWebAdminPasskeyTwoFactorPost
		loginPost = s.handleWebAdminPasskeyLoginPost
	}
	s.router.Get(login, options)
	s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).Post(login, loginPost)
	s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
		s.jwtAuthenticatorPartial(partial)).Get(twoFactor, twoFactorOptions)
	s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
		s.jwtAuthenticatorPartial(partial)).Post(twoFactor, twoFactorPost)
}
