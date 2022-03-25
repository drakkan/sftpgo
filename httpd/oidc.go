package httpd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/xid"
	"golang.org/x/oauth2"

	"github.com/drakkan/sftpgo/v2/common"
	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/httpclient"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

const (
	oidcCookieKey       = "oidc"
	authStateValidity   = 1 * 60 * 1000   // 1 minute
	tokenUpdateInterval = 3 * 60 * 1000   // 3 minutes
	tokenDeleteInterval = 2 * 3600 * 1000 // 2 hours
)

var (
	oidcTokenKey       = &contextKey{"OIDC token key"}
	oidcGeneratedToken = &contextKey{"OIDC generated token"}
	oidcMgr            *oidcManager
)

func init() {
	oidcMgr = &oidcManager{
		pendingAuths: make(map[string]oidcPendingAuth),
		tokens:       make(map[string]oidcToken),
		lastCleanup:  time.Now(),
	}
}

// OAuth2Config defines an interface for OAuth2 methods, so we can mock them
type OAuth2Config interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource
}

// OIDCTokenVerifier defines an interface for OpenID token verifier, so we can mock them
type OIDCTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

// OIDC defines the OpenID Connect configuration
type OIDC struct {
	// ClientID is the application's ID
	ClientID string `json:"client_id" mapstructure:"client_id"`
	// ClientSecret is the application's secret
	ClientSecret string `json:"client_secret" mapstructure:"client_secret"`
	// ConfigURL is the identifier for the service.
	// SFTPGo will try to retrieve the provider configuration on startup and then
	// will refuse to start if it fails to connect to the specified URL
	ConfigURL string `json:"config_url" mapstructure:"config_url"`
	// RedirectBaseURL is the base URL to redirect to after OpenID authentication.
	// The suffix "/web/oidc/redirect" will be added to this base URL, adding also the
	// "web_root" if configured
	RedirectBaseURL string `json:"redirect_base_url" mapstructure:"redirect_base_url"`
	// ID token claims field to map to the SFTPGo username
	UsernameField string `json:"username_field" mapstructure:"username_field"`
	// Optional ID token claims field to map to a SFTPGo role.
	// If the defined ID token claims field is set to "admin" the authenticated user
	// is mapped to an SFTPGo admin.
	// You don't need to specify this field if you want to use OpenID only for the
	// Web Client UI
	RoleField         string `json:"role_field" mapstructure:"role_field"`
	provider          *oidc.Provider
	verifier          OIDCTokenVerifier
	providerLogoutURL string
	oauth2Config      OAuth2Config
}

func (o *OIDC) isEnabled() bool {
	return o.provider != nil
}

func (o *OIDC) hasRoles() bool {
	return o.isEnabled() && o.RoleField != ""
}

func (o *OIDC) getRedirectURL() string {
	url := o.RedirectBaseURL
	if strings.HasSuffix(o.RedirectBaseURL, "/") {
		url = strings.TrimSuffix(o.RedirectBaseURL, "/")
	}
	url += webOIDCRedirectPath
	logger.Debug(logSender, "", "oidc redirect URL: %#v", url)
	return url
}

func (o *OIDC) initialize() error {
	if o.ConfigURL == "" {
		return nil
	}
	if o.UsernameField == "" {
		return errors.New("oidc: username field cannot be empty")
	}
	if o.RedirectBaseURL == "" {
		return errors.New("oidc: redirect base URL cannot be empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, o.ConfigURL)
	if err != nil {
		return fmt.Errorf("oidc: unable to initialize provider for URL %#v: %w", o.ConfigURL, err)
	}
	claims := make(map[string]interface{})
	// we cannot get an error here because the response body was already parsed as JSON
	// on provider creation
	provider.Claims(&claims) //nolint:errcheck
	endSessionEndPoint, ok := claims["end_session_endpoint"]
	if ok {
		if val, ok := endSessionEndPoint.(string); ok {
			o.providerLogoutURL = val
			logger.Debug(logSender, "", "oidc end session endpoint %#v", o.providerLogoutURL)
		}
	}
	o.provider = provider
	o.verifier = provider.Verifier(&oidc.Config{
		ClientID: o.ClientID,
	})
	o.oauth2Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint:     o.provider.Endpoint(),
		RedirectURL:  o.getRedirectURL(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return nil
}

type oidcPendingAuth struct {
	State    string
	Nonce    string
	Audience tokenAudience
	IssueAt  int64
}

func newOIDCPendingAuth(audience tokenAudience) oidcPendingAuth {
	return oidcPendingAuth{
		State:    xid.New().String(),
		Nonce:    xid.New().String(),
		Audience: audience,
		IssueAt:  util.GetTimeAsMsSinceEpoch(time.Now()),
	}
}

type oidcToken struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type,omitempty"`
	RefreshToken string      `json:"refresh_token,omitempty"`
	ExpiresAt    int64       `json:"expires_at,omitempty"`
	SessionID    string      `json:"session_id"`
	IDToken      string      `json:"id_token"`
	Nonce        string      `json:"nonce"`
	Username     string      `json:"username"`
	Permissions  []string    `json:"permissions"`
	Role         interface{} `json:"role"`
	Cookie       string      `json:"cookie"`
	UsedAt       int64       `json:"used_at"`
}

func (t *oidcToken) parseClaims(claims map[string]interface{}, usernameField, roleField string) error {
	getClaimsFields := func() []string {
		keys := make([]string, 0, len(claims))
		for k := range claims {
			keys = append(keys, k)
		}
		return keys
	}

	username, ok := claims[usernameField].(string)
	if !ok || username == "" {
		logger.Warn(logSender, "", "username field %#v not found, claims fields: %+v", usernameField, getClaimsFields())
		return errors.New("no username field")
	}
	t.Username = username
	if roleField != "" {
		role, ok := claims[roleField]
		if ok {
			t.Role = role
		}
	}
	sid, ok := claims["sid"].(string)
	if ok {
		t.SessionID = sid
	}
	return nil
}

func (t *oidcToken) isAdmin() bool {
	switch v := t.Role.(type) {
	case string:
		return v == "admin"
	case []interface{}:
		for _, s := range v {
			if val, ok := s.(string); ok && val == "admin" {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (t *oidcToken) isExpired() bool {
	if t.ExpiresAt == 0 {
		return false
	}
	return t.ExpiresAt < util.GetTimeAsMsSinceEpoch(time.Now())
}

func (t *oidcToken) refresh(config OAuth2Config, verifier OIDCTokenVerifier) error {
	if t.RefreshToken == "" {
		logger.Debug(logSender, "", "refresh token not set, unable to refresh cookie %#v", t.Cookie)
		return errors.New("refresh token not set")
	}
	oauth2Token := oauth2.Token{
		AccessToken:  t.AccessToken,
		TokenType:    t.TokenType,
		RefreshToken: t.RefreshToken,
	}
	if t.ExpiresAt > 0 {
		oauth2Token.Expiry = util.GetTimeFromMsecSinceEpoch(t.ExpiresAt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	newToken, err := config.TokenSource(ctx, &oauth2Token).Token()
	if err != nil {
		logger.Debug(logSender, "", "unable to refresh token for cookie %#v: %v", t.Cookie, err)
		return err
	}
	rawIDToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		logger.Debug(logSender, "", "the refreshed token has no id token, cookie %#v", t.Cookie)
		return errors.New("the refreshed token has no id token")
	}

	t.AccessToken = newToken.AccessToken
	t.TokenType = newToken.TokenType
	t.RefreshToken = newToken.RefreshToken
	t.IDToken = rawIDToken
	if !newToken.Expiry.IsZero() {
		t.ExpiresAt = util.GetTimeAsMsSinceEpoch(newToken.Expiry)
	} else {
		t.ExpiresAt = 0
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		logger.Debug(logSender, "", "unable to verify refreshed id token for cookie %#v: %v", t.Cookie, err)
		return err
	}
	if idToken.Nonce != t.Nonce {
		logger.Debug(logSender, "", "unable to verify refreshed id token for cookie %#v: nonce mismatch", t.Cookie)
		return errors.New("the refreshed token nonce mismatch")
	}
	claims := make(map[string]interface{})
	err = idToken.Claims(&claims)
	if err != nil {
		logger.Debug(logSender, "", "unable to get refreshed id token claims for cookie %#v: %v", t.Cookie, err)
		return err
	}
	sid, ok := claims["sid"].(string)
	if ok {
		t.SessionID = sid
	}
	logger.Debug(logSender, "", "oidc token refreshed for user %#v, cookie %#v", t.Username, t.Cookie)
	oidcMgr.addToken(*t)

	return nil
}

func (t *oidcToken) getUser(r *http.Request) error {
	if t.isAdmin() {
		admin, err := dataprovider.AdminExists(t.Username)
		if err != nil {
			return err
		}
		if err := admin.CanLogin(util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
			return err
		}
		t.Permissions = admin.Permissions
		dataprovider.UpdateAdminLastLogin(&admin)
		return nil
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	user, err := dataprovider.GetUserAfterIDPAuth(t.Username, ipAddr, common.ProtocolOIDC)
	if err != nil {
		return err
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, common.ProtocolOIDC); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodIDP, ipAddr, err)
		return fmt.Errorf("access denied by post connect hook: %w", err)
	}
	if err := user.CheckLoginConditions(); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodIDP, ipAddr, err)
		return err
	}
	connectionID := fmt.Sprintf("%v_%v", common.ProtocolOIDC, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodIDP, ipAddr, err)
		return err
	}
	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&user, dataprovider.LoginMethodIDP, ipAddr, common.ErrInternalFailure)
		return err
	}
	updateLoginMetrics(&user, dataprovider.LoginMethodIDP, ipAddr, nil)
	dataprovider.UpdateLastLogin(&user)
	t.Permissions = user.Filters.WebClient
	return nil
}

type oidcManager struct {
	authMutex    sync.RWMutex
	pendingAuths map[string]oidcPendingAuth
	tokenMutex   sync.RWMutex
	tokens       map[string]oidcToken
	lastCleanup  time.Time
}

func (o *oidcManager) addPendingAuth(pendingAuth oidcPendingAuth) {
	o.authMutex.Lock()
	o.pendingAuths[pendingAuth.State] = pendingAuth
	o.authMutex.Unlock()

	o.checkCleanup()
}

func (o *oidcManager) removePendingAuth(key string) {
	o.authMutex.Lock()
	defer o.authMutex.Unlock()

	delete(o.pendingAuths, key)
}

func (o *oidcManager) getPendingAuth(state string) (oidcPendingAuth, error) {
	o.authMutex.RLock()
	defer o.authMutex.RUnlock()

	authReq, ok := o.pendingAuths[state]
	if !ok {
		return oidcPendingAuth{}, errors.New("oidc: no auth request found for the specified state")
	}
	diff := util.GetTimeAsMsSinceEpoch(time.Now()) - authReq.IssueAt
	if diff > authStateValidity {
		return oidcPendingAuth{}, errors.New("oidc: auth request is too old")
	}
	return authReq, nil
}

func (o *oidcManager) addToken(token oidcToken) {
	o.tokenMutex.Lock()
	token.UsedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	o.tokens[token.Cookie] = token
	o.tokenMutex.Unlock()

	o.checkCleanup()
}

func (o *oidcManager) getToken(cookie string) (oidcToken, error) {
	o.tokenMutex.RLock()
	defer o.tokenMutex.RUnlock()

	token, ok := o.tokens[cookie]
	if !ok {
		return oidcToken{}, errors.New("oidc: no token found for the specified session")
	}
	return token, nil
}

func (o *oidcManager) removeToken(cookie string) {
	o.tokenMutex.Lock()
	defer o.tokenMutex.Unlock()

	delete(o.tokens, cookie)
}

func (o *oidcManager) updateTokenUsage(token oidcToken) {
	diff := util.GetTimeAsMsSinceEpoch(time.Now()) - token.UsedAt
	if diff > tokenUpdateInterval {
		o.addToken(token)
	}
}

func (o *oidcManager) checkCleanup() {
	o.authMutex.RLock()
	needCleanup := o.lastCleanup.Add(20 * time.Minute).Before(time.Now())
	o.authMutex.RUnlock()

	if needCleanup {
		o.authMutex.Lock()
		o.lastCleanup = time.Now()
		o.authMutex.Unlock()

		o.cleanupAuthRequests()
		o.cleanupTokens()
	}
}

func (o *oidcManager) cleanupAuthRequests() {
	o.authMutex.Lock()
	defer o.authMutex.Unlock()

	for k, auth := range o.pendingAuths {
		diff := util.GetTimeAsMsSinceEpoch(time.Now()) - auth.IssueAt
		// remove old pending auth requests
		if diff < 0 || diff > authStateValidity {
			delete(o.pendingAuths, k)
		}
	}
}

func (o *oidcManager) cleanupTokens() {
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

func (s *httpdServer) validateOIDCToken(w http.ResponseWriter, r *http.Request, isAdmin bool) (oidcToken, error) {
	doRedirect := func() {
		removeOIDCCookie(w, r)
		if isAdmin {
			http.Redirect(w, r, webAdminLoginPath, http.StatusFound)
			return
		}
		http.Redirect(w, r, webClientLoginPath, http.StatusFound)
	}

	cookie, err := r.Cookie(oidcCookieKey)
	if err != nil {
		logger.Debug(logSender, "", "no oidc cookie, redirecting to login page")
		doRedirect()
		return oidcToken{}, errInvalidToken
	}
	token, err := oidcMgr.getToken(cookie.Value)
	if err != nil {
		logger.Debug(logSender, "", "error getting oidc token associated with cookie %#v: %v", cookie.Value, err)
		doRedirect()
		return oidcToken{}, errInvalidToken
	}
	if token.isExpired() {
		logger.Debug(logSender, "", "oidc token associated with cookie %#v is expired", token.Cookie)
		if err = token.refresh(s.binding.OIDC.oauth2Config, s.binding.OIDC.verifier); err != nil {
			setFlashMessage(w, r, "Your OpenID token is expired, please log-in again")
			doRedirect()
			return oidcToken{}, errInvalidToken
		}
	} else {
		oidcMgr.updateTokenUsage(token)
	}
	if isAdmin {
		if !token.isAdmin() {
			logger.Debug(logSender, "", "oidc token associated with cookie %#v is not valid for admin users", token.Cookie)
			setFlashMessage(w, r, "Your OpenID token is not valid for the SFTPGo Web Admin UI. Please logout from your OpenID server and log-in as an SFTPGo admin")
			doRedirect()
			return oidcToken{}, errInvalidToken
		}
		return token, nil
	}
	if token.isAdmin() {
		logger.Debug(logSender, "", "oidc token associated with cookie %#v is valid for admin users", token.Cookie)
		setFlashMessage(w, r, "Your OpenID token is not valid for the SFTPGo Web Client UI. Please logout from your OpenID server and log-in as an SFTPGo user")
		doRedirect()
		return oidcToken{}, errInvalidToken
	}
	return token, nil
}

func (s *httpdServer) oidcTokenAuthenticator(audience tokenAudience) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if canSkipOIDCValidation(r) {
				next.ServeHTTP(w, r)
				return
			}
			token, err := s.validateOIDCToken(w, r, audience == tokenAudienceWebAdmin)
			if err != nil {
				return
			}
			jwtTokenClaims := jwtTokenClaims{
				Username:    token.Username,
				Permissions: token.Permissions,
			}
			_, tokenString, err := jwtTokenClaims.createToken(s.tokenAuth, audience, util.GetIPFromRemoteAddress(r.RemoteAddr))
			if err != nil {
				setFlashMessage(w, r, "Unable to create cookie")
				if audience == tokenAudienceWebAdmin {
					http.Redirect(w, r, webAdminLoginPath, http.StatusFound)
				} else {
					http.Redirect(w, r, webClientLoginPath, http.StatusFound)
				}
				return
			}
			ctx := context.WithValue(r.Context(), oidcTokenKey, token.Cookie)
			ctx = context.WithValue(ctx, oidcGeneratedToken, tokenString)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (s *httpdServer) handleWebAdminOIDCLogin(w http.ResponseWriter, r *http.Request) {
	s.oidcLoginRedirect(w, r, tokenAudienceWebAdmin)
}

func (s *httpdServer) handleWebClientOIDCLogin(w http.ResponseWriter, r *http.Request) {
	s.oidcLoginRedirect(w, r, tokenAudienceWebClient)
}

func (s *httpdServer) oidcLoginRedirect(w http.ResponseWriter, r *http.Request, audience tokenAudience) {
	pendingAuth := newOIDCPendingAuth(audience)
	oidcMgr.addPendingAuth(pendingAuth)
	http.Redirect(w, r, s.binding.OIDC.oauth2Config.AuthCodeURL(pendingAuth.State,
		oidc.Nonce(pendingAuth.Nonce)), http.StatusFound)
}

func (s *httpdServer) handleOIDCRedirect(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	authReq, err := oidcMgr.getPendingAuth(state)
	if err != nil {
		logger.Debug(logSender, "", "oidc authentication state did not match")
		s.renderClientMessagePage(w, r, "Invalid authentication request", "Authentication state did not match",
			http.StatusBadRequest, nil, "")
		return
	}
	oidcMgr.removePendingAuth(state)

	doRedirect := func() {
		if authReq.Audience == tokenAudienceWebAdmin {
			http.Redirect(w, r, webAdminLoginPath, http.StatusFound)
			return
		}
		http.Redirect(w, r, webClientLoginPath, http.StatusFound)
	}
	doLogout := func(rawIDToken string) {
		s.logoutFromOIDCOP(rawIDToken)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	oauth2Token, err := s.binding.OIDC.oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		logger.Debug(logSender, "", "failed to exchange oidc token: %v", err)
		setFlashMessage(w, r, "Failed to exchange OpenID token")
		doRedirect()
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		logger.Debug(logSender, "", "no id_token field in OAuth2 OpenID token")
		setFlashMessage(w, r, "No id_token field in OAuth2 OpenID token")
		doRedirect()
		return
	}
	idToken, err := s.binding.OIDC.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		logger.Debug(logSender, "", "failed to verify oidc token: %v", err)
		setFlashMessage(w, r, "Failed to verify OpenID token")
		doRedirect()
		doLogout(rawIDToken)
		return
	}
	if idToken.Nonce != authReq.Nonce {
		logger.Debug(logSender, "", "oidc authentication nonce did not match")
		setFlashMessage(w, r, "OpenID authentication nonce did not match")
		doRedirect()
		doLogout(rawIDToken)
		return
	}

	claims := make(map[string]interface{})
	err = idToken.Claims(&claims)
	if err != nil {
		logger.Debug(logSender, "", "unable to get oidc token claims: %v", err)
		setFlashMessage(w, r, "Unable to get OpenID token claims")
		doRedirect()
		doLogout(rawIDToken)
		return
	}
	token := oidcToken{
		AccessToken:  oauth2Token.AccessToken,
		TokenType:    oauth2Token.TokenType,
		RefreshToken: oauth2Token.RefreshToken,
		IDToken:      rawIDToken,
		Nonce:        idToken.Nonce,
		Cookie:       xid.New().String(),
	}
	if !oauth2Token.Expiry.IsZero() {
		token.ExpiresAt = util.GetTimeAsMsSinceEpoch(oauth2Token.Expiry)
	}
	if err = token.parseClaims(claims, s.binding.OIDC.UsernameField, s.binding.OIDC.RoleField); err != nil {
		logger.Debug(logSender, "", "unable to parse oidc token claims: %v", err)
		setFlashMessage(w, r, fmt.Sprintf("Unable to parse OpenID token claims: %v", err))
		doRedirect()
		doLogout(rawIDToken)
		return
	}
	switch authReq.Audience {
	case tokenAudienceWebAdmin:
		if !token.isAdmin() {
			logger.Debug(logSender, "", "wrong oidc token role, the mapped user is not an SFTPGo admin")
			setFlashMessage(w, r, "Wrong OpenID role, the logged in user is not an SFTPGo admin")
			doRedirect()
			doLogout(rawIDToken)
			return
		}
	case tokenAudienceWebClient:
		if token.isAdmin() {
			logger.Debug(logSender, "", "wrong oidc token role, the mapped user is an SFTPGo admin")
			setFlashMessage(w, r, "Wrong OpenID role, the logged in user is an SFTPGo admin")
			doRedirect()
			doLogout(rawIDToken)
			return
		}
	}
	err = token.getUser(r)
	if err != nil {
		logger.Debug(logSender, "", "unable to get the sftpgo user associated with oidc token: %v", err)
		setFlashMessage(w, r, "Unable to get the user associated with the OpenID token")
		doRedirect()
		doLogout(rawIDToken)
		return
	}

	loginOIDCUser(w, r, token)
}

func loginOIDCUser(w http.ResponseWriter, r *http.Request, token oidcToken) {
	oidcMgr.addToken(token)

	cookie := http.Cookie{
		Name:     oidcCookieKey,
		Value:    token.Cookie,
		Path:     "/",
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
	}
	// we don't set a cookie expiration so we can refresh the token without setting a new cookie
	// the cookie will be invalidated on browser close
	http.SetCookie(w, &cookie)
	if token.isAdmin() {
		http.Redirect(w, r, webUsersPath, http.StatusFound)
		return
	}
	http.Redirect(w, r, webClientFilesPath, http.StatusFound)
}

func (s *httpdServer) logoutOIDCUser(w http.ResponseWriter, r *http.Request) {
	if oidcKey, ok := r.Context().Value(oidcTokenKey).(string); ok {
		removeOIDCCookie(w, r)
		token, err := oidcMgr.getToken(oidcKey)
		if err == nil {
			s.logoutFromOIDCOP(token.IDToken)
		}
		oidcMgr.removeToken(oidcKey)
	}
}

func (s *httpdServer) logoutFromOIDCOP(idToken string) {
	if s.binding.OIDC.providerLogoutURL == "" {
		logger.Debug(logSender, "", "oidc: provider logout URL not set, unable to logout from the OP")
		return
	}
	go s.doOIDCFromLogout(idToken)
}

func (s *httpdServer) doOIDCFromLogout(idToken string) {
	logoutURL, err := url.Parse(s.binding.OIDC.providerLogoutURL)
	if err != nil {
		logger.Warn(logSender, "", "oidc: unable to parse logout URL: %v", err)
		return
	}
	query := logoutURL.Query()
	if idToken != "" {
		query.Set("id_token_hint", idToken)
	}
	logoutURL.RawQuery = query.Encode()
	resp, err := httpclient.RetryableGet(logoutURL.String())
	if err != nil {
		logger.Warn(logSender, "", "oidc: error calling logout URL %#v: %v", logoutURL.String(), err)
		return
	}
	defer resp.Body.Close()
	logger.Debug(logSender, "", "oidc: logout url response code %v", resp.StatusCode)
}

func removeOIDCCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcCookieKey,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// canSkipOIDCValidation returns true if there is no OIDC cookie but a jwt cookie is set
// and so we check if the user is logged in using a built-in user
func canSkipOIDCValidation(r *http.Request) bool {
	_, err := r.Cookie(oidcCookieKey)
	if err != nil {
		_, err = r.Cookie(jwtCookieKey)
		return err == nil
	}
	return false
}

func isLoggedInWithOIDC(r *http.Request) bool {
	_, ok := r.Context().Value(oidcTokenKey).(string)
	return ok
}
