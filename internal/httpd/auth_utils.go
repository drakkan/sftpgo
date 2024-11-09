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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

type tokenAudience = string

const (
	tokenAudienceWebAdmin         tokenAudience = "WebAdmin"
	tokenAudienceWebClient        tokenAudience = "WebClient"
	tokenAudienceWebShare         tokenAudience = "WebShare"
	tokenAudienceWebAdminPartial  tokenAudience = "WebAdminPartial"
	tokenAudienceWebClientPartial tokenAudience = "WebClientPartial"
	tokenAudienceAPI              tokenAudience = "API"
	tokenAudienceAPIUser          tokenAudience = "APIUser"
	tokenAudienceCSRF             tokenAudience = "CSRF"
	tokenAudienceOAuth2           tokenAudience = "OAuth2"
	tokenAudienceWebLogin         tokenAudience = "WebLogin"
)

const (
	tokenValidationModeDefault       = 0
	tokenValidationModeNoIPMatch     = 1
	tokenValidationModeUserSignature = 2
)

const (
	claimUsernameKey                = "username"
	claimPermissionsKey             = "permissions"
	claimRole                       = "role"
	claimAPIKey                     = "api_key"
	claimNodeID                     = "node_id"
	claimMustChangePasswordKey      = "chpwd"
	claimMustSetSecondFactorKey     = "2fa_required"
	claimRequiredTwoFactorProtocols = "2fa_protos"
	claimHideUserPageSection        = "hus"
	claimRef                        = "ref"
	basicRealm                      = "Basic realm=\"SFTPGo\""
	jwtCookieKey                    = "jwt"
)

var (
	tokenDuration      = 20 * time.Minute
	shareTokenDuration = 2 * time.Hour
	// csrf token duration is greater than normal token duration to reduce issues
	// with the login form
	csrfTokenDuration     = 4 * time.Hour
	tokenRefreshThreshold = 10 * time.Minute
	tokenValidationMode   = tokenValidationModeDefault
)

type jwtTokenClaims struct {
	Username                   string
	Permissions                []string
	Role                       string
	Signature                  string
	Audience                   []string
	APIKeyID                   string
	NodeID                     string
	MustSetTwoFactorAuth       bool
	MustChangePassword         bool
	RequiredTwoFactorProtocols []string
	HideUserPageSections       int
	JwtID                      string
	Ref                        string
}

func (c *jwtTokenClaims) hasUserAudience() bool {
	for _, audience := range c.Audience {
		if audience == tokenAudienceWebClient || audience == tokenAudienceAPIUser {
			return true
		}
	}

	return false
}

func (c *jwtTokenClaims) asMap() map[string]any {
	claims := make(map[string]any)

	claims[claimUsernameKey] = c.Username
	claims[claimPermissionsKey] = c.Permissions
	if c.JwtID != "" {
		claims[jwt.JwtIDKey] = c.JwtID
	}
	if c.Ref != "" {
		claims[claimRef] = c.Ref
	}
	if c.Role != "" {
		claims[claimRole] = c.Role
	}
	if c.APIKeyID != "" {
		claims[claimAPIKey] = c.APIKeyID
	}
	if c.NodeID != "" {
		claims[claimNodeID] = c.NodeID
	}
	claims[jwt.SubjectKey] = c.Signature
	if c.MustChangePassword {
		claims[claimMustChangePasswordKey] = c.MustChangePassword
	}
	if c.MustSetTwoFactorAuth {
		claims[claimMustSetSecondFactorKey] = c.MustSetTwoFactorAuth
	}
	if len(c.RequiredTwoFactorProtocols) > 0 {
		claims[claimRequiredTwoFactorProtocols] = c.RequiredTwoFactorProtocols
	}
	if c.HideUserPageSections > 0 {
		claims[claimHideUserPageSection] = c.HideUserPageSections
	}

	return claims
}

func (c *jwtTokenClaims) decodeSliceString(val any) []string {
	switch v := val.(type) {
	case []any:
		result := make([]string, 0, len(v))
		for _, elem := range v {
			switch elemValue := elem.(type) {
			case string:
				result = append(result, elemValue)
			}
		}
		return result
	case []string:
		return v
	default:
		return nil
	}
}

func (c *jwtTokenClaims) decodeBoolean(val any) bool {
	switch v := val.(type) {
	case bool:
		return v
	default:
		return false
	}
}

func (c *jwtTokenClaims) decodeString(val any) string {
	switch v := val.(type) {
	case string:
		return v
	default:
		return ""
	}
}

func (c *jwtTokenClaims) Decode(token map[string]any) {
	c.Permissions = nil
	c.Username = c.decodeString(token[claimUsernameKey])
	c.Signature = c.decodeString(token[jwt.SubjectKey])
	c.JwtID = c.decodeString(token[jwt.JwtIDKey])

	audience := token[jwt.AudienceKey]
	switch v := audience.(type) {
	case []string:
		c.Audience = v
	}

	if val, ok := token[claimRef]; ok {
		c.Ref = c.decodeString(val)
	}

	if val, ok := token[claimAPIKey]; ok {
		c.APIKeyID = c.decodeString(val)
	}

	if val, ok := token[claimNodeID]; ok {
		c.NodeID = c.decodeString(val)
	}

	if val, ok := token[claimRole]; ok {
		c.Role = c.decodeString(val)
	}

	permissions := token[claimPermissionsKey]
	c.Permissions = c.decodeSliceString(permissions)

	if val, ok := token[claimMustChangePasswordKey]; ok {
		c.MustChangePassword = c.decodeBoolean(val)
	}

	if val, ok := token[claimMustSetSecondFactorKey]; ok {
		c.MustSetTwoFactorAuth = c.decodeBoolean(val)
	}

	if val, ok := token[claimRequiredTwoFactorProtocols]; ok {
		c.RequiredTwoFactorProtocols = c.decodeSliceString(val)
	}

	if val, ok := token[claimHideUserPageSection]; ok {
		switch v := val.(type) {
		case float64:
			c.HideUserPageSections = int(v)
		}
	}
}

func (c *jwtTokenClaims) hasPerm(perm string) bool {
	if slices.Contains(c.Permissions, dataprovider.PermAdminAny) {
		return true
	}

	return slices.Contains(c.Permissions, perm)
}

func (c *jwtTokenClaims) createToken(tokenAuth *jwtauth.JWTAuth, audience tokenAudience, ip string) (jwt.Token, string, error) {
	claims := c.asMap()
	now := time.Now().UTC()

	if _, ok := claims[jwt.JwtIDKey]; !ok {
		claims[jwt.JwtIDKey] = xid.New().String()
	}
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	if audience == tokenAudienceWebLogin {
		claims[jwt.ExpirationKey] = now.Add(csrfTokenDuration)
	} else {
		claims[jwt.ExpirationKey] = now.Add(tokenDuration)
	}
	claims[jwt.AudienceKey] = []string{audience, ip}

	return tokenAuth.Encode(claims)
}

func (c *jwtTokenClaims) createTokenResponse(tokenAuth *jwtauth.JWTAuth, audience tokenAudience, ip string) (map[string]any, error) {
	token, tokenString, err := c.createToken(tokenAuth, audience, ip)
	if err != nil {
		return nil, err
	}

	response := make(map[string]any)
	response["access_token"] = tokenString
	response["expires_at"] = token.Expiration().Format(time.RFC3339)

	return response, nil
}

func (c *jwtTokenClaims) createAndSetCookie(w http.ResponseWriter, r *http.Request, tokenAuth *jwtauth.JWTAuth,
	audience tokenAudience, ip string,
) error {
	resp, err := c.createTokenResponse(tokenAuth, audience, ip)
	if err != nil {
		return err
	}
	var basePath string
	if audience == tokenAudienceWebAdmin || audience == tokenAudienceWebAdminPartial {
		basePath = webBaseAdminPath
	} else {
		basePath = webBaseClientPath
	}
	duration := tokenDuration
	if audience == tokenAudienceWebShare {
		duration = shareTokenDuration
	}
	setCookie(w, r, basePath, resp["access_token"].(string), duration)

	return nil
}

func setCookie(w http.ResponseWriter, r *http.Request, cookiePath, cookieValue string, duration time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieKey,
		Value:    cookieValue,
		Path:     cookiePath,
		Expires:  time.Now().Add(duration),
		MaxAge:   int(duration / time.Second),
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func removeCookie(w http.ResponseWriter, r *http.Request, cookiePath string) {
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieKey,
		Value:    "",
		Path:     cookiePath,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Add("Cache-Control", `no-cache="Set-Cookie"`)
	invalidateToken(r, false)
}

func oidcTokenFromContext(r *http.Request) string {
	if token, ok := r.Context().Value(oidcGeneratedToken).(string); ok {
		return token
	}
	return ""
}

func isTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto, ok := r.Context().Value(forwardedProtoKey).(string); ok {
		return proto == "https"
	}
	return false
}

func isTokenInvalidated(r *http.Request) bool {
	var findTokenFns []func(r *http.Request) string
	findTokenFns = append(findTokenFns, jwtauth.TokenFromHeader)
	findTokenFns = append(findTokenFns, jwtauth.TokenFromCookie)
	findTokenFns = append(findTokenFns, oidcTokenFromContext)

	isTokenFound := false
	for _, fn := range findTokenFns {
		token := fn(r)
		if token != "" {
			isTokenFound = true
			if invalidatedJWTTokens.Get(token) {
				return true
			}
		}
	}

	return !isTokenFound
}

func invalidateToken(r *http.Request, isLoginToken bool) {
	duration := tokenDuration
	if isLoginToken {
		duration = csrfTokenDuration
	}
	tokenString := jwtauth.TokenFromHeader(r)
	if tokenString != "" {
		invalidatedJWTTokens.Add(tokenString, time.Now().Add(duration).UTC())
	}
	tokenString = jwtauth.TokenFromCookie(r)
	if tokenString != "" {
		invalidatedJWTTokens.Add(tokenString, time.Now().Add(duration).UTC())
	}
}

func getUserFromToken(r *http.Request) *dataprovider.User {
	user := &dataprovider.User{}
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		return user
	}
	tokenClaims := jwtTokenClaims{}
	tokenClaims.Decode(claims)
	user.Username = tokenClaims.Username
	user.Filters.WebClient = tokenClaims.Permissions
	user.Role = tokenClaims.Role
	return user
}

func getAdminFromToken(r *http.Request) *dataprovider.Admin {
	admin := &dataprovider.Admin{}
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		return admin
	}
	tokenClaims := jwtTokenClaims{}
	tokenClaims.Decode(claims)
	admin.Username = tokenClaims.Username
	admin.Permissions = tokenClaims.Permissions
	admin.Filters.Preferences.HideUserPageSections = tokenClaims.HideUserPageSections
	admin.Role = tokenClaims.Role
	return admin
}

func createLoginCookie(w http.ResponseWriter, r *http.Request, csrfTokenAuth *jwtauth.JWTAuth, tokenID, basePath, ip string,
) {
	c := jwtTokenClaims{
		JwtID: tokenID,
	}
	resp, err := c.createTokenResponse(csrfTokenAuth, tokenAudienceWebLogin, ip)
	if err != nil {
		return
	}
	setCookie(w, r, basePath, resp["access_token"].(string), csrfTokenDuration)
}

func createCSRFToken(w http.ResponseWriter, r *http.Request, csrfTokenAuth *jwtauth.JWTAuth, tokenID,
	basePath string,
) string {
	ip := util.GetIPFromRemoteAddress(r.RemoteAddr)
	claims := make(map[string]any)
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(csrfTokenDuration)
	claims[jwt.AudienceKey] = []string{tokenAudienceCSRF, ip}
	if tokenID != "" {
		createLoginCookie(w, r, csrfTokenAuth, tokenID, basePath, ip)
		claims[claimRef] = tokenID
	} else {
		if c, err := getTokenClaims(r); err == nil {
			claims[claimRef] = c.JwtID
		} else {
			logger.Error(logSender, "", "unable to add reference to CSRF token: %v", err)
		}
	}
	_, tokenString, err := csrfTokenAuth.Encode(claims)
	if err != nil {
		logger.Debug(logSender, "", "unable to create CSRF token: %v", err)
		return ""
	}
	return tokenString
}

func verifyCSRFToken(r *http.Request, csrfTokenAuth *jwtauth.JWTAuth) error {
	tokenString := r.Form.Get(csrfFormToken)
	token, err := jwtauth.VerifyToken(csrfTokenAuth, tokenString)
	if err != nil || token == nil {
		logger.Debug(logSender, "", "error validating CSRF token %q: %v", tokenString, err)
		return fmt.Errorf("unable to verify form token: %v", err)
	}

	if !slices.Contains(token.Audience(), tokenAudienceCSRF) {
		logger.Debug(logSender, "", "error validating CSRF token audience")
		return errors.New("the form token is not valid")
	}

	if err := validateIPForToken(token, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
		logger.Debug(logSender, "", "error validating CSRF token IP audience")
		return errors.New("the form token is not valid")
	}
	return checkCSRFTokenRef(r, token)
}

func checkCSRFTokenRef(r *http.Request, token jwt.Token) error {
	claims, err := getTokenClaims(r)
	if err != nil {
		logger.Debug(logSender, "", "error getting token claims for CSRF validation: %v", err)
		return err
	}
	ref, ok := token.Get(claimRef)
	if !ok {
		logger.Debug(logSender, "", "error validating CSRF token, missing reference")
		return errors.New("the form token is not valid")
	}
	if claims.JwtID == "" || claims.JwtID != ref.(string) {
		logger.Debug(logSender, "", "error validating CSRF reference, id %q, reference %q", claims.JwtID, ref)
		return errors.New("unexpected form token")
	}

	return nil
}

func verifyLoginCookie(r *http.Request) error {
	token, _, err := jwtauth.FromContext(r.Context())
	if err != nil || token == nil {
		logger.Debug(logSender, "", "error getting login token: %v", err)
		return errInvalidToken
	}
	if isTokenInvalidated(r) {
		logger.Debug(logSender, "", "the login token has been invalidated")
		return errInvalidToken
	}
	if !slices.Contains(token.Audience(), tokenAudienceWebLogin) {
		logger.Debug(logSender, "", "the token with id %q is not valid for audience %q", token.JwtID(), tokenAudienceWebLogin)
		return errInvalidToken
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := validateIPForToken(token, ipAddr); err != nil {
		return err
	}
	return nil
}

func verifyLoginCookieAndCSRFToken(r *http.Request, csrfTokenAuth *jwtauth.JWTAuth) error {
	if err := verifyLoginCookie(r); err != nil {
		return err
	}
	if err := verifyCSRFToken(r, csrfTokenAuth); err != nil {
		return err
	}
	return nil
}

func createOAuth2Token(csrfTokenAuth *jwtauth.JWTAuth, state, ip string) string {
	claims := make(map[string]any)
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = state
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(3 * time.Minute)
	claims[jwt.AudienceKey] = []string{tokenAudienceOAuth2, ip}

	_, tokenString, err := csrfTokenAuth.Encode(claims)
	if err != nil {
		logger.Debug(logSender, "", "unable to create OAuth2 token: %v", err)
		return ""
	}
	return tokenString
}

func verifyOAuth2Token(csrfTokenAuth *jwtauth.JWTAuth, tokenString, ip string) (string, error) {
	token, err := jwtauth.VerifyToken(csrfTokenAuth, tokenString)
	if err != nil || token == nil {
		logger.Debug(logSender, "", "error validating OAuth2 token %q: %v", tokenString, err)
		return "", util.NewI18nError(
			fmt.Errorf("unable to verify OAuth2 state: %v", err),
			util.I18nOAuth2ErrorVerifyState,
		)
	}

	if !slices.Contains(token.Audience(), tokenAudienceOAuth2) {
		logger.Debug(logSender, "", "error validating OAuth2 token audience")
		return "", util.NewI18nError(errors.New("invalid OAuth2 state"), util.I18nOAuth2InvalidState)
	}

	if err := validateIPForToken(token, ip); err != nil {
		logger.Debug(logSender, "", "error validating OAuth2 token IP audience")
		return "", util.NewI18nError(errors.New("invalid OAuth2 state"), util.I18nOAuth2InvalidState)
	}
	if val, ok := token.Get(jwt.JwtIDKey); ok {
		if state, ok := val.(string); ok {
			return state, nil
		}
	}
	logger.Debug(logSender, "", "jti not found in OAuth2 token")
	return "", util.NewI18nError(errors.New("invalid OAuth2 state"), util.I18nOAuth2InvalidState)
}

func validateIPForToken(token jwt.Token, ip string) error {
	if tokenValidationMode&tokenValidationModeNoIPMatch == 0 {
		if !slices.Contains(token.Audience(), ip) {
			return errInvalidToken
		}
	}
	return nil
}

func checkTokenSignature(r *http.Request, token jwt.Token) error {
	if _, ok := r.Context().Value(oidcTokenKey).(string); ok {
		return nil
	}
	var err error
	if tokenValidationMode&tokenValidationModeUserSignature != 0 {
		for _, audience := range token.Audience() {
			switch audience {
			case tokenAudienceAPI, tokenAudienceWebAdmin:
				err = validateSignatureForToken(token, dataprovider.GetAdminSignature)
			case tokenAudienceAPIUser, tokenAudienceWebClient:
				err = validateSignatureForToken(token, dataprovider.GetUserSignature)
			}
		}
	}
	if err != nil {
		invalidateToken(r, false)
	}
	return err
}

func validateSignatureForToken(token jwt.Token, getter func(string) (string, error)) error {
	username := ""
	if u, ok := token.Get(claimUsernameKey); ok {
		c := jwtTokenClaims{}
		username = c.decodeString(u)
	}

	signature, err := getter(username)
	if err != nil {
		logger.Debug(logSender, "", "unable to get signature for username %q: %v", username, err)
		return errInvalidToken
	}
	if signature != "" && signature == token.Subject() {
		return nil
	}
	logger.Debug(logSender, "", "signature mismatch for username %q, signature %q, token signature %q",
		username, signature, token.Subject())
	return errInvalidToken
}
