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
)

type tokenValidation = int

const (
	tokenValidationFull                      = iota
	tokenValidationNoIPMatch tokenValidation = iota
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
	basicRealm                      = "Basic realm=\"SFTPGo\""
	jwtCookieKey                    = "jwt"
)

var (
	tokenDuration      = 20 * time.Minute
	shareTokenDuration = 12 * time.Hour
	// csrf token duration is greater than normal token duration to reduce issues
	// with the login form
	csrfTokenDuration     = 6 * time.Hour
	tokenRefreshThreshold = 10 * time.Minute
	tokenValidationMode   = tokenValidationFull
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

	audience := token[jwt.AudienceKey]
	switch v := audience.(type) {
	case []string:
		c.Audience = v
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

func (c *jwtTokenClaims) isCriticalPermRemoved(permissions []string) bool {
	if util.Contains(permissions, dataprovider.PermAdminAny) {
		return false
	}
	if (util.Contains(c.Permissions, dataprovider.PermAdminManageAdmins) ||
		util.Contains(c.Permissions, dataprovider.PermAdminAny)) &&
		!util.Contains(permissions, dataprovider.PermAdminManageAdmins) &&
		!util.Contains(permissions, dataprovider.PermAdminAny) {
		return true
	}
	return false
}

func (c *jwtTokenClaims) hasPerm(perm string) bool {
	if util.Contains(c.Permissions, dataprovider.PermAdminAny) {
		return true
	}

	return util.Contains(c.Permissions, perm)
}

func (c *jwtTokenClaims) createToken(tokenAuth *jwtauth.JWTAuth, audience tokenAudience, ip string) (jwt.Token, string, error) {
	claims := c.asMap()
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(tokenDuration)
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
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieKey,
		Value:    resp["access_token"].(string),
		Path:     basePath,
		Expires:  time.Now().Add(duration),
		MaxAge:   int(duration / time.Second),
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

func (c *jwtTokenClaims) removeCookie(w http.ResponseWriter, r *http.Request, cookiePath string) {
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
	invalidateToken(r)
}

func tokenFromContext(r *http.Request) string {
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
	findTokenFns = append(findTokenFns, tokenFromContext)

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

func invalidateToken(r *http.Request) {
	tokenString := jwtauth.TokenFromHeader(r)
	if tokenString != "" {
		invalidatedJWTTokens.Add(tokenString, time.Now().Add(tokenDuration).UTC())
	}
	tokenString = jwtauth.TokenFromCookie(r)
	if tokenString != "" {
		invalidatedJWTTokens.Add(tokenString, time.Now().Add(tokenDuration).UTC())
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

func createCSRFToken(ip string) string {
	claims := make(map[string]any)
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(csrfTokenDuration)
	claims[jwt.AudienceKey] = []string{tokenAudienceCSRF, ip}

	_, tokenString, err := csrfTokenAuth.Encode(claims)
	if err != nil {
		logger.Debug(logSender, "", "unable to create CSRF token: %v", err)
		return ""
	}
	return tokenString
}

func verifyCSRFToken(tokenString, ip string) error {
	token, err := jwtauth.VerifyToken(csrfTokenAuth, tokenString)
	if err != nil || token == nil {
		logger.Debug(logSender, "", "error validating CSRF token %q: %v", tokenString, err)
		return fmt.Errorf("unable to verify form token: %v", err)
	}

	if !util.Contains(token.Audience(), tokenAudienceCSRF) {
		logger.Debug(logSender, "", "error validating CSRF token audience")
		return errors.New("the form token is not valid")
	}

	if tokenValidationMode != tokenValidationNoIPMatch {
		if !util.Contains(token.Audience(), ip) {
			logger.Debug(logSender, "", "error validating CSRF token IP audience")
			return errors.New("the form token is not valid")
		}
	}

	return nil
}

func createOAuth2Token(state, ip string) string {
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

func verifyOAuth2Token(tokenString, ip string) (string, error) {
	token, err := jwtauth.VerifyToken(csrfTokenAuth, tokenString)
	if err != nil || token == nil {
		logger.Debug(logSender, "", "error validating OAuth2 token %q: %v", tokenString, err)
		return "", util.NewI18nError(
			fmt.Errorf("unable to verify OAuth2 state: %v", err),
			util.I18nOAuth2ErrorVerifyState,
		)
	}

	if !util.Contains(token.Audience(), tokenAudienceOAuth2) {
		logger.Debug(logSender, "", "error validating OAuth2 token audience")
		return "", util.NewI18nError(errors.New("invalid OAuth2 state"), util.I18nOAuth2InvalidState)
	}

	if tokenValidationMode != tokenValidationNoIPMatch {
		if !util.Contains(token.Audience(), ip) {
			logger.Debug(logSender, "", "error validating OAuth2 token IP audience")
			return "", util.NewI18nError(errors.New("invalid OAuth2 state"), util.I18nOAuth2InvalidState)
		}
	}
	if val, ok := token.Get(jwt.JwtIDKey); ok {
		if state, ok := val.(string); ok {
			return state, nil
		}
	}
	logger.Debug(logSender, "", "jti not found in OAuth2 token")
	return "", util.NewI18nError(errors.New("invalid OAuth2 state"), util.I18nOAuth2InvalidState)
}
