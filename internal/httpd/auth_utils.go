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
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
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
	basicRealm = "Basic realm=\"SFTPGo\""
)

var (
	apiTokenDuration    = 20 * time.Minute
	cookieTokenDuration = 20 * time.Minute
	shareTokenDuration  = 2 * time.Hour
	// csrf token duration is greater than normal token duration to reduce issues
	// with the login form
	csrfTokenDuration      = 4 * time.Hour
	cookieRefreshThreshold = 10 * time.Minute
	maxTokenDuration       = 12 * time.Hour
	tokenValidationMode    = tokenValidationModeDefault
)

func isTokenDurationValid(minutes int) bool {
	return minutes >= 1 && minutes <= 720
}

func updateTokensDuration(api, cookie, share int) {
	if isTokenDurationValid(api) {
		apiTokenDuration = time.Duration(api) * time.Minute
	}
	if isTokenDurationValid(cookie) {
		cookieTokenDuration = time.Duration(cookie) * time.Minute
		cookieRefreshThreshold = cookieTokenDuration / 2
		if cookieTokenDuration > csrfTokenDuration {
			csrfTokenDuration = cookieTokenDuration
		}
	}
	if isTokenDurationValid(share) {
		shareTokenDuration = time.Duration(share) * time.Minute
	}
	logger.Debug(logSender, "", "API token duration %s, cookie token duration %s, cookie refresh threshold %s, share token duration %s, csrf token duration %s",
		apiTokenDuration, cookieTokenDuration, cookieRefreshThreshold, shareTokenDuration, csrfTokenDuration)
}

func getTokenDuration(audience tokenAudience) time.Duration {
	switch audience {
	case tokenAudienceWebShare:
		return shareTokenDuration
	case tokenAudienceWebLogin, tokenAudienceCSRF:
		return csrfTokenDuration
	case tokenAudienceAPI, tokenAudienceAPIUser:
		return apiTokenDuration
	case tokenAudienceWebAdmin, tokenAudienceWebClient:
		return cookieTokenDuration
	case tokenAudienceWebAdminPartial, tokenAudienceWebClientPartial, tokenAudienceOAuth2:
		return 5 * time.Minute
	default:
		logger.Error(logSender, "", "token duration not handled for audience: %q", audience)
		return 20 * time.Minute
	}
}

func getMaxCookieDuration() time.Duration {
	result := csrfTokenDuration
	if shareTokenDuration > result {
		result = shareTokenDuration
	}
	if cookieTokenDuration > result {
		result = cookieTokenDuration
	}
	return result
}

func hasUserAudience(claims *jwt.Claims) bool {
	return claims.HasAnyAudience([]string{tokenAudienceWebClient, tokenAudienceAPIUser})
}

func createAndSetCookie(w http.ResponseWriter, r *http.Request, claims *jwt.Claims, tokenAuth *jwt.Signer,
	audience tokenAudience, ip string,
) error {
	duration := getTokenDuration(audience)
	token, err := tokenAuth.SignWithParams(claims, audience, ip, duration)
	if err != nil {
		return err
	}
	resp := claims.BuildTokenResponse(token)
	var basePath string
	if audience == tokenAudienceWebAdmin || audience == tokenAudienceWebAdminPartial {
		basePath = webBaseAdminPath
	} else {
		basePath = webBaseClientPath
	}
	setCookie(w, r, basePath, resp.Token, duration)

	return nil
}

func setCookie(w http.ResponseWriter, r *http.Request, cookiePath, cookieValue string, duration time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     jwt.CookieKey,
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
	invalidateToken(r)
	http.SetCookie(w, &http.Cookie{
		Name:     jwt.CookieKey,
		Value:    "",
		Path:     cookiePath,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteStrictMode,
	})
	w.Header().Add("Cache-Control", `no-cache="Set-Cookie"`)
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
	findTokenFns = append(findTokenFns, jwt.TokenFromHeader)
	findTokenFns = append(findTokenFns, jwt.TokenFromCookie)
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

func invalidateToken(r *http.Request) {
	tokenString := jwt.TokenFromHeader(r)
	if tokenString != "" {
		invalidateTokenString(r, tokenString, apiTokenDuration)
	}
	tokenString = jwt.TokenFromCookie(r)
	if tokenString != "" {
		invalidateTokenString(r, tokenString, getMaxCookieDuration())
	}
}

func invalidateTokenString(r *http.Request, tokenString string, fallbackDuration time.Duration) {
	token, err := jwt.FromContext(r.Context())
	if err != nil {
		invalidatedJWTTokens.Add(tokenString, time.Now().Add(fallbackDuration).UTC())
		return
	}
	invalidatedJWTTokens.Add(tokenString, token.Expiry.Time().Add(1*time.Minute).UTC())
}

func getUserFromToken(r *http.Request) *dataprovider.User {
	user := &dataprovider.User{}
	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		return user
	}
	user.Username = claims.Username
	user.Filters.WebClient = claims.Permissions
	user.Role = claims.Role
	return user
}

func getAdminFromToken(r *http.Request) *dataprovider.Admin {
	admin := &dataprovider.Admin{}
	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		return admin
	}
	admin.Username = claims.Username
	admin.Permissions = claims.Permissions
	admin.Filters.Preferences.HideUserPageSections = claims.HideUserPageSections
	admin.Role = claims.Role
	return admin
}

func createLoginCookie(w http.ResponseWriter, r *http.Request, csrfTokenAuth *jwt.Signer, tokenID, basePath, ip string,
) {
	c := jwt.NewClaims(tokenAudienceWebLogin, ip, getTokenDuration(tokenAudienceWebLogin))
	c.ID = tokenID
	resp, err := c.GenerateTokenResponse(csrfTokenAuth)
	if err != nil {
		return
	}
	setCookie(w, r, basePath, resp.Token, csrfTokenDuration)
}

func createCSRFToken(w http.ResponseWriter, r *http.Request, csrfTokenAuth *jwt.Signer, tokenID,
	basePath string,
) string {
	ip := util.GetIPFromRemoteAddress(r.RemoteAddr)
	claims := jwt.NewClaims(tokenAudienceCSRF, ip, csrfTokenDuration)
	claims.ID = rand.Text()
	if tokenID != "" {
		createLoginCookie(w, r, csrfTokenAuth, tokenID, basePath, ip)
		claims.Ref = tokenID
	} else {
		if c, err := jwt.FromContext(r.Context()); err == nil {
			claims.Ref = c.ID
		} else {
			logger.Error(logSender, "", "unable to add reference to CSRF token: %v", err)
		}
	}
	tokenString, err := csrfTokenAuth.Sign(claims)
	if err != nil {
		logger.Debug(logSender, "", "unable to create CSRF token: %v", err)
		return ""
	}
	return tokenString
}

func verifyCSRFToken(r *http.Request, csrfTokenAuth *jwt.Signer) error {
	tokenString := r.Form.Get(csrfFormToken)
	token, err := jwt.VerifyToken(csrfTokenAuth, tokenString)
	if err != nil || token == nil {
		logger.Debug(logSender, "", "error validating CSRF token %q: %v", tokenString, err)
		return fmt.Errorf("unable to verify form token: %v", err)
	}

	if !token.Audience.Contains(tokenAudienceCSRF) {
		logger.Debug(logSender, "", "error validating CSRF token audience")
		return errors.New("the form token is not valid")
	}

	if err := validateIPForToken(token, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
		logger.Debug(logSender, "", "error validating CSRF token IP audience")
		return errors.New("the form token is not valid")
	}
	return checkCSRFTokenRef(r, token)
}

func checkCSRFTokenRef(r *http.Request, token *jwt.Claims) error {
	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		logger.Debug(logSender, "", "error getting token claims for CSRF validation: %v", err)
		return err
	}
	if token.ID == "" {
		logger.Debug(logSender, "", "error validating CSRF token, missing reference")
		return errors.New("the form token is not valid")
	}
	if claims.ID != token.Ref {
		logger.Debug(logSender, "", "error validating CSRF reference, id %q, reference %q", claims.ID, token.ID)
		return errors.New("unexpected form token")
	}

	return nil
}

func verifyLoginCookie(r *http.Request) error {
	token, err := jwt.FromContext(r.Context())
	if err != nil {
		logger.Debug(logSender, "", "error getting login token: %v", err)
		return errInvalidToken
	}
	if isTokenInvalidated(r) {
		logger.Debug(logSender, "", "the login token has been invalidated")
		return errInvalidToken
	}
	if !token.Audience.Contains(tokenAudienceWebLogin) {
		logger.Debug(logSender, "", "the token with id %q is not valid for audience %q", token.ID, tokenAudienceWebLogin)
		return errInvalidToken
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := validateIPForToken(token, ipAddr); err != nil {
		return err
	}
	return nil
}

func verifyLoginCookieAndCSRFToken(r *http.Request, csrfTokenAuth *jwt.Signer) error {
	if err := verifyLoginCookie(r); err != nil {
		return err
	}
	if err := verifyCSRFToken(r, csrfTokenAuth); err != nil {
		return err
	}
	return nil
}

func createOAuth2Token(csrfTokenAuth *jwt.Signer, state, ip string) string {
	claims := jwt.NewClaims(tokenAudienceOAuth2, ip, getTokenDuration(tokenAudienceOAuth2))
	claims.ID = state

	tokenString, err := csrfTokenAuth.Sign(claims)
	if err != nil {
		logger.Debug(logSender, "", "unable to create OAuth2 token: %v", err)
		return ""
	}
	return tokenString
}

func verifyOAuth2Token(csrfTokenAuth *jwt.Signer, tokenString, ip string) (string, error) {
	token, err := jwt.VerifyToken(csrfTokenAuth, tokenString)
	if err != nil || token == nil {
		logger.Debug(logSender, "", "error validating OAuth2 token %q: %v", tokenString, err)
		return "", util.NewI18nError(
			fmt.Errorf("unable to verify OAuth2 state: %v", err),
			util.I18nOAuth2ErrorVerifyState,
		)
	}

	if !token.Audience.Contains(tokenAudienceOAuth2) {
		logger.Debug(logSender, "", "error validating OAuth2 token audience")
		return "", util.NewI18nError(errors.New("invalid OAuth2 state"), util.I18nOAuth2InvalidState)
	}

	if err := validateIPForToken(token, ip); err != nil {
		logger.Debug(logSender, "", "error validating OAuth2 token IP audience")
		return "", util.NewI18nError(errors.New("invalid OAuth2 state"), util.I18nOAuth2InvalidState)
	}
	if token.ID != "" {
		return token.ID, nil
	}
	logger.Debug(logSender, "", "jti not found in OAuth2 token")
	return "", util.NewI18nError(errors.New("invalid OAuth2 state"), util.I18nOAuth2InvalidState)
}

func validateIPForToken(token *jwt.Claims, ip string) error {
	if tokenValidationMode&tokenValidationModeNoIPMatch == 0 {
		if !token.Audience.Contains(ip) {
			return errInvalidToken
		}
	}
	return nil
}

func checkTokenSignature(r *http.Request, token *jwt.Claims) error {
	if _, ok := r.Context().Value(oidcTokenKey).(string); ok {
		return nil
	}
	var err error
	if tokenValidationMode&tokenValidationModeUserSignature != 0 {
		for _, audience := range token.Audience {
			switch audience {
			case tokenAudienceAPI, tokenAudienceWebAdmin:
				err = validateSignatureForToken(token, dataprovider.GetAdminSignature)
			case tokenAudienceAPIUser, tokenAudienceWebClient:
				err = validateSignatureForToken(token, dataprovider.GetUserSignature)
			}
		}
	}
	if err != nil {
		invalidateToken(r)
	}
	return err
}

func validateSignatureForToken(token *jwt.Claims, getter func(string) (string, error)) error {
	signature, err := getter(token.Username)
	if err != nil {
		logger.Debug(logSender, "", "unable to get signature for username %q: %v", token.Username, err)
		return errInvalidToken
	}
	if signature != "" && signature == token.Subject {
		return nil
	}
	logger.Debug(logSender, "", "signature mismatch for username %q, signature %q, token signature %q",
		token.Username, signature, token.Subject)
	return errInvalidToken
}
