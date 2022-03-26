package httpd

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/v2/dataprovider"
	"github.com/drakkan/sftpgo/v2/logger"
	"github.com/drakkan/sftpgo/v2/util"
)

type tokenAudience = string

const (
	tokenAudienceWebAdmin         tokenAudience = "WebAdmin"
	tokenAudienceWebClient        tokenAudience = "WebClient"
	tokenAudienceWebAdminPartial  tokenAudience = "WebAdminPartial"
	tokenAudienceWebClientPartial tokenAudience = "WebClientPartial"
	tokenAudienceAPI              tokenAudience = "API"
	tokenAudienceAPIUser          tokenAudience = "APIUser"
	tokenAudienceCSRF             tokenAudience = "CSRF"
)

const (
	claimUsernameKey                = "username"
	claimPermissionsKey             = "permissions"
	claimAPIKey                     = "api_key"
	claimMustSetSecondFactorKey     = "2fa_required"
	claimRequiredTwoFactorProtocols = "2fa_protocols"
	basicRealm                      = "Basic realm=\"SFTPGo\""
	jwtCookieKey                    = "jwt"
)

var (
	tokenDuration = 20 * time.Minute
	// csrf token duration is greater than normal token duration to reduce issues
	// with the login form
	csrfTokenDuration     = 6 * time.Hour
	tokenRefreshThreshold = 10 * time.Minute
)

type jwtTokenClaims struct {
	Username                   string
	Permissions                []string
	Signature                  string
	Audience                   []string
	APIKeyID                   string
	MustSetTwoFactorAuth       bool
	RequiredTwoFactorProtocols []string
}

func (c *jwtTokenClaims) hasUserAudience() bool {
	for _, audience := range c.Audience {
		if audience == tokenAudienceWebClient || audience == tokenAudienceAPIUser {
			return true
		}
	}

	return false
}

func (c *jwtTokenClaims) asMap() map[string]interface{} {
	claims := make(map[string]interface{})

	claims[claimUsernameKey] = c.Username
	claims[claimPermissionsKey] = c.Permissions
	if c.APIKeyID != "" {
		claims[claimAPIKey] = c.APIKeyID
	}
	claims[jwt.SubjectKey] = c.Signature
	claims[claimMustSetSecondFactorKey] = c.MustSetTwoFactorAuth
	claims[claimRequiredTwoFactorProtocols] = c.RequiredTwoFactorProtocols

	return claims
}

func (c *jwtTokenClaims) Decode(token map[string]interface{}) {
	c.Permissions = nil
	username := token[claimUsernameKey]

	switch v := username.(type) {
	case string:
		c.Username = v
	}

	signature := token[jwt.SubjectKey]

	switch v := signature.(type) {
	case string:
		c.Signature = v
	}

	audience := token[jwt.AudienceKey]

	switch v := audience.(type) {
	case []string:
		c.Audience = v
	}

	if val, ok := token[claimAPIKey]; ok {
		switch v := val.(type) {
		case string:
			c.APIKeyID = v
		}
	}

	permissions := token[claimPermissionsKey]
	switch v := permissions.(type) {
	case []interface{}:
		for _, elem := range v {
			switch elemValue := elem.(type) {
			case string:
				c.Permissions = append(c.Permissions, elemValue)
			}
		}
	}

	secondFactorRequired := token[claimMustSetSecondFactorKey]
	switch v := secondFactorRequired.(type) {
	case bool:
		c.MustSetTwoFactorAuth = v
	}

	secondFactorProtocols := token[claimRequiredTwoFactorProtocols]
	switch v := secondFactorProtocols.(type) {
	case []interface{}:
		for _, elem := range v {
			switch elemValue := elem.(type) {
			case string:
				c.RequiredTwoFactorProtocols = append(c.RequiredTwoFactorProtocols, elemValue)
			}
		}
	}
}

func (c *jwtTokenClaims) isCriticalPermRemoved(permissions []string) bool {
	if util.IsStringInSlice(dataprovider.PermAdminAny, permissions) {
		return false
	}
	if (util.IsStringInSlice(dataprovider.PermAdminManageAdmins, c.Permissions) ||
		util.IsStringInSlice(dataprovider.PermAdminAny, c.Permissions)) &&
		!util.IsStringInSlice(dataprovider.PermAdminManageAdmins, permissions) &&
		!util.IsStringInSlice(dataprovider.PermAdminAny, permissions) {
		return true
	}
	return false
}

func (c *jwtTokenClaims) hasPerm(perm string) bool {
	if util.IsStringInSlice(dataprovider.PermAdminAny, c.Permissions) {
		return true
	}

	return util.IsStringInSlice(perm, c.Permissions)
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

func (c *jwtTokenClaims) createTokenResponse(tokenAuth *jwtauth.JWTAuth, audience tokenAudience, ip string) (map[string]interface{}, error) {
	token, tokenString, err := c.createToken(tokenAuth, audience, ip)
	if err != nil {
		return nil, err
	}

	response := make(map[string]interface{})
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
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieKey,
		Value:    resp["access_token"].(string),
		Path:     basePath,
		Expires:  time.Now().Add(tokenDuration),
		MaxAge:   int(tokenDuration / time.Second),
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
			if _, ok := invalidatedJWTTokens.Load(token); ok {
				return true
			}
		}
	}

	return !isTokenFound
}

func invalidateToken(r *http.Request) {
	tokenString := jwtauth.TokenFromHeader(r)
	if tokenString != "" {
		invalidatedJWTTokens.Store(tokenString, time.Now().Add(tokenDuration).UTC())
	}
	tokenString = jwtauth.TokenFromCookie(r)
	if tokenString != "" {
		invalidatedJWTTokens.Store(tokenString, time.Now().Add(tokenDuration).UTC())
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
	return admin
}

func createCSRFToken(ip string) string {
	claims := make(map[string]interface{})
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
		logger.Debug(logSender, "", "error validating CSRF token %#v: %v", tokenString, err)
		return fmt.Errorf("unable to verify form token: %v", err)
	}

	if !util.IsStringInSlice(tokenAudienceCSRF, token.Audience()) {
		logger.Debug(logSender, "", "error validating CSRF token audience")
		return errors.New("the form token is not valid")
	}

	if !util.IsStringInSlice(ip, token.Audience()) {
		logger.Debug(logSender, "", "error validating CSRF token IP audience")
		return errors.New("the form token is not valid")
	}

	return nil
}
