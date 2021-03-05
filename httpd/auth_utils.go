package httpd

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

type tokenAudience = string

const (
	tokenAudienceWeb  tokenAudience = "Web"
	tokenAudienceAPI  tokenAudience = "API"
	tokenAudienceCSRF tokenAudience = "CSRF"
)

const (
	claimUsernameKey    = "username"
	claimPermissionsKey = "permissions"
	basicRealm          = "Basic realm=\"SFTPGo\""
)

var (
	tokenDuration   = 10 * time.Minute
	tokenRefreshMin = 5 * time.Minute
)

type jwtTokenClaims struct {
	Username    string
	Permissions []string
	Signature   string
}

func (c *jwtTokenClaims) asMap() map[string]interface{} {
	claims := make(map[string]interface{})

	claims[claimUsernameKey] = c.Username
	claims[claimPermissionsKey] = c.Permissions
	claims[jwt.SubjectKey] = c.Signature

	return claims
}

func (c *jwtTokenClaims) Decode(token map[string]interface{}) {
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
}

func (c *jwtTokenClaims) isCriticalPermRemoved(permissions []string) bool {
	if utils.IsStringInSlice(dataprovider.PermAdminAny, permissions) {
		return false
	}
	if (utils.IsStringInSlice(dataprovider.PermAdminManageAdmins, c.Permissions) ||
		utils.IsStringInSlice(dataprovider.PermAdminAny, c.Permissions)) &&
		!utils.IsStringInSlice(dataprovider.PermAdminManageAdmins, permissions) &&
		!utils.IsStringInSlice(dataprovider.PermAdminAny, permissions) {
		return true
	}
	return false
}

func (c *jwtTokenClaims) hasPerm(perm string) bool {
	if utils.IsStringInSlice(dataprovider.PermAdminAny, c.Permissions) {
		return true
	}

	return utils.IsStringInSlice(perm, c.Permissions)
}

func (c *jwtTokenClaims) createTokenResponse(tokenAuth *jwtauth.JWTAuth, audience tokenAudience) (map[string]interface{}, error) {
	claims := c.asMap()
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(tokenDuration)
	claims[jwt.AudienceKey] = audience

	token, tokenString, err := tokenAuth.Encode(claims)
	if err != nil {
		return nil, err
	}

	response := make(map[string]interface{})
	response["access_token"] = tokenString
	response["expires_at"] = token.Expiration().Format(time.RFC3339)

	return response, nil
}

func (c *jwtTokenClaims) createAndSetCookie(w http.ResponseWriter, r *http.Request, tokenAuth *jwtauth.JWTAuth) error {
	resp, err := c.createTokenResponse(tokenAuth, tokenAudienceWeb)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    resp["access_token"].(string),
		Path:     webBasePath,
		Expires:  time.Now().Add(tokenDuration),
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})

	return nil
}

func (c *jwtTokenClaims) removeCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    "",
		Path:     webBasePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})
	invalidateToken(r)
}

func isTokenInvalidated(r *http.Request) bool {
	isTokenFound := false
	token := jwtauth.TokenFromHeader(r)
	if token != "" {
		isTokenFound = true
		if _, ok := invalidatedJWTTokens.Load(token); ok {
			return true
		}
	}
	token = jwtauth.TokenFromCookie(r)
	if token != "" {
		isTokenFound = true
		if _, ok := invalidatedJWTTokens.Load(token); ok {
			return true
		}
	}
	return !isTokenFound
}

func invalidateToken(r *http.Request) {
	tokenString := jwtauth.TokenFromHeader(r)
	if tokenString != "" {
		invalidatedJWTTokens.Store(tokenString, time.Now().UTC().Add(tokenDuration))
	}
	tokenString = jwtauth.TokenFromCookie(r)
	if tokenString != "" {
		invalidatedJWTTokens.Store(tokenString, time.Now().UTC().Add(tokenDuration))
	}
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

func createCSRFToken() string {
	claims := make(map[string]interface{})
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(tokenDuration)
	claims[jwt.AudienceKey] = tokenAudienceCSRF

	_, tokenString, err := csrfTokenAuth.Encode(claims)
	if err != nil {
		logger.Debug(logSender, "", "unable to create CSRF token: %v", err)
		return ""
	}
	return tokenString
}

func verifyCSRFToken(tokenString string) error {
	token, err := jwtauth.VerifyToken(csrfTokenAuth, tokenString)
	if err != nil || token == nil {
		logger.Debug(logSender, "", "error validating CSRF: %v", err)
		return fmt.Errorf("Unable to verify form token: %v", err)
	}

	if !utils.IsStringInSlice(tokenAudienceCSRF, token.Audience()) {
		logger.Debug(logSender, "", "error validating CSRF token audience")
		return errors.New("The form token is not valid")
	}

	return nil
}
