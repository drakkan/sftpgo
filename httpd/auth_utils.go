package httpd

import (
	"net/http"
	"time"

	"github.com/go-chi/jwtauth"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/dataprovider"
	"github.com/drakkan/sftpgo/utils"
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

func (c *jwtTokenClaims) createTokenResponse(tokenAuth *jwtauth.JWTAuth) (map[string]interface{}, error) {
	claims := c.asMap()
	now := time.Now().UTC()

	claims[jwt.JwtIDKey] = xid.New().String()
	claims[jwt.NotBeforeKey] = now.Add(-30 * time.Second)
	claims[jwt.ExpirationKey] = now.Add(tokenDuration)

	token, tokenString, err := tokenAuth.Encode(claims)
	if err != nil {
		return nil, err
	}

	response := make(map[string]interface{})
	response["access_token"] = tokenString
	response["expires_at"] = token.Expiration().Format(time.RFC3339)

	return response, nil
}

func (c *jwtTokenClaims) createAndSetCookie(w http.ResponseWriter, tokenAuth *jwtauth.JWTAuth) error {
	resp, err := c.createTokenResponse(tokenAuth)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    resp["access_token"].(string),
		Path:     webBasePath,
		Expires:  time.Now().Add(tokenDuration),
		HttpOnly: true,
	})

	return nil
}

func (c *jwtTokenClaims) removeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    "",
		Path:     webBasePath,
		MaxAge:   -1,
		HttpOnly: true,
	})
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
