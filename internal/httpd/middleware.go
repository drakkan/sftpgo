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
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/jwtauth/v5"
	"github.com/rs/xid"
	"github.com/sftpgo/sdk"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

var (
	forwardedProtoKey = &contextKey{"forwarded proto"}
	errInvalidToken   = errors.New("invalid JWT token")
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "context value " + k.name
}

func validateJWTToken(w http.ResponseWriter, r *http.Request, audience tokenAudience) error {
	token, _, err := jwtauth.FromContext(r.Context())

	var redirectPath string
	if audience == tokenAudienceWebAdmin {
		redirectPath = webAdminLoginPath
	} else {
		redirectPath = webClientLoginPath
		if uri := r.RequestURI; strings.HasPrefix(uri, webClientFilesPath) {
			redirectPath += "?next=" + url.QueryEscape(uri) //nolint:goconst
		}
	}

	isAPIToken := (audience == tokenAudienceAPI || audience == tokenAudienceAPIUser)

	doRedirect := func(message string, err error) {
		if isAPIToken {
			sendAPIResponse(w, r, err, message, http.StatusUnauthorized)
		} else {
			http.Redirect(w, r, redirectPath, http.StatusFound)
		}
	}

	if err != nil || token == nil {
		logger.Debug(logSender, "", "error getting jwt token: %v", err)
		doRedirect(http.StatusText(http.StatusUnauthorized), err)
		return errInvalidToken
	}

	if isTokenInvalidated(r) {
		logger.Debug(logSender, "", "the token has been invalidated")
		doRedirect("Your token is no longer valid", nil)
		return errInvalidToken
	}
	// a user with a partial token will be always redirected to the appropriate two factor auth page
	if err := checkPartialAuth(w, r, audience, token.Audience()); err != nil {
		return err
	}
	if !slices.Contains(token.Audience(), audience) {
		logger.Debug(logSender, "", "the token is not valid for audience %q", audience)
		doRedirect("Your token audience is not valid", nil)
		return errInvalidToken
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := validateIPForToken(token, ipAddr); err != nil {
		logger.Debug(logSender, "", "the token with id %q is not valid for the ip address %q", token.JwtID(), ipAddr)
		doRedirect("Your token is not valid", nil)
		return err
	}
	if err := checkTokenSignature(r, token); err != nil {
		doRedirect("Your token is no longer valid", nil)
		return err
	}
	return nil
}

func (s *httpdServer) validateJWTPartialToken(w http.ResponseWriter, r *http.Request, audience tokenAudience) error {
	token, _, err := jwtauth.FromContext(r.Context())
	var notFoundFunc func(w http.ResponseWriter, r *http.Request, err error)
	if audience == tokenAudienceWebAdminPartial {
		notFoundFunc = s.renderNotFoundPage
	} else {
		notFoundFunc = s.renderClientNotFoundPage
	}
	if err != nil || token == nil {
		notFoundFunc(w, r, nil)
		return errInvalidToken
	}
	if isTokenInvalidated(r) {
		notFoundFunc(w, r, nil)
		return errInvalidToken
	}
	if !slices.Contains(token.Audience(), audience) {
		logger.Debug(logSender, "", "the partial token with id %q is not valid for audience %q", token.JwtID(), audience)
		notFoundFunc(w, r, nil)
		return errInvalidToken
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := validateIPForToken(token, ipAddr); err != nil {
		logger.Debug(logSender, "", "the partial token with id %q is not valid for the ip address %q", token.JwtID(), ipAddr)
		notFoundFunc(w, r, nil)
		return err
	}

	return nil
}

func (s *httpdServer) jwtAuthenticatorPartial(audience tokenAudience) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := s.validateJWTPartialToken(w, r, audience); err != nil {
				return
			}

			// Token is authenticated, pass it through
			next.ServeHTTP(w, r)
		})
	}
}

func jwtAuthenticatorAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := validateJWTToken(w, r, tokenAudienceAPI); err != nil {
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func jwtAuthenticatorAPIUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := validateJWTToken(w, r, tokenAudienceAPIUser); err != nil {
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func jwtAuthenticatorWebAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := validateJWTToken(w, r, tokenAudienceWebAdmin); err != nil {
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func jwtAuthenticatorWebClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := validateJWTToken(w, r, tokenAudienceWebClient); err != nil {
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func (s *httpdServer) checkHTTPUserPerm(perm string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())
			if err != nil {
				if isWebRequest(r) {
					s.renderClientBadRequestPage(w, r, err)
				} else {
					sendAPIResponse(w, r, err, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				}
				return
			}
			tokenClaims := jwtTokenClaims{}
			tokenClaims.Decode(claims)
			// for web client perms are negated and not granted
			if tokenClaims.hasPerm(perm) {
				if isWebRequest(r) {
					s.renderClientForbiddenPage(w, r, errors.New("you don't have permission for this action"))
				} else {
					sendAPIResponse(w, r, nil, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// checkAuthRequirements checks if the user must set a second factor auth or change the password
func (s *httpdServer) checkAuthRequirements(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, claims, err := jwtauth.FromContext(r.Context())
		if err != nil {
			if isWebRequest(r) {
				if isWebClientRequest(r) {
					s.renderClientBadRequestPage(w, r, err)
				} else {
					s.renderBadRequestPage(w, r, err)
				}
			} else {
				sendAPIResponse(w, r, err, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			}
			return
		}
		tokenClaims := jwtTokenClaims{}
		tokenClaims.Decode(claims)
		if tokenClaims.MustSetTwoFactorAuth || tokenClaims.MustChangePassword {
			var err error
			if tokenClaims.MustSetTwoFactorAuth {
				if len(tokenClaims.RequiredTwoFactorProtocols) > 0 {
					protocols := strings.Join(tokenClaims.RequiredTwoFactorProtocols, ", ")
					err = util.NewI18nError(
						util.NewGenericError(
							fmt.Sprintf("Two-factor authentication requirements not met, please configure two-factor authentication for the following protocols: %v",
								protocols)),
						util.I18nError2FARequired,
						util.I18nErrorArgs(map[string]any{
							"val": protocols,
						}),
					)
				} else {
					err = util.NewI18nError(
						util.NewGenericError("Two-factor authentication requirements not met, please configure two-factor authentication"),
						util.I18nError2FARequiredGeneric,
					)
				}
			} else {
				err = util.NewI18nError(
					util.NewGenericError("Password change required. Please set a new password to continue to use your account"),
					util.I18nErrorChangePwdRequired,
				)
			}
			if isWebRequest(r) {
				if isWebClientRequest(r) {
					s.renderClientForbiddenPage(w, r, err)
				} else {
					s.renderForbiddenPage(w, r, err)
				}
			} else {
				sendAPIResponse(w, r, err, "", http.StatusForbidden)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *httpdServer) requireBuiltinLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLoggedInWithOIDC(r) {
			err := util.NewI18nError(
				util.NewGenericError("This feature is not available if you are logged in with OpenID"),
				util.I18nErrorNoOIDCFeature,
			)
			if isWebClientRequest(r) {
				s.renderClientForbiddenPage(w, r, err)
			} else {
				s.renderForbiddenPage(w, r, err)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *httpdServer) checkPerms(perms ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())
			if err != nil {
				if isWebRequest(r) {
					s.renderBadRequestPage(w, r, err)
				} else {
					sendAPIResponse(w, r, err, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				}
				return
			}
			tokenClaims := jwtTokenClaims{}
			tokenClaims.Decode(claims)

			for _, perm := range perms {
				if !tokenClaims.hasPerm(perm) {
					if isWebRequest(r) {
						s.renderForbiddenPage(w, r, util.NewI18nError(fs.ErrPermission, util.I18nError403Message))
					} else {
						sendAPIResponse(w, r, nil, http.StatusText(http.StatusForbidden), http.StatusForbidden)
					}
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (s *httpdServer) verifyCSRFHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get(csrfHeaderToken)
		token, err := jwtauth.VerifyToken(s.csrfTokenAuth, tokenString)
		if err != nil || token == nil {
			logger.Debug(logSender, "", "error validating CSRF header: %v", err)
			sendAPIResponse(w, r, err, "Invalid token", http.StatusForbidden)
			return
		}

		if !slices.Contains(token.Audience(), tokenAudienceCSRF) {
			logger.Debug(logSender, "", "error validating CSRF header token audience")
			sendAPIResponse(w, r, errors.New("the token is not valid"), "", http.StatusForbidden)
			return
		}

		if err := validateIPForToken(token, util.GetIPFromRemoteAddress(r.RemoteAddr)); err != nil {
			logger.Debug(logSender, "", "error validating CSRF header IP audience")
			sendAPIResponse(w, r, errors.New("the token is not valid"), "", http.StatusForbidden)
			return
		}
		if err := checkCSRFTokenRef(r, token); err != nil {
			sendAPIResponse(w, r, errors.New("the token is not valid"), "", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func checkNodeToken(tokenAuth *jwtauth.JWTAuth) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get(dataprovider.NodeTokenHeader)
			if token == "" {
				next.ServeHTTP(w, r)
				return
			}
			if len(token) > 7 && strings.ToUpper(token[0:6]) == "BEARER" {
				token = token[7:]
			}
			admin, role, err := dataprovider.AuthenticateNodeToken(token)
			if err != nil {
				logger.Debug(logSender, "", "unable to authenticate node token %q: %v", token, err)
				sendAPIResponse(w, r, fmt.Errorf("the provided token cannot be authenticated"), "", http.StatusUnauthorized)
				return
			}
			c := jwtTokenClaims{
				Username:    admin,
				Permissions: []string{dataprovider.PermAdminViewConnections, dataprovider.PermAdminCloseConnections},
				NodeID:      dataprovider.GetNodeName(),
				Role:        role,
			}
			resp, err := c.createTokenResponse(tokenAuth, tokenAudienceAPI, util.GetIPFromRemoteAddress(r.RemoteAddr))
			if err != nil {
				sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", resp["access_token"]))

			next.ServeHTTP(w, r)
		})
	}
}

func checkAPIKeyAuth(tokenAuth *jwtauth.JWTAuth, scope dataprovider.APIKeyScope) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get("X-SFTPGO-API-KEY")
			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}
			keyParams := strings.SplitN(apiKey, ".", 3)
			if len(keyParams) < 2 {
				logger.Debug(logSender, "", "invalid api key %q", apiKey)
				sendAPIResponse(w, r, errors.New("the provided api key is not valid"), "", http.StatusBadRequest)
				return
			}
			keyID := keyParams[0]
			key := keyParams[1]
			apiUser := ""
			if len(keyParams) > 2 {
				apiUser = keyParams[2]
			}

			k, err := dataprovider.APIKeyExists(keyID)
			if err != nil {
				handleDefenderEventLoginFailed(util.GetIPFromRemoteAddress(r.RemoteAddr), util.NewRecordNotFoundError("invalid api key")) //nolint:errcheck
				logger.Debug(logSender, "", "invalid api key %q: %v", apiKey, err)
				sendAPIResponse(w, r, errors.New("the provided api key is not valid"), "", http.StatusBadRequest)
				return
			}
			if k.Scope != scope {
				handleDefenderEventLoginFailed(util.GetIPFromRemoteAddress(r.RemoteAddr), dataprovider.ErrInvalidCredentials) //nolint:errcheck
				logger.Debug(logSender, "", "unable to authenticate api key %q: invalid scope: got %d, wanted: %d",
					apiKey, k.Scope, scope)
				sendAPIResponse(w, r, fmt.Errorf("the provided api key is invalid for this request"), "", http.StatusForbidden)
				return
			}
			if err := k.Authenticate(key); err != nil {
				handleDefenderEventLoginFailed(util.GetIPFromRemoteAddress(r.RemoteAddr), dataprovider.ErrInvalidCredentials) //nolint:errcheck
				logger.Debug(logSender, "", "unable to authenticate api key %q: %v", apiKey, err)
				sendAPIResponse(w, r, fmt.Errorf("the provided api key cannot be authenticated"), "", http.StatusUnauthorized)
				return
			}
			if scope == dataprovider.APIKeyScopeAdmin {
				if k.Admin != "" {
					apiUser = k.Admin
				}
				if err := authenticateAdminWithAPIKey(apiUser, keyID, tokenAuth, r); err != nil {
					handleDefenderEventLoginFailed(util.GetIPFromRemoteAddress(r.RemoteAddr), err) //nolint:errcheck
					logger.Debug(logSender, "", "unable to authenticate admin %q associated with api key %q: %v",
						apiUser, apiKey, err)
					sendAPIResponse(w, r, fmt.Errorf("the admin associated with the provided api key cannot be authenticated"),
						"", http.StatusUnauthorized)
					return
				}
				common.DelayLogin(nil)
			} else {
				if k.User != "" {
					apiUser = k.User
				}
				if err := authenticateUserWithAPIKey(apiUser, keyID, tokenAuth, r); err != nil {
					logger.Debug(logSender, "", "unable to authenticate user %q associated with api key %q: %v",
						apiUser, apiKey, err)
					updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: apiUser}},
						dataprovider.LoginMethodPassword, util.GetIPFromRemoteAddress(r.RemoteAddr), err, r)
					code := http.StatusUnauthorized
					if errors.Is(err, common.ErrInternalFailure) {
						code = http.StatusInternalServerError
					}
					sendAPIResponse(w, r, errors.New("the user associated with the provided api key cannot be authenticated"),
						"", code)
					return
				}
				updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: apiUser}},
					dataprovider.LoginMethodPassword, util.GetIPFromRemoteAddress(r.RemoteAddr), nil, r)
			}
			dataprovider.UpdateAPIKeyLastUse(&k) //nolint:errcheck

			next.ServeHTTP(w, r)
		})
	}
}

func forbidAPIKeyAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := getTokenClaims(r)
		if err != nil || claims.Username == "" {
			sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
			return
		}
		if claims.APIKeyID != "" {
			sendAPIResponse(w, r, nil, "API key authentication is not allowed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func authenticateAdminWithAPIKey(username, keyID string, tokenAuth *jwtauth.JWTAuth, r *http.Request) error {
	if username == "" {
		return errors.New("the provided key is not associated with any admin and no username was provided")
	}
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		return err
	}
	if !admin.Filters.AllowAPIKeyAuth {
		return fmt.Errorf("API key authentication disabled for admin %q", admin.Username)
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := admin.CanLogin(ipAddr); err != nil {
		return err
	}
	c := jwtTokenClaims{
		Username:    admin.Username,
		Permissions: admin.Permissions,
		Signature:   admin.GetSignature(),
		Role:        admin.Role,
		APIKeyID:    keyID,
	}

	resp, err := c.createTokenResponse(tokenAuth, tokenAudienceAPI, ipAddr)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", resp["access_token"]))
	dataprovider.UpdateAdminLastLogin(&admin)
	common.DelayLogin(nil)
	return nil
}

func authenticateUserWithAPIKey(username, keyID string, tokenAuth *jwtauth.JWTAuth, r *http.Request) error {
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	protocol := common.ProtocolHTTP
	if username == "" {
		err := errors.New("the provided key is not associated with any user and no username was provided")
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		return err
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, protocol); err != nil {
		return err
	}
	user, err := dataprovider.GetUserWithGroupSettings(username, "")
	if err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		return err
	}
	if !user.Filters.AllowAPIKeyAuth {
		err := fmt.Errorf("API key authentication disabled for user %q", user.Username)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		return err
	}
	if err := user.CheckLoginConditions(); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		return err
	}
	connectionID := fmt.Sprintf("%v_%v", protocol, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID, true, false); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		return err
	}
	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		return common.ErrInternalFailure
	}
	c := jwtTokenClaims{
		Username:    user.Username,
		Permissions: user.Filters.WebClient,
		Signature:   user.GetSignature(),
		Role:        user.Role,
		APIKeyID:    keyID,
	}

	resp, err := c.createTokenResponse(tokenAuth, tokenAudienceAPIUser, ipAddr)
	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		return err
	}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", resp["access_token"]))
	dataprovider.UpdateLastLogin(&user)
	updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, nil, r)

	return nil
}

func checkPartialAuth(w http.ResponseWriter, r *http.Request, audience string, tokenAudience []string) error {
	if audience == tokenAudienceWebAdmin && slices.Contains(tokenAudience, tokenAudienceWebAdminPartial) {
		http.Redirect(w, r, webAdminTwoFactorPath, http.StatusFound)
		return errInvalidToken
	}
	if audience == tokenAudienceWebClient && slices.Contains(tokenAudience, tokenAudienceWebClientPartial) {
		http.Redirect(w, r, webClientTwoFactorPath, http.StatusFound)
		return errInvalidToken
	}
	return nil
}

func cacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate, private")
		next.ServeHTTP(w, r)
	})
}

func cleanCacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Del("Cache-Control")
		next.ServeHTTP(w, r)
	})
}
