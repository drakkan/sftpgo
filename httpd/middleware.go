package httpd

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

var connAddrKey = &contextKey{"connection address"}

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "context value " + k.name
}

func saveConnectionAddress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), connAddrKey, r.RemoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func jwtAuthenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, err := jwtauth.FromContext(r.Context())

		if err != nil || token == nil {
			logger.Debug(logSender, "", "error getting jwt token: %v", err)
			sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		err = jwt.Validate(token)
		if err != nil {
			logger.Debug(logSender, "", "error validating jwt token: %v", err)
			sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if !utils.IsStringInSlice(tokenAudienceAPI, token.Audience()) {
			logger.Debug(logSender, "", "the token audience is not valid for API usage")
			sendAPIResponse(w, r, nil, "Your token audience is not valid", http.StatusUnauthorized)
			return
		}
		if isTokenInvalidated(r) {
			logger.Debug(logSender, "", "the token has been invalidated")
			sendAPIResponse(w, r, nil, "Your token is no longer valid", http.StatusUnauthorized)
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func jwtAuthenticatorWeb(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, err := jwtauth.FromContext(r.Context())

		if err != nil || token == nil {
			logger.Debug(logSender, "", "error getting web jwt token: %v", err)
			http.Redirect(w, r, webLoginPath, http.StatusFound)
			return
		}

		err = jwt.Validate(token)
		if err != nil {
			logger.Debug(logSender, "", "error validating web jwt token: %v", err)
			http.Redirect(w, r, webLoginPath, http.StatusFound)
			return
		}
		if !utils.IsStringInSlice(tokenAudienceWeb, token.Audience()) {
			logger.Debug(logSender, "", "the token audience is not valid for Web usage")
			http.Redirect(w, r, webLoginPath, http.StatusFound)
			return
		}
		if isTokenInvalidated(r) {
			logger.Debug(logSender, "", "the token has been invalidated")
			http.Redirect(w, r, webLoginPath, http.StatusFound)
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func checkPerm(perm string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())
			if err != nil {
				if isWebAdminRequest(r) {
					renderBadRequestPage(w, r, err)
				} else {
					sendAPIResponse(w, r, err, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				}
				return
			}
			tokenClaims := jwtTokenClaims{}
			tokenClaims.Decode(claims)

			if !tokenClaims.hasPerm(perm) {
				if isWebAdminRequest(r) {
					renderForbiddenPage(w, r, "You don't have permission for this action")
				} else {
					sendAPIResponse(w, r, nil, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func verifyCSRFHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get(csrfHeaderToken)
		token, err := jwtauth.VerifyToken(csrfTokenAuth, tokenString)
		if err != nil || token == nil {
			logger.Debug(logSender, "", "error validating CSRF header: %v", err)
			sendAPIResponse(w, r, err, "Invalid token", http.StatusForbidden)
			return
		}

		if !utils.IsStringInSlice(tokenAudienceCSRF, token.Audience()) {
			logger.Debug(logSender, "", "error validating CSRF header audience")
			sendAPIResponse(w, r, errors.New("The token is not valid"), "", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
