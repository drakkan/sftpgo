package httpd

import (
	"context"
	"net/http"

	"github.com/go-chi/jwtauth"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
)

type ctxKeyConnAddr int

const connAddrKey ctxKeyConnAddr = 0

func saveConnectionAddress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), connAddrKey, r.RemoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func jwtAuthenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, err := jwtauth.FromContext(r.Context())

		if err != nil {
			logger.Debug(logSender, "", "error getting jwt token: %v", err)
			sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		err = jwt.Validate(token)
		if token == nil || err != nil {
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

		if err != nil {
			logger.Debug(logSender, "", "error getting web jwt token: %v", err)
			http.Redirect(w, r, webLoginPath, http.StatusFound)
			return
		}

		err = jwt.Validate(token)
		if token == nil || err != nil {
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
