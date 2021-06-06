package httpd

import (
	"errors"
	"net/http"
	"runtime/debug"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/drakkan/sftpgo/logger"
	"github.com/drakkan/sftpgo/utils"
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
		redirectPath = webLoginPath
	} else {
		redirectPath = webClientLoginPath
	}

	isAPIToken := (audience == tokenAudienceAPI || audience == tokenAudienceAPIUser)

	if err != nil || token == nil {
		logger.Debug(logSender, "", "error getting jwt token: %v", err)
		if isAPIToken {
			sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		} else {
			http.Redirect(w, r, redirectPath, http.StatusFound)
		}
		return errInvalidToken
	}

	err = jwt.Validate(token)
	if err != nil {
		logger.Debug(logSender, "", "error validating jwt token: %v", err)
		if isAPIToken {
			sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		} else {
			http.Redirect(w, r, redirectPath, http.StatusFound)
		}
		return errInvalidToken
	}
	if !utils.IsStringInSlice(audience, token.Audience()) {
		logger.Debug(logSender, "", "the token is not valid for audience %#v", audience)
		if isAPIToken {
			sendAPIResponse(w, r, nil, "Your token audience is not valid", http.StatusUnauthorized)
		} else {
			http.Redirect(w, r, redirectPath, http.StatusFound)
		}
		return errInvalidToken
	}
	if isTokenInvalidated(r) {
		logger.Debug(logSender, "", "the token has been invalidated")
		if isAPIToken {
			sendAPIResponse(w, r, nil, "Your token is no longer valid", http.StatusUnauthorized)
		} else {
			http.Redirect(w, r, redirectPath, http.StatusFound)
		}
		return errInvalidToken
	}
	return nil
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

//nolint:unparam
func checkHTTPUserPerm(perm string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())
			if err != nil {
				if isWebRequest(r) {
					renderClientBadRequestPage(w, r, err)
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
					renderClientForbiddenPage(w, r, "You don't have permission for this action")
				} else {
					sendAPIResponse(w, r, nil, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func checkPerm(perm string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())
			if err != nil {
				if isWebRequest(r) {
					renderBadRequestPage(w, r, err)
				} else {
					sendAPIResponse(w, r, err, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				}
				return
			}
			tokenClaims := jwtTokenClaims{}
			tokenClaims.Decode(claims)

			if !tokenClaims.hasPerm(perm) {
				if isWebRequest(r) {
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
			sendAPIResponse(w, r, errors.New("the token is not valid"), "", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func recoverer(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				if rvr == http.ErrAbortHandler {
					panic(rvr)
				}

				logEntry := middleware.GetLogEntry(r)
				if logEntry != nil {
					logEntry.Panic(rvr, debug.Stack())
				} else {
					middleware.PrintPrettyStack(rvr)
				}

				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
