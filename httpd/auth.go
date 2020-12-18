package httpd

import (
	"net/http"
	"strings"

	"github.com/drakkan/sftpgo/common"
)

func checkAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validateCredentials(r) {
			w.Header().Set(common.HTTPAuthenticationHeader, "Basic realm=\"SFTPGo Web\"")
			if strings.HasPrefix(r.RequestURI, apiPrefix) {
				sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			} else {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validateCredentials(r *http.Request) bool {
	if !httpAuth.IsEnabled() {
		return true
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return httpAuth.ValidateCredentials(username, password)
}
